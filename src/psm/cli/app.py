"""psm CLI. Exit codes: 0 clean, 1 error, 2 warnings, 3 alerts."""

from __future__ import annotations

import os
import sqlite3
import sys
from pathlib import Path

import typer
from rich.console import Console

from psm import __version__
from psm.collectors.android import adb
from psm.collectors.macos.collector import MacosConfig
from psm.collectors.macos.ingest import ShimValidationError
from psm.collectors.macos.transport import SshError, find_ssh
from psm.collectors.windows.collector import default_file_walk_paths
from psm.collectors.windows.elevation import ELEVATION_ADDS, is_elevated
from psm.core.chain import verify_chain
from psm.core.diff import scope_notes
from psm.core.models import Device
from psm.core.orchestrator import OrchestratorError, take_snapshot
from psm.enrich import known_good
from psm.enrich.labeler import build_labels
from psm.enrich.vt import VtClient
from psm.report import daily as daily_report
from psm.report.explain import render as render_explain
from psm.report.scan import render_alerts, render_scan
from psm.report.timeline import export_jsonl, iso_ago, parse_last, render_timeline
from psm.store.db import open_db
from psm.store.queries import (
    get_device_by_name,
    insert_device,
    load_alerts,
    load_event,
    load_item_payload,
    load_snapshot,
    load_timeline,
    set_alert_status,
)

app = typer.Typer(no_args_is_help=True, add_completion=False)
db_app = typer.Typer(no_args_is_help=True, help="Database maintenance.")
device_app = typer.Typer(no_args_is_help=True, help="Registered devices.")
alerts_app = typer.Typer(no_args_is_help=False, invoke_without_command=True,
                         help="Correlation alerts lifecycle.")
ingest_app = typer.Typer(no_args_is_help=True, help="Ingest a pre-collected collector envelope.")
report_app = typer.Typer(no_args_is_help=True, help="Scheduled reports.")
enrich_app = typer.Typer(no_args_is_help=True, help="Enrichment: known-good hashes.")
app.add_typer(db_app, name="db")
app.add_typer(device_app, name="device")
app.add_typer(alerts_app, name="alerts")
app.add_typer(ingest_app, name="ingest")
app.add_typer(report_app, name="report")
app.add_typer(enrich_app, name="enrich")

console = Console()
err = Console(stderr=True)

DbOption = typer.Option(
    None,
    "--db",
    help="Path to the psm database (defaults to %LOCALAPPDATA%\\psm\\psm.sqlite).",
)


def _get_device(conn: sqlite3.Connection, name: str | None) -> Device:
    if name:
        d = get_device_by_name(conn, name)
        if d is None:
            err.print(f"[red]no device named {name!r}[/red] — try `psm device list`")
            raise typer.Exit(code=1)
        return d
    rows = conn.execute("SELECT name FROM devices").fetchall()
    if len(rows) == 0:
        err.print("[red]no devices registered[/red] — run `psm device add`")
        raise typer.Exit(code=1)
    if len(rows) > 1:
        err.print(
            f"[red]multiple devices registered[/red] — pass a name: {[r['name'] for r in rows]}"
        )
        raise typer.Exit(code=1)
    d = get_device_by_name(conn, rows[0]["name"])
    assert d is not None
    return d


def _file_walk_paths() -> tuple[str, ...]:
    override = os.environ.get("PSM_FILE_WALK_PATHS")
    if override:
        return tuple(p for p in override.split(os.pathsep) if p)
    return default_file_walk_paths()


# ---- db ----

@db_app.command("verify")
def db_verify(db: Path | None = DbOption) -> None:
    """Recompute the event hash chain from genesis and confirm the head matches."""
    conn = open_db(db)
    report = verify_chain(conn)
    if report.ok:
        head_display = report.head or "<genesis>"
        console.print(
            f"[green]chain ok[/green]  events={report.events_checked}  head={head_display}"
        )
        raise typer.Exit(code=0)
    err.print(f"[red]chain broken[/red] {report.error}")
    if report.first_bad_event_id is not None:
        err.print(f"first bad event id = {report.first_bad_event_id}")
    raise typer.Exit(code=1)


# ---- device ----

@device_app.command("add")
def device_add(
    name: str = typer.Option(..., "--name", help="Short label used on the CLI."),
    platform: str = typer.Option(
        "windows", "--platform", help="windows|macos|android (only windows implemented in phase 1)."
    ),
    identifier: str = typer.Option(
        None,
        "--identifier",
        help="hostname / SSH target / adb serial. Defaults to the machine hostname.",
    ),
    db: Path | None = DbOption,
) -> None:
    """Register a device."""
    if platform not in ("windows", "macos", "android"):
        err.print(f"[red]unknown platform {platform!r}[/red]")
        raise typer.Exit(code=1)
    conn = open_db(db)
    if get_device_by_name(conn, name) is not None:
        err.print(f"[red]device {name!r} already exists[/red]")
        raise typer.Exit(code=1)
    ident = identifier or os.environ.get("COMPUTERNAME") or "localhost"
    d = Device(name=name, platform=platform, identifier=ident)  # type: ignore[arg-type]
    insert_device(conn, d)
    console.print(f"[green]registered[/green] device #{d.id} name={name} platform={platform}")


@device_app.command("list")
def device_list(db: Path | None = DbOption) -> None:
    conn = open_db(db)
    rows = conn.execute("SELECT id, name, platform, identifier FROM devices ORDER BY id").fetchall()
    if not rows:
        console.print("[dim]no devices registered[/dim]")
        return
    for r in rows:
        console.print(f"#{r['id']}  {r['name']}  ({r['platform']})  {r['identifier']}")


# ---- doctor ----

@app.command("doctor")
def doctor(
    name: str = typer.Argument(None, help="Device name (optional if only one is registered)."),
    db: Path | None = DbOption,
) -> None:
    """Report what the current environment supports and what elevation would add."""
    conn = open_db(db)
    device = _get_device(conn, name)

    console.print(
        f"[bold]psm[/bold] {__version__}  device={device.name} platform={device.platform}"
    )

    if device.platform == "android":
        _doctor_android(device)
        raise typer.Exit(code=0)

    if device.platform == "macos":
        _doctor_macos(device)
        raise typer.Exit(code=0)

    if device.platform != "windows":
        console.print(
            f"[yellow]doctor for {device.platform} not implemented in phase 1[/yellow]"
        )
        raise typer.Exit(code=0)

    if sys.platform != "win32":
        console.print(
            "[yellow]not running on Windows — collection modules are unavailable[/yellow]"
        )
        raise typer.Exit(code=0)

    elevated = is_elevated()
    label = "[green]elevated[/green]" if elevated else "[yellow]NOT elevated[/yellow]"
    console.print(f"elevation: {label}")
    if not elevated:
        console.print("[dim]elevation would add:[/dim]")
        for item in ELEVATION_ADDS:
            console.print(f"  • {item}")

    paths = _file_walk_paths()
    console.print(f"file walk paths: {list(paths)}")


def _resolve_macos_config(device: Device, ssh: str | None) -> MacosConfig | None:
    if device.platform != "macos":
        return None
    target = ssh or device.identifier
    if not target:
        return None
    return MacosConfig(ssh_target=target)


def _doctor_macos(device: Device) -> None:
    target = device.identifier
    console.print(f"target: [cyan]{target}[/cyan]")
    try:
        ssh_bin = find_ssh()
    except SshError as e:
        console.print(f"[red]{e}[/red]")
        return
    console.print(f"ssh: [green]{ssh_bin}[/green]")
    console.print(
        "reachability: run `psm scan mac --ssh <target>` — a full scan is the only "
        "reliable readiness signal for the shim + FDA + TCC path."
    )


def _doctor_android(device: Device) -> None:
    try:
        adb_path = adb.find_adb()
    except adb.AdbNotFound as e:
        console.print(f"[red]adb.exe not found[/red]: {e}")
        return
    console.print(f"adb: [green]{adb_path}[/green]")

    try:
        devices = adb.list_devices(adb_path)
    except adb.AdbError as e:
        console.print(f"[red]adb devices failed[/red]: {e}")
        return

    match = next((d for d in devices if d.serial == device.identifier), None)
    if match is None:
        console.print(
            f"[yellow]serial {device.identifier} not visible to `adb devices`[/yellow]"
        )
        for hint in adb.DRIVER_GUIDANCE:
            console.print(f"  • {hint}")
        return

    if match.state == "device":
        console.print(f"device: [green]{match.serial}[/green] state=device (authorized)")
        sdk = adb.get_sdk_level(adb_path, match.serial)
        if sdk is not None:
            console.print(f"sdk level: {sdk}")
    else:
        console.print(
            f"device: [yellow]{match.serial}[/yellow] state={match.state}"
        )
        for hint in adb.DRIVER_GUIDANCE:
            console.print(f"  • {hint}")


# ---- baseline / scan ----

@app.command("baseline")
def baseline(
    name: str = typer.Argument(None, help="Device name (optional if only one is registered)."),
    ssh: str = typer.Option(None, "--ssh", help="SSH target (macOS): user@host."),
    db: Path | None = DbOption,
) -> None:
    """Capture a baseline snapshot for the device."""
    conn = open_db(db)
    device = _get_device(conn, name)
    file_paths = _file_walk_paths() if device.platform == "windows" else ()
    macos_cfg = _resolve_macos_config(device, ssh)
    try:
        result = take_snapshot(
            conn, device, kind="baseline",
            file_walk_paths=file_paths, macos_config=macos_cfg,
        )
    except OrchestratorError as e:
        err.print(f"[red]orchestrator error:[/red] {e}")
        raise typer.Exit(code=1) from e
    console.print(
        f"[green]baseline captured[/green]  snapshot=#{result.snapshot.id}  "
        f"modules={sorted(result.snapshot.capabilities)}"
    )
    if result.snapshot.gaps:
        console.print(f"[yellow]{len(result.snapshot.gaps)} collection gap(s)[/yellow]")


@app.command("scan")
def scan(
    name: str = typer.Argument(None, help="Device name (optional if only one is registered)."),
    ssh: str = typer.Option(None, "--ssh", help="SSH target (macOS): user@host."),
    enrich: str = typer.Option(
        None, "--enrich", help="Enrichment sources: comma-list of `known_good`, `vt`."
    ),
    db: Path | None = DbOption,
) -> None:
    """Take a new scan snapshot, diff, run rules, print report.

    Exit codes: 0 clean · 2 warnings only · 3 alerts fired.
    """
    conn = open_db(db)
    device = _get_device(conn, name)
    file_paths = _file_walk_paths() if device.platform == "windows" else ()
    macos_cfg = _resolve_macos_config(device, ssh)
    sources = {s.strip() for s in (enrich or "").split(",") if s.strip()}
    unknown_sources = sources - {"known_good", "vt"}
    if unknown_sources:
        err.print(f"[red]unknown --enrich source(s): {sorted(unknown_sources)}[/red]")
        raise typer.Exit(code=1)

    try:
        result = take_snapshot(
            conn, device, kind="scan",
            file_walk_paths=file_paths, macos_config=macos_cfg,
            suppress_known_good="known_good" in sources,
        )
    except OrchestratorError as e:
        err.print(f"[red]orchestrator error:[/red] {e}")
        raise typer.Exit(code=1) from e

    notes: dict[str, list[str]] = {}
    if result.prior_snapshot_id is not None:
        prior = load_snapshot(conn, result.prior_snapshot_id)
        notes = scope_notes(prior, result.snapshot)

    enrichment: dict[int, str] = {}
    if sources:
        vt_client = VtClient() if "vt" in sources else None
        if "vt" in sources and (vt_client is None or not vt_client.enabled):
            err.print(
                "[yellow]--enrich vt requested but PSM_VT_API_KEY not set;"
                " skipping VT lookups.[/yellow]"
            )
        enrichment = build_labels(conn, result.events, vt_client=vt_client)

    render_scan(
        console,
        snapshot=result.snapshot,
        events=result.events,
        prior_snapshot_id=result.prior_snapshot_id,
        scope_notes=notes,
        enrichment=enrichment or None,
    )
    if result.alerts:
        render_alerts(console, result.alerts)

    if result.alerts:
        exit_code = 3
    elif result.snapshot.gaps:
        exit_code = 2
    else:
        exit_code = 0
    raise typer.Exit(code=exit_code)


# ---- ingest ----

@ingest_app.command("macos")
def ingest_macos(
    file: Path = typer.Argument(  # noqa: B008
        ..., exists=True, help="Path to a psm_mac_collector.py output."
    ),
    name: str = typer.Option(None, "--device", help="Device name (must be a macOS device)."),
    kind: str = typer.Option("scan", "--kind", help="baseline|scan"),
    db: Path | None = DbOption,
) -> None:
    """Ingest a shim envelope from disk (offline / manual collection mode)."""
    if kind not in ("baseline", "scan"):
        err.print(f"[red]--kind must be baseline|scan, got {kind!r}[/red]")
        raise typer.Exit(code=1)
    conn = open_db(db)
    device = _get_device(conn, name)
    if device.platform != "macos":
        err.print(f"[red]device {device.name!r} is {device.platform}, not macos[/red]")
        raise typer.Exit(code=1)

    try:
        macos_cfg = MacosConfig(envelope_path=file)
        result = take_snapshot(
            conn, device, kind=kind, macos_config=macos_cfg,
        )
    except ShimValidationError as e:
        err.print(f"[red]shim envelope invalid:[/red] {e}")
        raise typer.Exit(code=1) from e
    except OrchestratorError as e:
        err.print(f"[red]orchestrator error:[/red] {e}")
        raise typer.Exit(code=1) from e

    console.print(
        f"[green]ingested[/green]  snapshot=#{result.snapshot.id}  "
        f"modules={sorted(result.snapshot.capabilities)}  events={len(result.events)}"
    )
    if result.alerts:
        render_alerts(console, result.alerts)
    if result.alerts:
        raise typer.Exit(code=3)
    if result.snapshot.gaps:
        raise typer.Exit(code=2)


# ---- alerts ----

@alerts_app.callback()
def alerts_root(
    ctx: typer.Context,
    status: str = typer.Option("open", "--status", help="open|ack|closed|all"),
    ack: int = typer.Option(None, "--ack", help="Mark an alert acknowledged."),
    close: int = typer.Option(None, "--close", help="Mark an alert closed."),
    db: Path | None = DbOption,
) -> None:
    if ctx.invoked_subcommand is not None:
        return
    conn = open_db(db)
    if ack is not None:
        if not set_alert_status(conn, ack, "ack"):
            err.print(f"[red]no alert #{ack}[/red]")
            raise typer.Exit(code=1)
        console.print(f"[green]alert #{ack} acknowledged[/green]")
        return
    if close is not None:
        if not set_alert_status(conn, close, "closed"):
            err.print(f"[red]no alert #{close}[/red]")
            raise typer.Exit(code=1)
        console.print(f"[green]alert #{close} closed[/green]")
        return

    lookup = None if status == "all" else status
    alerts = load_alerts(conn, status=lookup)
    if not alerts:
        console.print(f"[dim]no {status} alerts[/dim]")
        return
    for a in alerts:
        events = a.detail.get("events", [])
        console.print(
            f"[bold]#{a.id}[/bold]  [yellow]{a.rule_id}[/yellow]  {a.title}  "
            f"[dim]{a.ts}  status={a.status}  events={events}[/dim]"
        )


# ---- timeline ----

@app.command("timeline")
def timeline(
    device: str = typer.Option(None, "--device", help="Restrict to this device name."),
    last: str = typer.Option(None, "--last", help="Window spec, e.g. 24h, 7d."),
    category: str = typer.Option(None, "--category", help="Restrict to a single category."),
    limit: int = typer.Option(500, "--limit", help="Max rows returned."),
    export: Path = typer.Option(  # noqa: B008
        None, "--export", help="Write JSONL to this path (Timesketch)."
    ),
    db: Path | None = DbOption,
) -> None:
    """Query the event stream by device / window / category. Optionally export JSONL."""
    conn = open_db(db)
    device_id: int | None = None
    if device:
        d = get_device_by_name(conn, device)
        if d is None:
            err.print(f"[red]no device named {device!r}[/red]")
            raise typer.Exit(code=1)
        device_id = d.id
    since_iso: str | None = None
    if last:
        try:
            since_iso = iso_ago(parse_last(last))
        except ValueError as e:
            err.print(f"[red]{e}[/red]")
            raise typer.Exit(code=1) from e

    rows = load_timeline(
        conn,
        device_id=device_id,
        category=category,
        since_iso=since_iso,
        limit=limit,
    )
    render_timeline(console, rows)
    if export is not None:
        count = export_jsonl(rows, export)
        console.print(f"[green]wrote {count} event(s)[/green] → {export}")


# ---- enrich ----

@enrich_app.command("import")
def enrich_import(
    file: Path = typer.Argument(  # noqa: B008
        ..., exists=True, help="Plain-text (one sha256/line) or JSONL entries."
    ),
    source: str = typer.Option(None, "--source", help="Override source label."),
    db: Path | None = DbOption,
) -> None:
    """Import a known-good hash list."""
    conn = open_db(db)
    try:
        entries = known_good.parse_file(file, default_source=source)
    except known_good.KnownGoodParseError as e:
        err.print(f"[red]parse error:[/red] {e}")
        raise typer.Exit(code=1) from e
    n = known_good.import_entries(conn, entries)
    console.print(f"[green]imported[/green] {n} known-good hash(es) from {file}")


@enrich_app.command("capture")
def enrich_capture(
    device: str = typer.Option(None, "--device", help="Restrict to one device."),
    source: str = typer.Option("baseline", "--source", help="Label attached to captured hashes."),
    db: Path | None = DbOption,
) -> None:
    """Capture current file-item hashes as a known-good baseline."""
    conn = open_db(db)
    device_id: int | None = None
    if device:
        d = get_device_by_name(conn, device)
        if d is None:
            err.print(f"[red]no device named {device!r}[/red]")
            raise typer.Exit(code=1)
        device_id = d.id
    n = known_good.capture_baseline(conn, source=source, device_id=device_id)
    console.print(f"[green]captured[/green] {n} hash(es) as known-good baseline")


# ---- report ----

@report_app.command("daily")
def report_daily(
    out: Path = typer.Option(  # noqa: B008
        None,
        "--out",
        help="Output directory (default: %LOCALAPPDATA%\\psm\\reports).",
    ),
    last: str = typer.Option("24h", "--last", help="Window spec, e.g. 24h, 7d."),
    db: Path | None = DbOption,
) -> None:
    """Generate a daily Markdown report of recent events + open alerts."""
    try:
        window = parse_last(last)
    except ValueError as e:
        err.print(f"[red]{e}[/red]")
        raise typer.Exit(code=1) from e

    conn = open_db(db)
    since_iso = iso_ago(window)
    events = load_timeline(conn, since_iso=since_iso, limit=10_000)
    alerts = load_alerts(conn, status="open")

    if out is None:
        local = os.environ.get("LOCALAPPDATA")
        out = Path(local) / "psm" / "reports" if local else Path("./psm-reports")
    dest = daily_report.write(out, events, alerts, window=window)
    console.print(f"[green]wrote[/green] {dest}  events={len(events)}  alerts={len(alerts)}")


# ---- explain ----

@app.command("explain")
def explain(
    event_id: int = typer.Argument(..., help="Event id (see `psm timeline` or scan output)."),
    db: Path | None = DbOption,
) -> None:
    """Print a Markdown-formatted explanation of a specific event."""
    conn = open_db(db)
    row = load_event(conn, event_id)
    if row is None:
        err.print(f"[red]no event #{event_id}[/red]")
        raise typer.Exit(code=1)
    hash_ = row["after_hash"] if row["action"] != "removed" else row["before_hash"]
    payload = load_item_payload(conn, hash_) if hash_ else {}
    text = render_explain(row["category"], row["action"], payload or {})
    console.print(text)


def main() -> None:
    app()


if __name__ == "__main__":
    main()

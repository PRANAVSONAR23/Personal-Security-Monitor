"""psm CLI. Exit codes: 0 clean, 1 error, 2 warnings, 3 alerts."""

from __future__ import annotations

import os
import sqlite3
import time
from datetime import timedelta
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

import psm.collectors.registry  # noqa: F401  — registers collectors
from psm import __version__
from psm.collectors.android import adb
from psm.core.chain import verify_chain
from psm.core.diff import scope_notes
from psm.core.models import Device
from psm.core.orchestrator import OrchestratorError, take_snapshot
from psm.core.tiers import describe, tiers_for
from psm.enrich import known_good
from psm.enrich.labeler import build_labels
from psm.enrich.vt import VtClient
from psm.hunt import runner as hunt_runner
from psm.report import daily as daily_report
from psm.report.explain import render as render_explain
from psm.report.scan import render_alerts, render_scan
from psm.report.timeline import export_jsonl, iso_ago, parse_last, render_timeline
from psm.store.db import default_data_dir, open_db, transaction
from psm.store.queries import (
    get_device_by_name,
    insert_device,
    load_alerts,
    load_event,
    load_findings,
    load_item_payload,
    load_latest_snapshot_id,
    load_snapshot,
    load_snapshot_items,
    load_timeline,
    purge_flows_before,
    rollup_flows,
    set_alert_status,
)
from psm.streams.netflow.correlate import correlate
from psm.streams.netflow.device import (
    DeviceSource,
    local_addresses,
    to_flow,
    uid_to_package,
)
from psm.streams.netflow.router import RouterSource, hotspot_prefixes
from psm.streams.netflow.writer import FlowAggregator, persist

app = typer.Typer(no_args_is_help=True, add_completion=False)
db_app = typer.Typer(no_args_is_help=True, help="Database maintenance.")
device_app = typer.Typer(no_args_is_help=True, help="Registered devices.")
alerts_app = typer.Typer(
    no_args_is_help=False, invoke_without_command=True, help="Correlation alerts lifecycle."
)
report_app = typer.Typer(no_args_is_help=True, help="Scheduled reports.")
enrich_app = typer.Typer(no_args_is_help=True, help="Enrichment: known-good hashes.")
flow_app = typer.Typer(no_args_is_help=True, help="Network flow capture and queries.")
hunt_app = typer.Typer(
    no_args_is_help=False,
    invoke_without_command=True,
    help="Analyze collected artifacts for malicious indicators.",
)
app.add_typer(db_app, name="db")
app.add_typer(device_app, name="device")
app.add_typer(alerts_app, name="alerts")
app.add_typer(report_app, name="report")
app.add_typer(enrich_app, name="enrich")
app.add_typer(hunt_app, name="hunt")
app.add_typer(flow_app, name="flow")

console = Console()
err = Console(stderr=True)

DbOption = typer.Option(
    None,
    "--db",
    help="Path to the psm database (default: ~/Library/Application Support/psm/psm.sqlite).",
)


def _version_callback(value: bool) -> None:
    if value:
        console.print(__version__)
        raise typer.Exit(code=0)


@app.callback()
def _root(
    version: bool = typer.Option(
        False,
        "--version",
        "-V",
        callback=_version_callback,
        is_eager=True,
        help="Show the psm version and exit.",
    ),
) -> None:
    """psm — inventory diffing, artifact hunting, and network flow logging."""


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


DEFAULT_WALK = {
    "macos": ("~/Downloads", "~/Library/LaunchAgents", "/usr/local/bin", "/opt/homebrew/bin"),
    "android": ("/sdcard/Download",),
}


def _file_walk_paths(platform: str) -> tuple[str, ...]:
    """F5: v1 only ever wired this for Windows, so the macOS file walk was
    unreachable from the CLI even though the collector supported it."""
    override = os.environ.get("PSM_FILE_WALK_PATHS")
    if override:
        return tuple(p for p in override.split(os.pathsep) if p)
    return DEFAULT_WALK.get(platform, ())


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
    platform: str = typer.Option("macos", "--platform", help="macos|android"),
    identifier: str = typer.Option(
        None,
        "--identifier",
        help="hostname / SSH target / adb serial. Defaults to the machine hostname.",
    ),
    db: Path | None = DbOption,
) -> None:
    """Register a device."""
    if platform not in ("macos", "android"):
        err.print(f"[red]unknown platform {platform!r}[/red]")
        raise typer.Exit(code=1)
    conn = open_db(db)
    if get_device_by_name(conn, name) is not None:
        err.print(f"[red]device {name!r} already exists[/red]")
        raise typer.Exit(code=1)
    ident = identifier or ("local" if platform == "macos" else "")
    if not ident:
        err.print("[red]--identifier is required for android (adb serial or host:port)[/red]")
        raise typer.Exit(code=1)
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
    """Report which capability tiers are satisfied, and what each missing one adds."""
    conn = open_db(db)
    device = _get_device(conn, name)
    console.print(
        f"[bold]psm[/bold] {__version__}  device={device.name} platform={device.platform}"
    )

    satisfied = _probe_tiers(device)
    for tier in tiers_for(device.platform):
        info = describe(device.platform, tier)
        if info is None:
            continue
        mark = "[green]✓[/green]" if tier in satisfied else "[yellow]✗[/yellow]"
        console.print(f"{mark} [bold]{tier}[/bold] — {info.summary}")
        if tier not in satisfied:
            for u in info.unlocks:
                console.print(f"    would add: {u}")
            console.print(f"    [dim]{info.how}[/dim]")

    if device.platform == "android":
        _doctor_android(device)
    else:
        console.print(f"file walk paths: {list(_file_walk_paths(device.platform))}")


def _probe_tiers(device: Device) -> set[str]:
    satisfied: set[str] = set()
    if device.platform == "macos":
        satisfied.add("base")
        if os.geteuid() == 0:
            satisfied.add("admin")
        if _fda_readable():
            satisfied.add("fda")
        return satisfied
    try:
        adb_path = adb.find_adb()
    except adb.AdbNotFound:
        return satisfied
    for d in adb.list_devices(adb_path):
        if d.serial == device.identifier and d.state == "device":
            satisfied.add("base")
    return satisfied


def _fda_readable() -> bool:
    """Full Disk Access is not queryable; probe a path only FDA can open."""
    probe = Path.home() / "Library" / "Application Support" / "com.apple.TCC" / "TCC.db"
    try:
        with probe.open("rb") as f:
            f.read(16)
    except OSError:
        return False
    return True


def _doctor_android(device: Device) -> None:
    try:
        adb_path = adb.find_adb()
    except adb.AdbNotFound as e:
        console.print(f"[red]adb not found[/red]: {e}")
        return
    console.print(f"adb: [green]{adb_path}[/green]")
    try:
        devices = adb.list_devices(adb_path)
    except adb.AdbError as e:
        console.print(f"[red]adb devices failed[/red]: {e}")
        return

    match = next((d for d in devices if d.serial == device.identifier), None)
    if match is None:
        console.print(f"[yellow]{device.identifier} not visible to `adb devices`[/yellow]")
        for hint in adb.CONNECT_GUIDANCE:
            console.print(f"  • {hint}")
        return
    if match.state == "device":
        console.print(f"device: [green]{match.serial}[/green] state=device (authorized)")
        sdk = adb.get_sdk_level(adb_path, match.serial)
        if sdk is not None:
            console.print(f"sdk level: {sdk}")
    else:
        console.print(f"device: [yellow]{match.serial}[/yellow] state={match.state}")
        for hint in adb.CONNECT_GUIDANCE:
            console.print(f"  • {hint}")


# ---- baseline / scan ----


@app.command("baseline")
def baseline(
    name: str = typer.Argument(None, help="Device name (optional if only one is registered)."),
    db: Path | None = DbOption,
) -> None:
    """Capture a baseline snapshot for the device."""
    conn = open_db(db)
    device = _get_device(conn, name)
    try:
        result = take_snapshot(
            conn,
            device,
            kind="baseline",
            file_walk_paths=_file_walk_paths(device.platform),
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
    sources = {s.strip() for s in (enrich or "").split(",") if s.strip()}
    unknown_sources = sources - {"known_good", "vt"}
    if unknown_sources:
        err.print(f"[red]unknown --enrich source(s): {sorted(unknown_sources)}[/red]")
        raise typer.Exit(code=1)

    try:
        result = take_snapshot(
            conn,
            device,
            kind="scan",
            file_walk_paths=_file_walk_paths(device.platform),
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


# ---- watch ----


@app.command("watch")
def watch(
    name: str = typer.Argument(None, help="Device name (optional if only one is registered)."),
    before_after: bool = typer.Option(
        False, "--before-after", help="Snapshot, wait for a keypress, snapshot, diff."
    ),
    db: Path | None = DbOption,
) -> None:
    """Bracket a risky action with two snapshots and show exactly what it changed.

    Specified in v1 and never implemented. This is the highest-value flow: you
    clicked something and want to know what it did, without waiting for the next
    routine scan.
    """
    if not before_after:
        err.print("[red]--before-after is required (it is the only mode today)[/red]")
        raise typer.Exit(code=1)

    conn = open_db(db)
    device = _get_device(conn, name)
    walk = _file_walk_paths(device.platform)

    try:
        before = take_snapshot(conn, device, kind="before", file_walk_paths=walk)
    except OrchestratorError as e:
        err.print(f"[red]orchestrator error:[/red] {e}")
        raise typer.Exit(code=1) from e
    console.print(
        f"[green]before[/green] snapshot=#{before.snapshot.id}  "
        f"modules={sorted(before.snapshot.capabilities)}"
    )
    console.print("[bold]Now do the thing you want to inspect.[/bold]")
    typer.prompt("Press Enter when finished", default="", show_default=False)

    try:
        after = take_snapshot(conn, device, kind="after", file_walk_paths=walk)
    except OrchestratorError as e:
        err.print(f"[red]orchestrator error:[/red] {e}")
        raise typer.Exit(code=1) from e

    notes: dict[str, list[str]] = {}
    if after.prior_snapshot_id is not None:
        notes = scope_notes(load_snapshot(conn, after.prior_snapshot_id), after.snapshot)
    render_scan(
        console,
        snapshot=after.snapshot,
        events=after.events,
        prior_snapshot_id=after.prior_snapshot_id,
        scope_notes=notes,
    )
    if after.alerts:
        render_alerts(console, after.alerts)
        raise typer.Exit(code=3)
    raise typer.Exit(code=2 if after.snapshot.gaps else 0)


# ---- persistence ----


@app.command("persistence")
def persistence(
    name: str = typer.Argument(None, help="Device name (optional if only one is registered)."),
    db: Path | None = DbOption,
) -> None:
    """Dump every autostart entry psm currently knows about for a device.

    Persistence is the highest-signal category, so it gets a dedicated view
    rather than being buried in a full scan report.
    """
    conn = open_db(db)
    device = _get_device(conn, name)
    assert device.id is not None
    snap_id = load_latest_snapshot_id(conn, device.id, kinds=("baseline", "scan", "after"))
    if snap_id is None:
        err.print(f"[red]no snapshots for {device.name!r}[/red] — run `psm baseline` first")
        raise typer.Exit(code=1)

    rows = [i for i in load_snapshot_items(conn, snap_id) if i.category == "persistence"]
    if not rows:
        console.print(f"[dim]no persistence entries in snapshot #{snap_id}[/dim]")
        return

    table = Table(title=f"persistence — {device.name} (snapshot #{snap_id})")
    table.add_column("location")
    table.add_column("name")
    table.add_column("target", overflow="fold")
    table.add_column("enabled")
    for item in sorted(rows, key=lambda i: i.subject_key):
        pl = item.payload
        table.add_row(
            str(pl.get("location", "")),
            str(pl.get("name", "")),
            str(pl.get("target", "")),
            "yes" if pl.get("enabled", True) else "no",
        )
    console.print(table)


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


# ---- hunt ----

_VERDICT_STYLE = {
    "malicious": "red",
    "suspicious": "yellow",
    "unknown": "dim",
    "clean": "green",
}


@hunt_app.callback()
def hunt_root(
    ctx: typer.Context,
    name: str = typer.Argument(None, help="Device name (optional if only one is registered)."),
    db: Path | None = DbOption,
) -> None:
    """Run the analyzers over the latest snapshot and report findings.

    Reads only what inventory already stored — no device access, no network — so
    it is safe to re-run after changing an analyzer.
    """
    if ctx.invoked_subcommand is not None:
        return
    conn = open_db(db)
    device = _get_device(conn, name)
    try:
        result = hunt_runner.run(conn, device)
    except hunt_runner.HuntError as e:
        err.print(f"[red]{e}[/red]")
        raise typer.Exit(code=1) from e

    console.print(
        f"[bold]hunt[/bold] {device.name}  snapshot=#{result.snapshot_id}  "
        f"artifacts={result.artifacts}  findings={len(result.findings)}"
    )
    if not result.findings:
        console.print("[green]no findings[/green]")
        raise typer.Exit(code=0)

    _render_findings(conn, result.findings)
    worst = {f.verdict for f in result.findings}
    raise typer.Exit(code=3 if "malicious" in worst else 2)


@hunt_app.command("findings")
def hunt_findings(
    verdict: str = typer.Option(
        None, "--verdict", help="Filter: clean|suspicious|malicious|unknown."
    ),
    last: str = typer.Option(None, "--last", help="Window spec, e.g. 24h, 7d."),
    limit: int = typer.Option(200, "--limit"),
    db: Path | None = DbOption,
) -> None:
    """List stored findings."""
    conn = open_db(db)
    since = None
    if last:
        try:
            since = iso_ago(parse_last(last))
        except ValueError as e:
            err.print(f"[red]{e}[/red]")
            raise typer.Exit(code=1) from e
    verdicts = (verdict,) if verdict else None
    rows = load_findings(conn, verdicts=verdicts, since_iso=since, limit=limit)
    if not rows:
        console.print("[dim]no findings[/dim]")
        return

    table = Table(title=f"findings ({len(rows)})")
    table.add_column("verdict")
    table.add_column("conf")
    table.add_column("analyzer")
    table.add_column("rule")
    table.add_column("subject", overflow="fold")
    for r in rows:
        style = _VERDICT_STYLE.get(r["verdict"], "")
        table.add_row(
            f"[{style}]{r['verdict']}[/{style}]" if style else r["verdict"],
            r["confidence"],
            r["analyzer_id"],
            r["rule_id"] or "",
            r["subject_key"],
        )
    console.print(table)


def _render_findings(conn: sqlite3.Connection, findings: list) -> None:
    rows = load_findings(conn, limit=10_000)
    by_id = {r["id"]: r for r in rows}
    table = Table(title=f"findings ({len(findings)})")
    table.add_column("verdict")
    table.add_column("conf")
    table.add_column("rule")
    table.add_column("subject", overflow="fold")
    table.add_column("why", overflow="fold")
    order = {"malicious": 0, "suspicious": 1, "unknown": 2, "clean": 3}
    for f in sorted(findings, key=lambda f: (order.get(f.verdict, 9), f.rule_id or "")):
        row = by_id.get(f.id or -1)
        style = _VERDICT_STYLE.get(f.verdict, "")
        table.add_row(
            f"[{style}]{f.verdict}[/{style}]" if style else f.verdict,
            f.confidence,
            f.rule_id or "",
            row["subject_key"] if row else "",
            str(f.evidence.get("detail", "")),
        )
    console.print(table)


# ---- flow ----

FLUSH_EVERY = 500  # packets between database writes


@flow_app.command("status")
def flow_status(db: Path | None = DbOption) -> None:
    """Report whether a capture leg can run, and what is stored."""
    conn = open_db(db)
    for label, (ok, detail) in (
        ("device leg", _device_leg_status(conn)),
        ("router leg", RouterSource().available()),
    ):
        mark = "[green]ready[/green]" if ok else "[yellow]unavailable[/yellow]"
        console.print(f"{label}: {mark}")
        console.print(f"  {detail}")

    row = conn.execute("SELECT COUNT(*) n, MIN(ts) lo, MAX(ts) hi FROM flows").fetchone()
    console.print(
        f"stored flows: {row['n']}" + (f"  window={row['lo']} … {row['hi']}" if row["n"] else "")
    )
    rollups = conn.execute("SELECT COUNT(*) n FROM flow_rollups").fetchone()["n"]
    console.print(f"hourly rollups: {rollups}")


@flow_app.command("start")
def flow_start(  # noqa: PLR0917 — CLI options
    name: str = typer.Argument(None, help="Device the captured traffic belongs to."),
    leg: str = typer.Option(
        "device", "--leg", help="device (poll /proc/net over adb) | router (pcap on the bridge)."
    ),
    interface: str = typer.Option(None, "--interface", help="Override the capture interface."),
    seconds: int = typer.Option(0, "--seconds", help="Stop after N seconds (0 = until Ctrl-C)."),
    interval: float = typer.Option(1.0, "--interval", help="Device leg poll interval, seconds."),
    db: Path | None = DbOption,
) -> None:
    """Capture flows until stopped.

    The device leg needs nothing installed on the phone and gives per-app
    attribution. The router leg gives byte counts and DNS/SNI hostnames but needs
    the phone on the Mac's Internet Sharing hotspot.
    """
    if leg not in ("device", "router"):
        err.print("[red]--leg must be device|router[/red]")
        raise typer.Exit(code=1)
    conn = open_db(db)
    device = _get_device(conn, name)
    assert device.id is not None
    if leg == "device":
        _capture_device(conn, device, seconds=seconds, interval=interval)
        return

    source = RouterSource(interface=interface)
    ok, detail = source.available()
    if not ok:
        err.print(f"[red]cannot start capture:[/red] {detail}")
        raise typer.Exit(code=1)

    iface = interface or detail
    agg = FlowAggregator(device_id=device.id, leg="router", local_prefixes=hotspot_prefixes(iface))
    console.print(
        f"capturing on [cyan]{iface}[/cyan] for {device.name} "
        f"(local prefixes: {list(agg.local_prefixes) or 'unknown'})  — Ctrl-C to stop"
    )

    deadline = time.monotonic() + seconds if seconds else None
    written = 0
    packets = 0
    try:
        for pkt in source.subscribe():
            agg.add(pkt)
            packets += 1
            if packets % FLUSH_EVERY == 0:
                written += _flush(conn, agg)
            if deadline and time.monotonic() > deadline:
                break
    except KeyboardInterrupt:
        console.print("\n[dim]stopping[/dim]")
    finally:
        source.stop()
        written += _flush(conn, agg)

    console.print(f"[green]captured[/green] {packets} packets → {written} flow rows")
    if agg.dns:
        console.print(f"DNS names observed: {len(agg.dns)}")


def _capture_device(
    conn: sqlite3.Connection, device: Device, *, seconds: int, interval: float
) -> None:
    """Poll /proc/net over adb and record attributable connections."""
    if device.platform != "android":
        err.print(f"[red]the device leg is Android-only; {device.name} is {device.platform}[/red]")
        raise typer.Exit(code=1)
    assert device.id is not None

    adb_path = adb.find_adb()
    serial = device.identifier

    def shell(cmd: str) -> tuple[int, str, str]:
        try:
            result = adb.shell(adb_path, serial, cmd, timeout_s=30)
        except adb.AdbError as e:
            return (-1, "", str(e))
        return (result.returncode, result.stdout, result.stderr)

    source = DeviceSource(shell=shell, interval_s=interval, exclude_ips=local_addresses())
    ok, why = source.available()
    if not ok:
        err.print(f"[red]cannot start device leg:[/red] {why}")
        raise typer.Exit(code=1)

    uid_map = uid_to_package(conn, device.id)
    console.print(
        f"polling [cyan]{serial}[/cyan] every {interval}s "
        f"({len(uid_map)} uid→package entries) — Ctrl-C to stop"
    )
    deadline = time.monotonic() + seconds if seconds else None
    written = 0
    try:
        for sock in source.subscribe():
            flow = to_flow(source, sock, device.id, uid_map)
            with transaction(conn):
                written += persist(conn, [flow])
            console.print(
                f"  [dim]{flow.ts}[/dim] {flow.app_pkg or f'uid:{sock.uid}'} → "
                f"{flow.hostname or flow.dst_ip}:{flow.dst_port}"
            )
            if deadline and time.monotonic() > deadline:
                break
    except KeyboardInterrupt:
        console.print("\n[dim]stopping[/dim]")
    finally:
        source.stop()

    console.print(f"[green]recorded[/green] {written} connection(s)")
    if source.skipped_unattributable:
        console.print(
            f"[dim]{source.skipped_unattributable} closing socket(s) skipped — the kernel "
            f"drops the owning uid once a socket starts closing, so they cannot be "
            f"attributed[/dim]"
        )


def _flush(conn: sqlite3.Connection, agg: FlowAggregator) -> int:
    flows = agg.drain()
    if not flows:
        return 0
    with transaction(conn):
        return persist(conn, flows)


@flow_app.command("correlate")
def flow_correlate(
    name: str = typer.Argument(None, help="Device name."),
    window: int = typer.Option(30, "--window", help="Join window in seconds."),
    db: Path | None = DbOption,
) -> None:
    """Fill each leg's gaps from the other: router hostnames onto device-leg flows,
    device-leg apps onto router flows."""
    conn = open_db(db)
    device = _get_device(conn, name)
    assert device.id is not None
    with transaction(conn):
        result = correlate(conn, device.id, window_s=window)
    console.print(
        f"[green]correlated[/green] hostnames filled={result.hostnames_filled}  "
        f"apps filled={result.apps_filled}  ambiguous={result.ambiguous}"
    )


@flow_app.command("top")
def flow_top(
    by: str = typer.Option("host", "--by", help="host|app|ip"),
    last: str = typer.Option("24h", "--last", help="Window spec, e.g. 24h, 7d."),
    limit: int = typer.Option(25, "--limit"),
    db: Path | None = DbOption,
) -> None:
    """Rank what the device talked to."""
    if by not in ("host", "app", "ip"):
        err.print("[red]--by must be host|app|ip[/red]")
        raise typer.Exit(code=1)
    conn = open_db(db)
    try:
        since = iso_ago(parse_last(last))
    except ValueError as e:
        err.print(f"[red]{e}[/red]")
        raise typer.Exit(code=1) from e

    column = {"host": "hostname", "app": "app_pkg", "ip": "dst_ip"}[by]
    rows = conn.execute(
        f"SELECT COALESCE({column}, '(unattributed)') k, COUNT(*) flows, "
        f"       SUM(bytes_out) out_b, SUM(bytes_in) in_b "
        f"FROM flows WHERE ts >= ? GROUP BY k ORDER BY flows DESC LIMIT ?",
        (since, limit),
    ).fetchall()
    if not rows:
        console.print(f"[dim]no flows in the last {last}[/dim]")
        return

    table = Table(title=f"top by {by} (last {last})")
    table.add_column(by)
    table.add_column("flows", justify="right")
    table.add_column("out", justify="right")
    table.add_column("in", justify="right")
    for r in rows:
        table.add_row(str(r["k"]), str(r["flows"]), _bytes(r["out_b"]), _bytes(r["in_b"]))
    console.print(table)


@flow_app.command("host")
def flow_host(
    hostname: str = typer.Argument(..., help="Hostname to look up."),
    last: str = typer.Option("7d", "--last"),
    db: Path | None = DbOption,
) -> None:
    """Show every flow to a hostname."""
    conn = open_db(db)
    try:
        since = iso_ago(parse_last(last))
    except ValueError as e:
        err.print(f"[red]{e}[/red]")
        raise typer.Exit(code=1) from e
    rows = conn.execute(
        "SELECT ts, proto, dst_ip, dst_port, app_pkg, sni_status, bytes_out, bytes_in "
        "FROM flows WHERE hostname = ? AND ts >= ? ORDER BY ts DESC LIMIT 200",
        (hostname, since),
    ).fetchall()
    if not rows:
        console.print(f"[dim]no flows to {hostname} in the last {last}[/dim]")
        return
    table = Table(title=f"{hostname} (last {last})")
    for col in ("ts", "proto", "ip", "port", "app", "sni", "out", "in"):
        table.add_column(col)
    for r in rows:
        table.add_row(
            r["ts"],
            r["proto"],
            r["dst_ip"],
            str(r["dst_port"]),
            r["app_pkg"] or "",
            r["sni_status"] or "",
            _bytes(r["bytes_out"]),
            _bytes(r["bytes_in"]),
        )
    console.print(table)


@flow_app.command("rollup")
def flow_rollup(
    name: str = typer.Argument(None, help="Device name."),
    keep_days: int = typer.Option(7, "--keep-days", help="Raw flow retention."),
    db: Path | None = DbOption,
) -> None:
    """Compact raw flows into hourly aggregates and drop raw rows past retention."""
    conn = open_db(db)
    device = _get_device(conn, name)
    assert device.id is not None
    hours = [
        r["h"]
        for r in conn.execute(
            "SELECT DISTINCT substr(ts, 1, 13) h FROM flows WHERE device_id = ?",
            (device.id,),
        ).fetchall()
    ]
    with transaction(conn):
        for hour in hours:
            rollup_flows(conn, device.id, hour)
        cutoff = iso_ago(timedelta(days=keep_days))
        purged = purge_flows_before(conn, cutoff)
    console.print(
        f"[green]rolled up[/green] {len(hours)} hour(s); purged {purged} raw row(s) "
        f"older than {keep_days}d"
    )


def _device_leg_status(conn: sqlite3.Connection) -> tuple[bool, str]:
    rows = conn.execute("SELECT name, identifier FROM devices WHERE platform='android'").fetchall()
    if not rows:
        return False, "no android device registered"
    try:
        adb_path = adb.find_adb()
    except adb.AdbNotFound as e:
        return False, str(e)
    serial = rows[0]["identifier"]

    def shell(cmd: str) -> tuple[int, str, str]:
        try:
            r = adb.shell(adb_path, serial, cmd, timeout_s=15)
        except adb.AdbError as e:
            return (-1, "", str(e))
        return (r.returncode, r.stdout, r.stderr)

    return DeviceSource(shell=shell).available()


def _bytes(n: int | None) -> str:
    value = float(n or 0)
    for unit in ("B", "K", "M", "G"):
        if value < 1024 or unit == "G":
            return f"{value:.0f}{unit}" if unit == "B" else f"{value:.1f}{unit}"
        value /= 1024
    return f"{value:.1f}G"


# ---- timeline ----


@app.command("timeline")
def timeline(  # noqa: PLR0917 — CLI options
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
        help="Output directory (default: ~/Library/Application Support/psm/reports).",
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
        out = default_data_dir() / "reports"
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

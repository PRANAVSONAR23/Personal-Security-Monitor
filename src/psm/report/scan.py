"""Scan report rendering — rich tables, action-colored, collection gaps surfaced."""

from __future__ import annotations

from collections import Counter

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from psm.core.models import Alert, CollectionGap, Event, Snapshot

_ACTION_STYLE = {
    "added": "green",
    "removed": "red",
    "changed": "yellow",
    "observed": "cyan",
}


def _sev_style(sev: str) -> str:
    return {"info": "dim", "notice": "white", "warning": "yellow", "alert": "bold red"}.get(
        sev, "white"
    )


def render_scan(
    console: Console,
    *,
    snapshot: Snapshot,
    events: list[Event],
    prior_snapshot_id: int | None,
    scope_notes: dict[str, list[str]] | None = None,
    enrichment: dict[int, str] | None = None,
) -> None:
    header_lines = [
        f"[bold]snapshot #{snapshot.id}[/bold]  ({snapshot.kind}, {snapshot.taken_at})",
        f"modules collected: {', '.join(sorted(snapshot.capabilities)) or '(none)'}",
    ]
    if prior_snapshot_id is not None:
        header_lines.append(f"diff against snapshot #{prior_snapshot_id}")
    console.print(Panel.fit("\n".join(header_lines), title="psm scan"))

    if snapshot.gaps:
        _render_gaps(console, snapshot.gaps)

    if scope_notes and (scope_notes.get("only_in_before") or scope_notes.get("only_in_after")):
        _render_scope_notes(console, scope_notes)

    if not events:
        console.print("[green]no changes detected[/green]")
        return

    counts = Counter(e.action for e in events)
    summary = "  ".join(
        f"[{_ACTION_STYLE[a]}]{a}={n}[/{_ACTION_STYLE[a]}]" for a, n in sorted(counts.items())
    )
    console.print(f"\n{summary}\n")

    for category in sorted({e.category for e in events}):
        _render_category(
            console,
            category,
            [e for e in events if e.category == category],
            enrichment=enrichment,
        )


def _render_category(
    console: Console,
    category: str,
    events: list[Event],
    *,
    enrichment: dict[int, str] | None = None,
) -> None:
    show_enrich = enrichment is not None and any(
        e.id is not None and e.id in enrichment for e in events
    )
    table = Table(title=category, show_header=True, header_style="bold")
    table.add_column("action", width=8)
    table.add_column("subject")
    table.add_column("sev", width=8)
    if show_enrich:
        table.add_column("enrich")
    for e in sorted(events, key=lambda x: (x.action, x.subject_key)):
        style = _ACTION_STYLE.get(e.action, "white")
        row = [
            f"[{style}]{e.action}[/{style}]",
            e.subject_key,
            f"[{_sev_style(e.severity)}]{e.severity}[/{_sev_style(e.severity)}]",
        ]
        if show_enrich:
            row.append((enrichment or {}).get(e.id, "") if e.id is not None else "")
        table.add_row(*row)
    console.print(table)


def _render_gaps(console: Console, gaps: list[CollectionGap]) -> None:
    table = Table(title="collection gaps", show_header=True, header_style="yellow")
    table.add_column("module")
    table.add_column("reason")
    table.add_column("detail")
    for g in gaps:
        table.add_row(g.module, g.reason, g.detail)
    console.print(table)


def _render_scope_notes(console: Console, notes: dict[str, list[str]]) -> None:
    parts = []
    if notes.get("only_in_before"):
        parts.append(f"only-in-before: {', '.join(notes['only_in_before'])}")
    if notes.get("only_in_after"):
        parts.append(f"only-in-after: {', '.join(notes['only_in_after'])}")
    console.print(f"[dim]scope note: {'  |  '.join(parts)}[/dim]")


def render_alerts(console: Console, alerts: list[Alert]) -> None:
    table = Table(title=f"alerts ({len(alerts)})", header_style="bold red")
    table.add_column("id", width=6)
    table.add_column("rule")
    table.add_column("title")
    table.add_column("events")
    for a in alerts:
        events = a.detail.get("events", [])
        table.add_row(
            f"#{a.id}" if a.id is not None else "?",
            a.rule_id,
            a.title,
            ", ".join(f"#{e}" for e in events),
        )
    console.print(table)

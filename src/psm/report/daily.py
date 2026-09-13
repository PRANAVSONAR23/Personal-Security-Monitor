"""Daily report generator.

Renders a single Markdown file summarizing events + open alerts in a rolling window
(default 24h). Written under `<out_dir>/daily-<YYYY-MM-DD>.md` — Task Scheduler
picks this up. Not the same as `psm timeline` — the daily report is meant to be
skimmable by a human.
"""

from __future__ import annotations

import datetime as _dt
from collections import Counter
from pathlib import Path
from typing import Any

from psm.core.models import Alert


def render(
    events: list[dict[str, Any]],
    alerts: list[Alert],
    *,
    window: _dt.timedelta,
    generated_at: str,
) -> str:
    counts = Counter((r["category"], r["action"]) for r in events)
    sev_counts = Counter(r.get("severity", "info") for r in events)

    lines: list[str] = []
    lines.append(f"# psm daily report — {generated_at}")
    lines.append("")
    lines.append(f"Window: last {_pretty_window(window)}")
    lines.append("")
    lines.append(f"- **events:** {len(events)}")
    lines.append(f"- **open alerts:** {len(alerts)}")
    for sev in ("alert", "warning", "notice", "info"):
        if sev_counts[sev]:
            lines.append(f"- **{sev}:** {sev_counts[sev]}")
    lines.append("")

    if alerts:
        lines.append("## Open alerts")
        lines.append("")
        for a in alerts:
            events_field = a.detail.get("events", []) if isinstance(a.detail, dict) else []
            lines.append(
                f"- **#{a.id}** `{a.rule_id}` — {a.title} "
                f"(events: {', '.join(f'#{e}' for e in events_field) or '—'})"
            )
        lines.append("")

    if events:
        lines.append("## Event counts by (category, action)")
        lines.append("")
        lines.append("| category | action | count |")
        lines.append("|---|---|---:|")
        for (cat, action), n in sorted(counts.items()):
            lines.append(f"| {cat} | {action} | {n} |")
        lines.append("")

        lines.append("## Recent events")
        lines.append("")
        lines.append("| id | ts | category | action | severity | subject |")
        lines.append("|---:|---|---|---|---|---|")
        for r in events[:50]:  # cap the table; timeline export is the full log
            lines.append(
                f"| #{r['id']} | {r['ts']} | {r['category']} | {r['action']} | "
                f"{r.get('severity', '')} | `{r['subject_key']}` |"
            )
        lines.append("")

    return "\n".join(lines)


def write(
    out_dir: Path,
    events: list[dict[str, Any]],
    alerts: list[Alert],
    *,
    window: _dt.timedelta,
    now: _dt.datetime | None = None,
) -> Path:
    now = now or _dt.datetime.now(_dt.UTC)
    out_dir.mkdir(parents=True, exist_ok=True)
    generated_iso = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    text = render(events, alerts, window=window, generated_at=generated_iso)
    dest = out_dir / f"daily-{now.strftime('%Y-%m-%d')}.md"
    dest.write_text(text, encoding="utf-8")
    return dest


def _pretty_window(window: _dt.timedelta) -> str:
    total = int(window.total_seconds())
    if total % 86400 == 0:
        return f"{total // 86400}d"
    if total % 3600 == 0:
        return f"{total // 3600}h"
    return f"{total}s"

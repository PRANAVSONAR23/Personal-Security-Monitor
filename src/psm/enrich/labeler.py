"""Turn events + payloads into per-event enrichment labels for the report.

Order of precedence:
  known_good  →  vt(malicious/suspicious)  →  vt(harmless/unknown)

We only annotate file-category events — every other category has no meaningful
hash to look up. Removed events use `before_hash`; everything else uses
`after_hash`.
"""

from __future__ import annotations

import sqlite3

from psm.core.models import Event
from psm.enrich.known_good import bulk_lookup as known_good_lookup
from psm.enrich.vt import VtClient
from psm.store.queries import load_item_payload


def build_labels(  # noqa: PLR0912
    conn: sqlite3.Connection,
    events: list[Event],
    *,
    vt_client: VtClient | None = None,
) -> dict[int, str]:
    labels: dict[int, str] = {}
    files = [e for e in events if e.category == "file" and e.id is not None]
    if not files:
        return labels

    hashes: dict[int, str] = {}
    for e in files:
        item_hash = e.after_hash if e.action != "removed" else e.before_hash
        if not item_hash:
            continue
        payload = load_item_payload(conn, item_hash)
        if not payload:
            continue
        sha = payload.get("sha256")
        if isinstance(sha, str):
            assert e.id is not None  # narrowed by the filter above
            hashes[e.id] = sha

    if not hashes:
        return labels

    kg = known_good_lookup(conn, hashes.values())
    for event_id, sha in hashes.items():
        if sha.lower() in kg:
            labels[event_id] = "known_good"

    if vt_client is not None and vt_client.enabled:
        vt_targets = [sha for eid, sha in hashes.items() if eid not in labels]
        vt = vt_client.bulk_lookup(vt_targets)
        for event_id, sha in hashes.items():
            if event_id in labels:
                continue
            verdict = vt.get(sha.lower())
            if verdict is None:
                continue
            if verdict.malicious:
                labels[event_id] = f"vt:malicious({verdict.malicious})"
            elif verdict.suspicious:
                labels[event_id] = f"vt:suspicious({verdict.suspicious})"
            elif verdict.known:
                labels[event_id] = "vt:seen"
            elif verdict.error:
                labels[event_id] = f"vt:{verdict.error}"
    return labels

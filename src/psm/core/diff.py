"""Snapshot diff (LLD §4). Pure function — no DB access."""

from __future__ import annotations

from psm.core.models import Event, Snapshot, utcnow_iso

SnapshotIndex = dict[str, dict[str, str]]  # {category: {subject_key: item_hash}}


def diff(
    snap_a: Snapshot,
    idx_a: SnapshotIndex,
    snap_b: Snapshot,
    idx_b: SnapshotIndex,
    *,
    ts: str | None = None,
) -> list[Event]:
    if snap_a.device_id != snap_b.device_id:
        raise ValueError("cannot diff snapshots from different devices")
    if snap_a.id is None or snap_b.id is None:
        raise ValueError("both snapshots must have ids assigned")

    stamp = ts or utcnow_iso()
    shared = snap_a.capabilities & snap_b.capabilities
    events: list[Event] = []

    for category in shared:
        a_map = idx_a.get(category, {})
        b_map = idx_b.get(category, {})

        for key in b_map.keys() - a_map.keys():
            events.append(
                Event(
                    device_id=snap_b.device_id,
                    ts=stamp,
                    category=category,
                    action="added",
                    subject_key=key,
                    before_hash=None,
                    after_hash=b_map[key],
                    snap_from=snap_a.id,
                    snap_to=snap_b.id,
                )
            )

        for key in a_map.keys() - b_map.keys():
            events.append(
                Event(
                    device_id=snap_b.device_id,
                    ts=stamp,
                    category=category,
                    action="removed",
                    subject_key=key,
                    before_hash=a_map[key],
                    after_hash=None,
                    snap_from=snap_a.id,
                    snap_to=snap_b.id,
                )
            )

        for key in a_map.keys() & b_map.keys():
            if a_map[key] != b_map[key]:
                events.append(
                    Event(
                        device_id=snap_b.device_id,
                        ts=stamp,
                        category=category,
                        action="changed",
                        subject_key=key,
                        before_hash=a_map[key],
                        after_hash=b_map[key],
                        snap_from=snap_a.id,
                        snap_to=snap_b.id,
                    )
                )

    return events


def scope_notes(snap_a: Snapshot, snap_b: Snapshot) -> dict[str, list[str]]:
    """Categories only in one snapshot — carried in reports, never as events."""
    return {
        "only_in_before": sorted(snap_a.capabilities - snap_b.capabilities),
        "only_in_after": sorted(snap_b.capabilities - snap_a.capabilities),
    }

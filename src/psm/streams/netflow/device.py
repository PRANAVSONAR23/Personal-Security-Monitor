"""On-device capture leg — polls /proc/net over adb.

This replaces the VpnService agent the plan originally called for, because the
platform already exposes what that agent would have provided. `/proc/net/{tcp,
tcp6,udp,udp6}` is readable over plain `adb exec-out` on a non-rooted device and
every row carries the owning UID, so per-app attribution needs nothing installed
on the phone at all.

What that buys over an agent:

  * Zero footprint — D4's agentless principle stays intact.
  * Nothing for MIUI to kill, which the user's own notes flag as the main risk to
    a background service on a 4 GB device.
  * No userspace packet forwarding, so a bug here cannot take the phone offline.
  * Works on mobile data, not only on a network we control.

What it costs, and these are real:

  * **It reports what is open now, sampled.** A socket opened and closed between
    two polls is never seen, and one caught mid-close is deliberately skipped
    because the kernel has already dropped its owner. So this is not a complete
    connection log — it is a sample of live connections, which is exactly right for
    long-lived channels (push, sync, streaming) and blind to brief ones.
  * **No per-connection byte counts.** /proc/net carries queue depths, not
    totals, so flows from this leg have zero bytes. The router leg is where byte
    volume comes from.
  * **No DNS.** Hostnames here come from reverse DNS, which is an inference
    (recorded as hostname_source="rdns") and is often useless for CDNs.
"""

from __future__ import annotations

import json
import socket
import sqlite3
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field

from psm.core.models import Flow, utcnow_iso
from psm.streams.base import SourceHealth, StreamSource
from psm.streams.netflow.procnet import Socket, parse

ShellFn = Callable[[str], tuple[int, str, str]]

TABLES: tuple[tuple[str, str], ...] = (
    ("/proc/net/tcp", "tcp"),
    ("/proc/net/tcp6", "tcp"),
    ("/proc/net/udp", "udp"),
    ("/proc/net/udp6", "udp"),
)
# One `cat` of all four tables measured ~0.48 s over wireless adb, so a 1 s
# interval is about the floor without the poll dominating the link.
DEFAULT_INTERVAL_S = 1.0
RDNS_TIMEOUT_S = 1.0


@dataclass(slots=True)
class DeviceSource(StreamSource):
    shell: ShellFn
    interval_s: float = DEFAULT_INTERVAL_S
    resolve_hostnames: bool = True
    # The controller's own addresses. Our adb session is itself a socket on the
    # phone (uid 2000, com.android.shell) and showed up as 14 of 21 attributable
    # connections — observer effect, not device behaviour.
    exclude_ips: frozenset[str] = frozenset()
    kind: str = "netflow"
    requires_tier: str = "base"
    _seen: set[tuple[str, int, str, int, int]] = field(default_factory=set)
    skipped_unattributable: int = 0
    _rdns: dict[str, str | None] = field(default_factory=dict)
    _health: SourceHealth = field(default_factory=lambda: SourceHealth(running=False))
    _stop: bool = False

    def available(self) -> tuple[bool, str]:
        rc, out, err = self.shell("cat /proc/net/tcp")
        if rc != 0 or "local_address" not in out:
            return False, (
                "/proc/net/tcp is not readable over adb "
                f"({(err or out).strip()[:120]}) — check the device is connected"
            )
        return True, "polling /proc/net over adb"

    def poll(self) -> list[Socket]:
        """One sample of all four tables. A failed table is skipped, not fatal."""
        sockets: list[Socket] = []
        for path, proto in TABLES:
            rc, out, _ = self.shell(f"cat {path}")
            if rc != 0:
                continue
            sockets.extend(parse(out, proto))
        return sockets

    def new_connections(self, sockets: list[Socket]) -> list[Socket]:
        """Sockets with a remote peer not seen in an earlier poll."""
        fresh: list[Socket] = []
        for s in sockets:
            if not s.is_remote or s.key in self._seen:
                continue
            self._seen.add(s.key)
            if s.remote_ip in self.exclude_ips:
                continue
            if not s.is_attributable:
                # Closing socket: uid reads 0 because the owner is gone. Counted so
                # the blind spot is visible, not emitted as root activity.
                self.skipped_unattributable += 1
                continue
            fresh.append(s)
        return fresh

    def subscribe(self) -> Iterator[Socket]:
        ok, detail = self.available()
        if not ok:
            self._health = SourceHealth(running=False, error=detail)
            return
        self._health = SourceHealth(running=True, started_at=utcnow_iso())
        self._stop = False
        try:
            while not self._stop:
                fresh = self.new_connections(self.poll())
                self._health.records += len(fresh)
                yield from fresh
                time.sleep(self.interval_s)
        finally:
            self._health.running = False
            self._health.stopped_at = utcnow_iso()

    def stop(self) -> None:
        self._stop = True

    def health(self) -> SourceHealth:
        return self._health

    def hostname(self, ip: str) -> str | None:
        """Best-effort reverse DNS, cached — including negative results, so a
        CDN address with no PTR is not re-queried on every poll."""
        if not self.resolve_hostnames:
            return None
        if ip in self._rdns:
            return self._rdns[ip]
        name: str | None = None
        previous = socket.getdefaulttimeout()
        socket.setdefaulttimeout(RDNS_TIMEOUT_S)
        try:
            name = socket.gethostbyaddr(ip)[0]
        except (OSError, socket.herror, socket.gaierror):
            name = None
        finally:
            socket.setdefaulttimeout(previous)
        self._rdns[ip] = name
        return name


def local_addresses() -> frozenset[str]:
    """Every address this machine answers on, so our own adb traffic is excluded."""
    found = {"127.0.0.1", "::1"}
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None):
            found.add(info[4][0])
    except OSError:
        pass
    try:
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        probe.connect(("8.8.8.8", 80))
        found.add(probe.getsockname()[0])
        probe.close()
    except OSError:
        pass
    return frozenset(found)


def uid_to_package(conn: sqlite3.Connection, device_id: int) -> dict[int, str]:
    """UID → package, from the application inventory already collected.

    `app_id` is the dumpsys `userId` field, stored by the packages module, so this
    needs no extra device round trip.
    """
    rows = conn.execute(
        "SELECT DISTINCT i.payload FROM snapshot_items si "
        "JOIN items i ON i.hash = si.item_hash "
        "JOIN snapshots s ON s.id = si.snapshot_id "
        "WHERE s.device_id = ? AND i.category = 'application'",
        (device_id,),
    ).fetchall()
    mapping: dict[int, str] = {}
    for row in rows:
        payload = json.loads(row["payload"])
        uid, pkg = payload.get("app_id"), payload.get("id")
        if isinstance(uid, int) and isinstance(pkg, str):
            mapping.setdefault(uid, pkg)
    return mapping


def to_flow(
    source: DeviceSource,
    sock: Socket,
    device_id: int,
    uid_map: dict[int, str],
) -> Flow:
    name = source.hostname(sock.remote_ip)
    return Flow(
        device_id=device_id,
        ts=utcnow_iso(),
        leg="device",
        proto=sock.proto,
        dst_ip=sock.remote_ip,
        dst_port=sock.remote_port,
        src_port=sock.local_port,
        hostname=name,
        hostname_source="rdns" if name else None,
        sni_status=None,
        app_uid=sock.uid,
        app_pkg=uid_map.get(sock.uid),
        bytes_out=0,  # /proc/net has queue depths, not totals — see module docstring
        bytes_in=0,
    )

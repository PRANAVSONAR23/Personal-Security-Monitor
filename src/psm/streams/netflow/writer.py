"""Packet aggregation and persistence.

Packets are folded into per-window aggregates before they touch SQLite: one row
per (window, proto, remote ip, remote port, hostname) with byte counts summed.
Writing a row per packet would be millions of rows a day for no added signal,
and the hourly rollup would then be aggregating an aggregate.

Hostnames come from two places, preferred in this order:

  1. TLS SNI on the connection itself — exact, no inference.
  2. The DNS cache built from observed A/AAAA answers — an attribution, since
     several names can share an address.

`hostname_source` records which, so a guess is never presented as a fact.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime

from psm.core.models import CaptureLeg, Flow
from psm.store.queries import insert_flows
from psm.streams.netflow.decode import Packet

# A remote endpoint seen with one of these ports is the server side, used only
# when the local-prefix check cannot settle direction.
WELL_KNOWN = frozenset({53, 80, 443, 853, 993, 995, 8080, 8443, 5228})


@dataclass(slots=True)
class _Agg:
    proto: str
    dst_ip: str
    dst_port: int
    hostname: str | None
    hostname_source: str | None
    sni_status: str | None
    bytes_out: int = 0
    bytes_in: int = 0
    count: int = 0
    first_ts: float = 0.0
    last_ts: float = 0.0


@dataclass(slots=True)
class FlowAggregator:
    """Folds packets into flow rows. Pure in-memory; the caller persists."""

    device_id: int
    leg: CaptureLeg
    local_prefixes: tuple[str, ...] = ()
    dns: dict[str, str] = field(default_factory=dict)
    table: dict[tuple[str, str, int, str | None], _Agg] = field(default_factory=dict)
    dropped: int = 0

    def add(self, pkt: Packet) -> None:
        for name, addresses in pkt.dns_answers.items():
            for address in addresses:
                self.dns[address] = name

        remote_ip, remote_port, outbound = self._orient(pkt)
        hostname, source = self._hostname(pkt, remote_ip)
        key = (pkt.proto, remote_ip, remote_port, hostname)
        agg = self.table.get(key)
        if agg is None:
            agg = _Agg(
                proto=pkt.proto,
                dst_ip=remote_ip,
                dst_port=remote_port,
                hostname=hostname,
                hostname_source=source,
                sni_status=pkt.sni_status,
                first_ts=pkt.ts,
            )
            self.table[key] = agg
        if pkt.sni_status == "plain":
            agg.sni_status = "plain"
        elif pkt.sni_status == "ech" and agg.sni_status != "plain":
            agg.sni_status = "ech"
        if outbound:
            agg.bytes_out += pkt.length
        else:
            agg.bytes_in += pkt.length
        agg.count += 1
        agg.last_ts = pkt.ts

    def _orient(self, pkt: Packet) -> tuple[str, int, bool]:
        """Identify the remote endpoint and whether the packet was outbound."""
        src_local = self._is_local(pkt.src_ip)
        dst_local = self._is_local(pkt.dst_ip)
        if src_local and not dst_local:
            return pkt.dst_ip, pkt.dst_port, True
        if dst_local and not src_local:
            return pkt.src_ip, pkt.src_port, False
        # Both or neither local: fall back to which side holds a server port.
        if pkt.dst_port in WELL_KNOWN or pkt.dst_port < pkt.src_port:
            return pkt.dst_ip, pkt.dst_port, True
        return pkt.src_ip, pkt.src_port, False

    def _is_local(self, ip: str) -> bool:
        return any(ip.startswith(p) for p in self.local_prefixes)

    def _hostname(self, pkt: Packet, remote_ip: str) -> tuple[str | None, str | None]:
        if pkt.hostname and pkt.sni_status == "plain":
            return pkt.hostname, "sni"
        if pkt.hostname and pkt.proto == "udp":
            return pkt.hostname, "dns-query"
        cached = self.dns.get(remote_ip)
        if cached:
            return cached, "dns-cache"
        return None, None

    def drain(self) -> list[Flow]:
        """Return accumulated rows and reset the table."""
        flows = [
            Flow(
                device_id=self.device_id,
                ts=_iso(a.first_ts),
                leg=self.leg,
                proto=a.proto,
                dst_ip=a.dst_ip,
                dst_port=a.dst_port,
                src_port=None,
                hostname=a.hostname,
                hostname_source=a.hostname_source,  # type: ignore[arg-type]
                sni_status=a.sni_status,  # type: ignore[arg-type]
                bytes_out=a.bytes_out,
                bytes_in=a.bytes_in,
            )
            for a in self.table.values()
        ]
        self.table.clear()
        return flows


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def persist(conn: sqlite3.Connection, flows: Iterable[Flow]) -> int:
    return insert_flows(conn, flows)

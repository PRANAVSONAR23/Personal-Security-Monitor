"""Parser for Android's /proc/net socket tables.

Readable over plain `adb exec-out` on a non-rooted device, and every row carries
the owning UID — which is per-app network attribution with nothing installed on
the phone. Verified on a POCO M2 Pro, SDK 31: 58 tcp + 97 tcp6 + 52 udp + 48 udp6
rows, `ss` blocked by netlink permissions but /proc readable.

Row layout (fields after `str.split()`):

      sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt uid ...
      41: 0601A8C0:90D6 902A9039:01BB 01 00000000:00000000 00:00000000 00000000 10645
       0      1              2         3         4              5         6       7

Addresses are hex with each 4-byte word in little-endian order, so `0601A8C0`
is 192.168.1.6. IPv4-mapped IPv6 rows carry the v4 address in the final word.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass

# 0x0A is TCP_LISTEN. This kernel reports listening sockets as 0x8A — the same
# state with the high bit set — so the bit is masked off rather than treating 0x8A
# as an unknown state and dropping 72 of 150 rows.
_STATE_MASK = 0x7F
TCP_STATES: dict[int, str] = {
    0x01: "established",
    0x02: "syn-sent",
    0x03: "syn-recv",
    0x04: "fin-wait1",
    0x05: "fin-wait2",
    0x06: "time-wait",
    0x07: "close",
    0x08: "close-wait",
    0x09: "last-ack",
    0x0A: "listen",
    0x0B: "closing",
}

# States in which the kernel still reports the owning UID. Once a socket starts
# closing the owner is dropped and uid reads 0 — measured on the test device as 50
# FIN_WAIT1 plus 7 LAST_ACK sockets, every one of them uid=0. Emitting those would
# invent 57 flows of apparent root activity, so they are skipped rather than
# attributed to root.
ATTRIBUTABLE_STATES = frozenset({"established", "syn-sent", "syn-recv", "close-wait", "stateless"})

_HEADER = re.compile(r"^\s*sl\s")


@dataclass(frozen=True, slots=True)
class Socket:
    proto: str  # "tcp" | "udp"
    local_ip: str
    local_port: int
    remote_ip: str
    remote_port: int
    state: str
    uid: int
    inode: int

    @property
    def key(self) -> tuple[str, int, str, int, int]:
        """Identity for diffing successive polls. The inode makes a reused
        local port a distinct socket rather than a continuation of the old one."""
        return (self.proto, self.local_port, self.remote_ip, self.remote_port, self.inode)

    @property
    def is_remote(self) -> bool:
        return self.remote_port != 0 and not self.remote_ip.startswith("0.0.0.0")

    @property
    def is_attributable(self) -> bool:
        """Whether this row's UID can be trusted as the owner."""
        return self.state in ATTRIBUTABLE_STATES


def parse(text: str, proto: str) -> list[Socket]:
    """Parse one /proc/net table. `proto` is "tcp" or "udp"."""
    out: list[Socket] = []
    for raw in text.splitlines():
        if not raw.strip() or _HEADER.match(raw):
            continue
        fields = raw.split()
        if len(fields) < 10:
            continue
        try:
            local_ip, local_port = _addr(fields[1])
            remote_ip, remote_port = _addr(fields[2])
            state_raw = int(fields[3], 16) & _STATE_MASK
            uid = int(fields[7])
            inode = int(fields[9])
        except (ValueError, IndexError):
            continue
        out.append(
            Socket(
                proto=proto,
                local_ip=local_ip,
                local_port=local_port,
                remote_ip=remote_ip,
                remote_port=remote_port,
                # UDP has no state machine; the column is meaningless there.
                state=TCP_STATES.get(state_raw, "other") if proto == "tcp" else "stateless",
                uid=uid,
                inode=inode,
            )
        )
    return out


def _addr(field: str) -> tuple[str, int]:
    hex_ip, _, hex_port = field.partition(":")
    return _ip(hex_ip), int(hex_port, 16)


def _ip(hex_ip: str) -> str:
    """Decode a /proc/net hex address.

    Each 4-byte word is stored in host byte order (little-endian on ARM), so the
    bytes of every word are reversed before handing them to `ipaddress`, which
    then does the canonical formatting — including collapsing ::ffff:a.b.c.d to
    the plain IPv4 form.
    """
    try:
        if len(hex_ip) == 8:
            raw = bytes.fromhex(hex_ip)[::-1]
        elif len(hex_ip) == 32:
            raw = b"".join(bytes.fromhex(hex_ip[i : i + 8])[::-1] for i in range(0, 32, 8))
        else:
            return hex_ip
        address = ipaddress.ip_address(raw)
    except ValueError:
        return hex_ip
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        return str(address.ipv4_mapped)
    return str(address)

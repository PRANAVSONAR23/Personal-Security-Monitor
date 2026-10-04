"""Mac-as-router capture leg.

The phone joins the Mac's Internet Sharing hotspot, so every packet it sends
routes through the Mac and can be read off the bridge interface. Zero footprint
on the phone — nothing is installed and no agent runs there.

Prerequisites, both checked by `available()` so a missing one is explained rather
than discovered mid-capture:

  * Internet Sharing on, which creates a bridge interface (bridge100 on current
    macOS) and makes the Wi-Fi AP interface (ap1) associated.
  * root, for BPF access. This is the `admin` tier.

Hardware limit worth knowing before trying: macOS will not share a Wi-Fi uplink
back out over the same Wi-Fi radio, so this leg needs a second interface — a
wired uplink to share from, or a wired link to the client. With Wi-Fi as the only
active interface the hotspot cannot be created at all, and `available()` says so.
"""

from __future__ import annotations

import os
import shutil
import struct
import subprocess
from collections.abc import Iterator
from dataclasses import dataclass, field

from psm.core.models import utcnow_iso
from psm.streams.base import SourceHealth, StreamSource
from psm.streams.netflow.decode import DecodeError, Packet, decode, iter_pcap

# Internet Sharing bridges clients here; the number increments if several exist.
BRIDGE_PREFIX = "bridge1"
SNAPLEN = 1600  # enough for a full ClientHello without copying payload bodies
READ_CHUNK = 1 << 16


@dataclass(slots=True)
class RouterSource(StreamSource):
    """Reads a live pcap stream from `tcpdump` on the sharing bridge."""

    interface: str | None = None
    snaplen: int = SNAPLEN
    kind: str = "netflow"
    requires_tier: str = "admin"
    _health: SourceHealth = field(default_factory=lambda: SourceHealth(running=False))
    _proc: subprocess.Popen[bytes] | None = None

    # -- prerequisites ---------------------------------------------------

    def available(self) -> tuple[bool, str]:
        if shutil.which("tcpdump") is None:
            return False, "tcpdump not found on PATH"
        if os.geteuid() != 0:
            return False, ("packet capture needs root (the `admin` tier) — run psm under sudo")
        iface = self.interface or find_bridge()
        if iface is None:
            return False, (
                "no Internet Sharing bridge interface found. Enable System Settings → "
                "General → Sharing → Internet Sharing, sharing from a wired connection "
                "to Wi-Fi, then join that hotspot from the phone. Note macOS cannot "
                "share a Wi-Fi uplink over Wi-Fi, so a wired uplink is required."
            )
        return True, iface

    # -- capture ---------------------------------------------------------

    def subscribe(self) -> Iterator[Packet]:
        ok, detail = self.available()
        if not ok:
            self._health = SourceHealth(running=False, error=detail)
            return
        iface = self.interface or detail
        argv = [
            "tcpdump",
            "-i",
            iface,
            "-n",  # no reverse DNS, which would be our own traffic
            "-s",
            str(self.snaplen),
            "-U",  # flush per packet so records arrive promptly
            "-w",
            "-",  # pcap on stdout
            "ip or ip6",
        ]
        self._health = SourceHealth(running=True, started_at=utcnow_iso())
        self._proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        try:
            yield from self._read(self._proc)
        finally:
            self.stop()

    def _read(self, proc: subprocess.Popen[bytes]) -> Iterator[Packet]:
        assert proc.stdout is not None
        buffer = b""
        linktype: int | None = None
        while True:
            chunk = proc.stdout.read(READ_CHUNK)
            if not chunk:
                break
            buffer += chunk
            if linktype is None:
                if len(buffer) < 24:
                    continue
                try:
                    linktype, _ = iter_pcap(buffer[:24])
                except DecodeError:
                    break
            consumed, packets = _drain(buffer, linktype)
            buffer = buffer[consumed:]
            yield from packets
            self._health.records += len(packets)

    def stop(self) -> None:
        self._health.running = False
        self._health.stopped_at = utcnow_iso()
        if self._proc is not None and self._proc.poll() is None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._proc.kill()
        self._proc = None

    def health(self) -> SourceHealth:
        return self._health


def _drain(buffer: bytes, linktype: int) -> tuple[int, list[Packet]]:
    """Decode whole records from `buffer`, returning (bytes consumed, packets).

    A partial trailing record is left for the next read; without this a packet
    split across two reads would be dropped.
    """
    offset = 24 if buffer[:4] in _MAGICS else 0
    packets: list[Packet] = []
    while offset + 16 <= len(buffer):
        sec, frac, incl, _orig = struct.unpack("<IIII", buffer[offset : offset + 16])
        if offset + 16 + incl > len(buffer):
            break
        frame = buffer[offset + 16 : offset + 16 + incl]
        offset += 16 + incl
        pkt = decode(sec + frac / 1_000_000, frame, linktype)
        if pkt is not None:
            packets.append(pkt)
    return offset, packets


_MAGICS = frozenset(
    {
        (0xA1B2C3D4).to_bytes(4, "little"),
        (0xA1B23C4D).to_bytes(4, "little"),
        (0xA1B2C3D4).to_bytes(4, "big"),
        (0xA1B23C4D).to_bytes(4, "big"),
    }
)


def find_bridge() -> str | None:
    """Locate the Internet Sharing bridge, if one is up."""
    try:
        out = subprocess.run(
            ["ifconfig", "-l"], capture_output=True, text=True, timeout=5, check=False
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    for name in out.split():
        if name.startswith(BRIDGE_PREFIX):
            return name
    return None


def hotspot_prefixes(interface: str) -> tuple[str, ...]:
    """The client-side address prefix served on `interface`, for orienting flows."""
    try:
        out = subprocess.run(
            ["ifconfig", interface], capture_output=True, text=True, timeout=5, check=False
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return ()
    for line in out.splitlines():
        parts = line.split()
        if parts and parts[0] == "inet" and len(parts) > 1:
            octets = parts[1].split(".")
            if len(octets) == 4:
                return (".".join(octets[:3]) + ".",)
    return ()

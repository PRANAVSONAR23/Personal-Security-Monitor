"""Packet decoders — pcap stream to flow records. Stdlib only.

Shared by both capture legs: the Mac-as-router leg reads Ethernet frames off a
bridge interface, the on-device VPN leg reads raw IP packets off a TUN. Only the
link-layer offset differs, so `linktype` is a parameter and everything above IP
is common.

What is extracted, and the ceiling on each:

  flow tuple    proto, src/dst, ports, byte counts — always available.
  DNS           query names, and A/AAAA answers so later flows to those IPs can
                be attributed to a hostname. Lost entirely if the device uses
                DNS-over-HTTPS or DNS-over-TLS.
  TLS SNI       the hostname from the ClientHello, which is sent in cleartext.
                No decryption, no interception. Lost when the client uses
                Encrypted Client Hello, which is recorded as sni_status="ech"
                rather than silently dropped.

No TCP reassembly: a ClientHello split across segments is not recovered and the
flow is reported with sni_status="none". In practice a ClientHello fits in one
segment; the alternative is holding per-connection state for a marginal gain.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Literal

PCAP_MAGIC_US = 0xA1B2C3D4
PCAP_MAGIC_NS = 0xA1B23C4D

LINKTYPE_NULL = 0
LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 101  # libpcap DLT_RAW on Linux/BSD: bare IP, what a TUN yields

ETH_HEADER_LEN = 14
ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_IPV6 = 0x86DD

PROTO_TCP = 6
PROTO_UDP = 17

TLS_HANDSHAKE = 0x16
TLS_CLIENT_HELLO = 0x01
EXT_SERVER_NAME = 0x0000
EXT_ECH = 0xFE0D  # draft-ietf-tls-esni encrypted_client_hello

SniStatus = Literal["plain", "ech", "none"]


class DecodeError(ValueError):
    pass


@dataclass(slots=True)
class Packet:
    ts: float
    proto: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    length: int
    hostname: str | None = None
    sni_status: SniStatus | None = None
    dns_answers: dict[str, list[str]] = field(default_factory=dict)


# ---------- pcap framing ----------


def iter_pcap(stream: bytes) -> tuple[int, list[tuple[float, bytes]]]:
    """Split a pcap byte stream into (linktype, [(timestamp, frame), ...]).

    Operates on a complete buffer. The live reader feeds whole records.
    """
    if len(stream) < 24:
        raise DecodeError("short pcap global header")
    (magic,) = struct.unpack("<I", stream[:4])
    if magic == PCAP_MAGIC_US:
        endian, nanos = "<", False
    elif magic == PCAP_MAGIC_NS:
        endian, nanos = "<", True
    elif struct.unpack(">I", stream[:4])[0] == PCAP_MAGIC_US:
        endian, nanos = ">", False
    elif struct.unpack(">I", stream[:4])[0] == PCAP_MAGIC_NS:
        endian, nanos = ">", True
    else:
        raise DecodeError(f"not a pcap stream (magic={magic:#x})")

    linktype = struct.unpack(endian + "I", stream[20:24])[0]
    out: list[tuple[float, bytes]] = []
    off = 24
    divisor = 1_000_000_000 if nanos else 1_000_000
    while off + 16 <= len(stream):
        sec, frac, incl, _orig = struct.unpack(endian + "IIII", stream[off : off + 16])
        off += 16
        if off + incl > len(stream):
            break  # truncated trailing record
        out.append((sec + frac / divisor, stream[off : off + incl]))
        off += incl
    return linktype, out


def ip_payload(frame: bytes, linktype: int) -> bytes:
    """Strip the link layer, returning the IP packet."""
    if linktype == LINKTYPE_ETHERNET:
        if len(frame) < ETH_HEADER_LEN:
            return b""
        (ethertype,) = struct.unpack("!H", frame[12:14])
        if ethertype not in (ETHERTYPE_IPV4, ETHERTYPE_IPV6):
            return b""
        return frame[ETH_HEADER_LEN:]
    if linktype == LINKTYPE_NULL:
        return frame[4:]  # 4-byte BSD loopback address family
    return frame  # RAW: already an IP packet


# ---------- IP / transport ----------


def decode(ts: float, frame: bytes, linktype: int) -> Packet | None:
    packet = ip_payload(frame, linktype)
    if len(packet) < 20:
        return None
    version = packet[0] >> 4
    if version == 4:
        return _decode_v4(ts, packet)
    if version == 6:
        return _decode_v6(ts, packet)
    return None


def _decode_v4(ts: float, p: bytes) -> Packet | None:
    ihl = (p[0] & 0x0F) * 4
    if ihl < 20 or len(p) < ihl:
        return None
    proto = p[9]
    src = _ipv4(p[12:16])
    dst = _ipv4(p[16:20])
    total = struct.unpack("!H", p[2:4])[0] or len(p)
    return _decode_transport(ts, proto, src, dst, p[ihl:], total=total)


def _decode_v6(ts: float, p: bytes) -> Packet | None:
    if len(p) < 40:
        return None
    proto = p[6]
    src = _ipv6(p[8:24])
    dst = _ipv6(p[24:40])
    payload_len = struct.unpack("!H", p[4:6])[0]
    # Extension headers are not walked: only TCP/UDP directly after the fixed
    # header is decoded, which covers ordinary traffic.
    return _decode_transport(ts, proto, src, dst, p[40:], total=payload_len + 40)


def _decode_transport(
    ts: float, proto: int, src: str, dst: str, seg: bytes, *, total: int
) -> Packet | None:
    if proto == PROTO_TCP:
        if len(seg) < 20:
            return None
        sport, dport = struct.unpack("!HH", seg[:4])
        offset = (seg[12] >> 4) * 4
        payload = seg[offset:] if len(seg) >= offset else b""
        pkt = Packet(ts, "tcp", src, dst, sport, dport, total)
        host, status = parse_tls_sni(payload)
        if status is not None:
            pkt.hostname, pkt.sni_status = host, status
        return pkt

    if proto == PROTO_UDP:
        if len(seg) < 8:
            return None
        sport, dport = struct.unpack("!HH", seg[:4])
        pkt = Packet(ts, "udp", src, dst, sport, dport, total)
        if 53 in (sport, dport):
            name, answers = parse_dns(seg[8:])
            if name:
                pkt.hostname = name
            if answers:
                pkt.dns_answers = answers
        return pkt

    return None


def _ipv4(raw: bytes) -> str:
    return ".".join(str(b) for b in raw)


def _ipv6(raw: bytes) -> str:
    parts = [f"{struct.unpack('!H', raw[i : i + 2])[0]:x}" for i in range(0, 16, 2)]
    return ":".join(parts)


# ---------- DNS ----------


def parse_dns(payload: bytes) -> tuple[str | None, dict[str, list[str]]]:
    """Return (queried name, {name: [addresses]}) from a DNS message."""
    if len(payload) < 12:
        return None, {}
    qdcount, ancount = struct.unpack("!HH", payload[4:8])
    off = 12
    qname: str | None = None
    for i in range(qdcount):
        name, off = _read_name(payload, off)
        if off + 4 > len(payload):
            return qname, {}
        off += 4  # qtype + qclass
        if i == 0:
            qname = name
    answers: dict[str, list[str]] = {}
    for _ in range(ancount):
        name, off = _read_name(payload, off)
        if off + 10 > len(payload):
            break
        rtype, _rclass, _ttl, rdlen = struct.unpack("!HHIH", payload[off : off + 10])
        off += 10
        rdata = payload[off : off + rdlen]
        off += rdlen
        if rtype == 1 and rdlen == 4:  # A
            answers.setdefault(name, []).append(_ipv4(rdata))
        elif rtype == 28 and rdlen == 16:  # AAAA
            answers.setdefault(name, []).append(_ipv6(rdata))
    return qname, answers


def _read_name(payload: bytes, off: int, depth: int = 0) -> tuple[str, int]:
    """Read a DNS name, following compression pointers. Returns (name, next offset)."""
    labels: list[str] = []
    jumped = False
    end = off
    # A malformed message can point a compression offset back at itself; depth
    # caps the recursion rather than looping forever.
    while off < len(payload) and depth < 16:
        length = payload[off]
        if length == 0:
            off += 1
            if not jumped:
                end = off
            break
        if length & 0xC0 == 0xC0:  # pointer
            if off + 2 > len(payload):
                break
            (pointer,) = struct.unpack("!H", payload[off : off + 2])
            if not jumped:
                end = off + 2
            name, _ = _read_name(payload, pointer & 0x3FFF, depth + 1)
            labels.append(name)
            jumped = True
            break
        off += 1
        labels.append(payload[off : off + length].decode("ascii", errors="replace"))
        off += length
        if not jumped:
            end = off
    return ".".join(x for x in labels if x), end


# ---------- TLS ----------


def parse_tls_sni(payload: bytes) -> tuple[str | None, SniStatus | None]:
    """Extract the SNI hostname from a TLS ClientHello.

    Returns (hostname, status). status is None when this is not a ClientHello at
    all, so a plain data segment is distinguishable from a hello with no SNI.
    """
    if len(payload) < 6 or payload[0] != TLS_HANDSHAKE:
        return None, None
    # record: type(1) version(2) length(2) | handshake: type(1) length(3)
    if payload[5] != TLS_CLIENT_HELLO:
        return None, None
    try:
        return _client_hello_sni(payload)
    except (struct.error, IndexError):
        return None, "none"


def _client_hello_sni(p: bytes) -> tuple[str | None, SniStatus]:
    off = 9  # skip record header (5) + handshake type/length (4)
    off += 2 + 32  # client version + random
    session_len = p[off]
    off += 1 + session_len
    (cipher_len,) = struct.unpack("!H", p[off : off + 2])
    off += 2 + cipher_len
    comp_len = p[off]
    off += 1 + comp_len
    if off + 2 > len(p):
        return None, "none"
    (ext_total,) = struct.unpack("!H", p[off : off + 2])
    off += 2
    end = min(off + ext_total, len(p))

    hostname: str | None = None
    saw_ech = False
    while off + 4 <= end:
        ext_type, ext_len = struct.unpack("!HH", p[off : off + 4])
        off += 4
        body = p[off : off + ext_len]
        off += ext_len
        if ext_type == EXT_ECH:
            saw_ech = True
        elif ext_type == EXT_SERVER_NAME and len(body) >= 5:
            # server_name_list(2) | name_type(1) | length(2) | host
            (name_len,) = struct.unpack("!H", body[3:5])
            # Decoded as ASCII, deliberately NOT idna-decoded. SNI is punycode on
            # the wire, and leaving it that way is the honest form for a security
            # tool: "xn--80ak6aa92e.com" cannot be mistaken for "apple.com", while
            # its Unicode rendering can. (The idna codec also rejects
            # errors="replace", so decoding it defensively is not even possible.)
            hostname = body[5 : 5 + name_len].decode("ascii", errors="replace") or None

    if hostname:
        return hostname, "plain"
    if saw_ech:
        # The real hostname is inside the encrypted hello. Recording "ech" keeps
        # the blind spot visible instead of reporting the flow as hostname-less.
        return None, "ech"
    return None, "none"

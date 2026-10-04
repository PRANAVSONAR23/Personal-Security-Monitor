"""Packet decoders, flow aggregation, and the capture source's prerequisites.

The TLS fixtures are real ClientHellos produced by OpenSSL through a memory BIO,
not hand-written bytes — hand-written ones hid a defect (the `idna` codec rejects
errors="replace") that a real 1525-byte hello surfaced immediately.
"""

from __future__ import annotations

import contextlib
import ssl
import struct
import time

import pytest

from psm.core.models import Device, Flow
from psm.store.queries import insert_device, insert_flows, rollup_flows
from psm.streams.netflow.decode import (
    LINKTYPE_ETHERNET,
    LINKTYPE_RAW,
    DecodeError,
    decode,
    iter_pcap,
    parse_dns,
    parse_tls_sni,
)
from psm.streams.netflow.router import RouterSource, _drain
from psm.streams.netflow.writer import FlowAggregator

# ---------- real TLS ClientHello ----------


def _real_client_hello(hostname: str) -> bytes:
    ctx = ssl.create_default_context()
    inc, out = ssl.MemoryBIO(), ssl.MemoryBIO()
    obj = ctx.wrap_bio(inc, out, server_hostname=hostname)
    with contextlib.suppress(ssl.SSLWantReadError):
        obj.do_handshake()
    return out.read()


def test_sni_extracted_from_a_real_client_hello():
    host, status = parse_tls_sni(_real_client_hello("graph.facebook.com"))
    assert (host, status) == ("graph.facebook.com", "plain")


def test_idn_hostname_stays_punycode():
    """Punycode is the honest form for a security tool: "xn--80ak6aa92e.com"
    cannot be mistaken for "apple.com", while its Unicode rendering can."""
    host, status = parse_tls_sni(_real_client_hello("xn--80ak6aa92e.com"))
    assert host == "xn--80ak6aa92e.com"
    assert status == "plain"


def test_non_handshake_payload_is_not_a_client_hello():
    """status None distinguishes 'not a hello' from 'a hello with no SNI'."""
    assert parse_tls_sni(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n") == (None, None)
    assert parse_tls_sni(b"") == (None, None)


def test_truncated_client_hello_does_not_raise():
    assert parse_tls_sni(bytes([0x16, 0x03, 0x01, 0x00, 0x05, 0x01])) == (None, "none")


def test_ech_is_recorded_rather_than_reported_as_hostname_less():
    """An Encrypted ClientHello hides the name; saying so keeps the blind spot
    visible instead of silently producing an unattributed flow."""
    # record(5) + hs type/len(4) + version(2) + random(32) + session(1) +
    # ciphers(2+2) + comp(1+1) + extensions
    ext = struct.pack("!HH", 0xFE0D, 4) + b"\x00\x00\x00\x00"
    body = (
        b"\x03\x03"
        + b"\x00" * 32
        + b"\x00"
        + struct.pack("!H", 2)
        + b"\x13\x01"
        + b"\x01\x00"
        + struct.pack("!H", len(ext))
        + ext
    )
    hello = bytes([0x16, 0x03, 0x01]) + struct.pack("!H", len(body) + 4)
    hello += bytes([0x01]) + len(body).to_bytes(3, "big") + body
    assert parse_tls_sni(hello) == (None, "ech")


# ---------- DNS ----------


def _dns_query(name: str) -> bytes:
    out = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    for label in name.encode().split(b"."):
        out += bytes([len(label)]) + label
    return out + b"\x00" + struct.pack("!HH", 1, 1)


def _dns_response(name: str, addresses: list[str]) -> bytes:
    out = struct.pack("!HHHHHH", 0x1234, 0x8180, 1, len(addresses), 0, 0)
    qname = b"".join(bytes([len(x)]) + x for x in name.encode().split(b".")) + b"\x00"
    out += qname + struct.pack("!HH", 1, 1)
    for address in addresses:
        out += b"\xc0\x0c"  # pointer to the question name
        out += struct.pack("!HHIH", 1, 1, 300, 4)
        out += bytes(int(o) for o in address.split("."))
    return out


def test_dns_query_name_parsed():
    name, answers = parse_dns(_dns_query("graph.facebook.com"))
    assert name == "graph.facebook.com"
    assert answers == {}


def test_dns_answers_parsed_with_name_compression():
    name, answers = parse_dns(_dns_response("example.com", ["93.184.216.34", "1.2.3.4"]))
    assert name == "example.com"
    assert answers == {"example.com": ["93.184.216.34", "1.2.3.4"]}


def test_malformed_dns_does_not_raise():
    assert parse_dns(b"") == (None, {})
    assert parse_dns(b"\x00" * 12)[1] == {}
    # A compression pointer aimed at itself must terminate, not spin.
    assert parse_dns(struct.pack("!HHHHHH", 1, 0, 1, 0, 0, 0) + b"\xc0\x0c")[1] == {}


# ---------- pcap framing + IP ----------


def _pcap(frames: list[bytes], linktype: int = LINKTYPE_ETHERNET) -> bytes:
    out = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, linktype)
    for f in frames:
        out += struct.pack("<IIII", 1700000000, 0, len(f), len(f)) + f
    return out


def _ipv4_tcp(src: str, dst: str, sport: int, dport: int, payload: bytes = b"") -> bytes:
    tcp = struct.pack("!HHIIBBHHH", sport, dport, 0, 0, 5 << 4, 0x18, 0, 0, 0) + payload
    total = 20 + len(tcp)
    ip = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total,
        0,
        0,
        64,
        6,
        0,
        bytes(int(o) for o in src.split(".")),
        bytes(int(o) for o in dst.split(".")),
    )
    return b"\x00" * 12 + b"\x08\x00" + ip + tcp


def _ipv4_udp(src: str, dst: str, sport: int, dport: int, payload: bytes) -> bytes:
    udp = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
    total = 20 + len(udp)
    ip = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total,
        0,
        0,
        64,
        17,
        0,
        bytes(int(o) for o in src.split(".")),
        bytes(int(o) for o in dst.split(".")),
    )
    return b"\x00" * 12 + b"\x08\x00" + ip + udp


def test_pcap_header_and_records_parsed():
    linktype, records = _pcap_parse([_ipv4_tcp("10.0.0.2", "1.1.1.1", 50000, 443)])
    assert linktype == LINKTYPE_ETHERNET
    assert len(records) == 1


def _pcap_parse(frames):
    return iter_pcap(_pcap(frames))


def test_rejects_non_pcap_input():
    with pytest.raises(DecodeError):
        iter_pcap(b"not a pcap at all....")


def test_tcp_flow_decoded_from_ethernet():
    _, records = _pcap_parse([_ipv4_tcp("10.0.0.2", "1.1.1.1", 50000, 443)])
    pkt = decode(records[0][0], records[0][1], LINKTYPE_ETHERNET)
    assert pkt is not None
    assert (pkt.proto, pkt.src_ip, pkt.dst_ip, pkt.dst_port) == (
        "tcp",
        "10.0.0.2",
        "1.1.1.1",
        443,
    )


def test_raw_linktype_needs_no_ethernet_header():
    """The on-device VPN leg reads a TUN, which yields bare IP packets."""
    frame = _ipv4_tcp("10.0.0.2", "1.1.1.1", 50000, 443)[14:]
    pkt = decode(0.0, frame, LINKTYPE_RAW)
    assert pkt is not None and pkt.dst_port == 443


def test_sni_surfaces_through_the_full_decode_path():
    hello = _real_client_hello("graph.facebook.com")
    frame = _ipv4_tcp("10.0.0.2", "157.240.1.1", 50000, 443, hello)
    pkt = decode(0.0, frame, LINKTYPE_ETHERNET)
    assert pkt is not None
    assert pkt.hostname == "graph.facebook.com"
    assert pkt.sni_status == "plain"


def test_dns_surfaces_through_the_full_decode_path():
    frame = _ipv4_udp("10.0.0.2", "1.1.1.1", 50000, 53, _dns_query("example.com"))
    pkt = decode(0.0, frame, LINKTYPE_ETHERNET)
    assert pkt is not None and pkt.hostname == "example.com"


# ---------- aggregation ----------


def _agg() -> FlowAggregator:
    return FlowAggregator(device_id=1, leg="router", local_prefixes=("10.0.0.",))


def _pkt(frame: bytes):
    return decode(0.0, frame, LINKTYPE_ETHERNET)


def test_direction_resolved_from_local_prefix():
    a = _agg()
    a.add(_pkt(_ipv4_tcp("10.0.0.2", "1.1.1.1", 50000, 443)))
    a.add(_pkt(_ipv4_tcp("1.1.1.1", "10.0.0.2", 443, 50000)))
    (flow,) = a.drain()
    assert flow.dst_ip == "1.1.1.1", "the remote end is the destination either way"
    assert flow.bytes_out > 0 and flow.bytes_in > 0


def test_direction_falls_back_to_well_known_port():
    a = FlowAggregator(device_id=1, leg="router")  # no prefixes known
    a.add(_pkt(_ipv4_tcp("192.168.9.9", "1.1.1.1", 50000, 443)))
    (flow,) = a.drain()
    assert (flow.dst_ip, flow.dst_port) == ("1.1.1.1", 443)


def test_dns_answers_attribute_later_flows_to_a_hostname():
    a = _agg()
    a.add(
        _pkt(
            _ipv4_udp(
                "1.1.1.1", "10.0.0.2", 53, 50000, _dns_response("tracker.example", ["5.6.7.8"])
            )
        )
    )
    a.add(_pkt(_ipv4_tcp("10.0.0.2", "5.6.7.8", 50001, 443)))
    flows = {f.dst_ip: f for f in a.drain()}
    assert flows["5.6.7.8"].hostname == "tracker.example"


def test_sni_beats_the_dns_cache():
    """SNI is observed on the connection; the cache is an inference."""
    a = _agg()
    a.add(
        _pkt(
            _ipv4_udp("1.1.1.1", "10.0.0.2", 53, 50000, _dns_response("guess.example", ["9.9.9.9"]))
        )
    )
    hello = _real_client_hello("actual.example")
    a.add(_pkt(_ipv4_tcp("10.0.0.2", "9.9.9.9", 50001, 443, hello)))
    hosts = {f.hostname for f in a.drain() if f.dst_ip == "9.9.9.9"}
    assert hosts == {"actual.example"}


def test_packets_fold_into_one_row_per_endpoint():
    a = _agg()
    for _ in range(50):
        a.add(_pkt(_ipv4_tcp("10.0.0.2", "1.1.1.1", 50000, 443)))
    flows = a.drain()
    assert len(flows) == 1, "50 packets to one endpoint is one row, not 50"
    assert a.drain() == [], "drain resets"


def test_aggregator_throughput_meets_the_target():
    """Exit criterion: sustained >= 2k flows/s without drop."""
    a = _agg()
    frames = [_ipv4_tcp("10.0.0.2", f"1.1.1.{i % 250}", 50000 + i, 443) for i in range(4000)]
    packets = [_pkt(f) for f in frames]
    start = time.perf_counter()
    for p in packets:
        a.add(p)
    elapsed = time.perf_counter() - start
    rate = len(packets) / elapsed
    assert rate > 2000, f"only {rate:.0f} packets/s"
    assert sum(f.bytes_out for f in a.drain()) > 0


# ---------- incremental reader ----------


def test_partial_trailing_record_is_left_for_the_next_read():
    """A packet split across two socket reads must not be dropped."""
    full = _pcap([_ipv4_tcp("10.0.0.2", "1.1.1.1", 50000, 443)] * 3)
    cut = len(full) - 10
    consumed, packets = _drain(full[:cut], LINKTYPE_ETHERNET)
    assert len(packets) == 2
    rest = full[consumed:] + full[cut:]
    _, more = _drain(b"\x00" * 0 + rest, LINKTYPE_ETHERNET)
    assert len(more) == 1


# ---------- prerequisites ----------


def test_router_source_explains_why_it_cannot_run():
    ok, reason = RouterSource().available()
    assert ok is False
    assert reason, "an unavailable source must say why"


# ---------- storage + rollup ----------


def test_rollup_aggregates_an_hour(db):

    d = Device(name="phone", platform="android", identifier="x")
    insert_device(db, d)
    assert d.id is not None
    insert_flows(
        db,
        [
            Flow(
                device_id=d.id,
                ts="2026-10-04T12:00:00Z",
                leg="router",
                proto="tcp",
                dst_ip="1.1.1.1",
                dst_port=443,
                hostname="a.example",
                bytes_out=100,
                bytes_in=200,
            ),
            Flow(
                device_id=d.id,
                ts="2026-10-04T12:30:00Z",
                leg="router",
                proto="tcp",
                dst_ip="1.1.1.1",
                dst_port=443,
                hostname="a.example",
                bytes_out=50,
                bytes_in=25,
            ),
            Flow(
                device_id=d.id,
                ts="2026-10-04T13:00:00Z",
                leg="router",
                proto="tcp",
                dst_ip="1.1.1.1",
                dst_port=443,
                hostname="a.example",
                bytes_out=7,
                bytes_in=7,
            ),
        ],
    )
    rollup_flows(db, d.id, "2026-10-04T12")
    row = db.execute(
        "SELECT flow_count, bytes_out, bytes_in FROM flow_rollups WHERE hour='2026-10-04T12'"
    ).fetchone()
    assert (row["flow_count"], row["bytes_out"], row["bytes_in"]) == (2, 150, 225)


def test_rollup_is_idempotent(db):

    d = Device(name="phone", platform="android", identifier="x")
    insert_device(db, d)
    assert d.id is not None
    insert_flows(
        db,
        [
            Flow(
                device_id=d.id,
                ts="2026-10-04T12:00:00Z",
                leg="router",
                proto="tcp",
                dst_ip="1.1.1.1",
                dst_port=443,
                bytes_out=10,
                bytes_in=10,
            ),
        ],
    )
    rollup_flows(db, d.id, "2026-10-04T12")
    rollup_flows(db, d.id, "2026-10-04T12")
    n = db.execute("SELECT COUNT(*) c FROM flow_rollups").fetchone()["c"]
    assert n == 1, "re-rolling the same hour must not double-count"

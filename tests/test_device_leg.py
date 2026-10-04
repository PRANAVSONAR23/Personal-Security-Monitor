# ruff: noqa: E501 — /proc/net rows are long in the real format and the fixtures
# are only useful verbatim.
"""The /proc/net device leg and cross-leg correlation.

Fixtures are real rows copied off a POCO M2 Pro (SDK 31) — including the
closing-state rows whose UID the kernel has already dropped, which is what makes
naive parsing invent root activity.
"""

from __future__ import annotations

import ipaddress

import pytest

from psm.core.models import Device, Flow, InventoryItem, Snapshot
from psm.store.queries import insert_device, insert_flows, insert_snapshot
from psm.streams.netflow.correlate import correlate
from psm.streams.netflow.device import DeviceSource, to_flow, uid_to_package
from psm.streams.netflow.procnet import parse

TCP = """\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:C366 00000000:0000 8A 00000024:00000000 00:00000000 00000000  1001        0 39216 1 0
  41: 0601A8C0:90D6 902A9039:01BB 01 00000000:00000000 00:00000000 00000000 10645        0 47886619 1 0
  42: 0601A8C0:90D7 902A9039:01BB 04 00000000:00000000 00:00000000 00000000     0        0 47886620 1 0
  43: 0601A8C0:90D8 902A9039:01BB 09 00000000:00000000 00:00000000 00000000     0        0 47886621 1 0
"""

TCP6 = """\
  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   3: 0000000000000000FFFF00000601A8C0:9E02 0000000000000000FFFF0000655C9D14:1466 01 00000000:00000000 00:00000000 00000000 10107        0 123456 1 0
"""


def _shell(tables: dict[str, str]):
    def run(cmd: str) -> tuple[int, str, str]:
        for path, text in tables.items():
            if cmd.endswith(path):
                return (0, text, "")
        return (1, "", "no such file")

    return run


# ---------- address decoding ----------


def test_ipv4_little_endian_words():
    (_, sock) = (None, parse(TCP, "tcp")[1])
    assert sock.local_ip == "192.168.1.6"
    assert sock.remote_ip == "57.144.42.144"
    assert sock.remote_port == 443


def test_ipv4_mapped_ipv6_collapses_to_v4():
    sock = parse(TCP6, "tcp")[0]
    assert sock.local_ip == "192.168.1.6"
    assert sock.remote_ip == "20.157.92.101"
    assert sock.remote_port == 5222


def test_real_ipv6_round_trips():
    """Ground truth: the test device's own link-local address, re-encoded the way
    the kernel prints it (each 4-byte word little-endian)."""
    packed = ipaddress.IPv6Address("fe80::d80d:32ff:fe90:c0b8").packed
    kernel = "".join(packed[i : i + 4][::-1].hex().upper() for i in range(0, 16, 4))
    row = f"  1: {kernel}:1F90 {kernel}:01BB 01 0:0 0:0 0 10200 0 99 1 0\n"
    sock = parse("  sl  local_address\n" + row, "tcp")[0]
    assert sock.local_ip == "fe80::d80d:32ff:fe90:c0b8"


# ---------- state and attribution ----------


def test_listen_state_high_bit_is_masked():
    """This kernel reports listening sockets as 0x8A, not 0x0A. Treating 0x8A as
    unknown dropped 72 of 150 rows on the test device."""
    sock = parse(TCP, "tcp")[0]
    assert sock.state == "listen"
    assert sock.is_remote is False


def test_closing_sockets_are_not_attributable():
    """FIN_WAIT1 and LAST_ACK report uid 0 because the owner is gone. On the test
    device that was 57 of 78 remote sockets — emitting them would invent root
    activity."""
    socks = parse(TCP, "tcp")
    closing = [s for s in socks if s.state in ("fin-wait1", "last-ack")]
    assert len(closing) == 2
    assert all(s.uid == 0 for s in closing)
    assert all(not s.is_attributable for s in closing)


def test_established_socket_is_attributable():
    established = next(s for s in parse(TCP, "tcp") if s.state == "established")
    assert established.is_attributable
    assert established.uid == 10645


def test_udp_state_column_is_meaningless():
    socks = parse(TCP, "udp")
    assert all(s.state == "stateless" for s in socks)
    assert all(s.is_attributable for s in socks)


# ---------- source ----------


def test_source_emits_only_attributable_remote_sockets():
    src = DeviceSource(shell=_shell({"/proc/net/tcp": TCP, "/proc/net/tcp6": TCP6}))
    fresh = src.new_connections(src.poll())
    assert {s.uid for s in fresh} == {10645, 10107}
    assert src.skipped_unattributable == 2


def test_source_does_not_re_emit_the_same_socket():
    src = DeviceSource(shell=_shell({"/proc/net/tcp": TCP}))
    first = src.new_connections(src.poll())
    second = src.new_connections(src.poll())
    assert len(first) == 1
    assert second == [], "a socket already reported must not be reported again"


def test_controller_traffic_is_excluded():
    """Our own adb session is a socket on the phone and was 14 of 21 attributable
    connections — observer effect, not device behaviour."""
    src = DeviceSource(
        shell=_shell({"/proc/net/tcp": TCP}), exclude_ips=frozenset({"57.144.42.144"})
    )
    assert src.new_connections(src.poll()) == []


def test_unavailable_when_proc_net_is_unreadable():
    src = DeviceSource(shell=lambda cmd: (1, "", "Permission denied"))
    ok, why = src.available()
    assert ok is False
    assert "proc/net" in why


def test_reverse_dns_caches_negative_results():
    src = DeviceSource(shell=_shell({}), resolve_hostnames=True)
    src._rdns["203.0.113.1"] = None  # pre-seed a failure
    assert src.hostname("203.0.113.1") is None
    assert "203.0.113.1" in src._rdns


def test_reverse_dns_can_be_disabled():
    src = DeviceSource(shell=_shell({}), resolve_hostnames=False)
    assert src.hostname("8.8.8.8") is None


# ---------- uid mapping ----------


def test_uid_map_comes_from_the_application_inventory(db):

    d = Device(name="phone", platform="android", identifier="x")
    insert_device(db, d)
    assert d.id is not None
    snap = Snapshot(device_id=d.id, kind="baseline", capabilities={"application"}, tool_version="t")
    insert_snapshot(
        db,
        snap,
        [
            InventoryItem("application", "pkg:com.a", {"id": "com.a", "app_id": 10645}),
            InventoryItem("application", "pkg:com.b", {"id": "com.b", "app_id": 10107}),
        ],
    )
    assert uid_to_package(db, d.id) == {10645: "com.a", 10107: "com.b"}


def test_flow_carries_app_and_provenance():
    src = DeviceSource(shell=_shell({"/proc/net/tcp": TCP}), resolve_hostnames=False)
    sock = src.new_connections(src.poll())[0]
    flow = to_flow(src, sock, device_id=1, uid_map={10645: "com.instagram.android"})
    assert flow.app_pkg == "com.instagram.android"
    assert flow.app_uid == 10645
    assert flow.leg == "device"
    assert (flow.bytes_out, flow.bytes_in) == (0, 0), "this leg has no byte counts"
    assert flow.hostname_source is None


# ---------- correlation ----------


@pytest.fixture()
def phone(db):
    d = Device(name="phone", platform="android", identifier="x")
    insert_device(db, d)
    return d


def _flow(leg, ts, **kw):
    base = dict(
        device_id=1,
        ts=ts,
        leg=leg,
        proto="tcp",
        dst_ip="1.2.3.4",
        dst_port=443,
    )
    base.update(kw)
    return Flow(**base)  # type: ignore[arg-type]


def test_router_hostname_fills_a_device_flow(db, phone):
    insert_flows(
        db,
        [
            _flow("device", "2026-10-04T12:00:00Z", app_pkg="com.a", hostname=None),
            _flow("router", "2026-10-04T12:00:05Z", hostname="real.example", hostname_source="sni"),
        ],
    )
    result = correlate(db, 1)
    assert result.hostnames_filled == 1
    row = db.execute("SELECT hostname, hostname_source FROM flows WHERE leg='device'").fetchone()
    assert (row["hostname"], row["hostname_source"]) == ("real.example", "sni")


def test_rdns_guess_is_overwritten_by_an_observed_name(db, phone):
    insert_flows(
        db,
        [
            _flow(
                "device",
                "2026-10-04T12:00:00Z",
                app_pkg="com.a",
                hostname="junk-cdn.example",
                hostname_source="rdns",
            ),
            _flow("router", "2026-10-04T12:00:01Z", hostname="real.example", hostname_source="sni"),
        ],
    )
    correlate(db, 1)
    row = db.execute("SELECT hostname FROM flows WHERE leg='device'").fetchone()
    assert row["hostname"] == "real.example"


def test_device_app_fills_a_router_flow(db, phone):
    insert_flows(
        db,
        [
            _flow("device", "2026-10-04T12:00:00Z", app_pkg="com.a"),
            _flow("router", "2026-10-04T12:00:02Z", hostname="x.example", bytes_out=500),
        ],
    )
    result = correlate(db, 1)
    assert result.apps_filled == 1
    row = db.execute("SELECT app_pkg, bytes_out FROM flows WHERE leg='router'").fetchone()
    assert (row["app_pkg"], row["bytes_out"]) == ("com.a", 500)


def test_two_apps_to_one_address_is_left_ambiguous(db, phone):
    """A shared CDN address is genuinely ambiguous; guessing one app would be worse
    than leaving it unattributed."""
    insert_flows(
        db,
        [
            _flow("device", "2026-10-04T12:00:00Z", app_pkg="com.a"),
            _flow("device", "2026-10-04T12:00:01Z", app_pkg="com.b", src_port=2),
            _flow("router", "2026-10-04T12:00:02Z", hostname="cdn.example"),
        ],
    )
    result = correlate(db, 1)
    assert result.apps_filled == 0
    assert result.ambiguous == 1
    assert db.execute("SELECT app_pkg FROM flows WHERE leg='router'").fetchone()["app_pkg"] is None


def test_outside_the_window_does_not_join(db, phone):
    insert_flows(
        db,
        [
            _flow("device", "2026-10-04T12:00:00Z", app_pkg="com.a"),
            _flow("router", "2026-10-04T12:05:00Z", hostname="late.example"),
        ],
    )
    result = correlate(db, 1, window_s=30)
    assert (result.hostnames_filled, result.apps_filled) == (0, 0)


def test_different_destination_does_not_join(db, phone):
    insert_flows(
        db,
        [
            _flow("device", "2026-10-04T12:00:00Z", app_pkg="com.a", dst_ip="1.1.1.1"),
            _flow("router", "2026-10-04T12:00:01Z", dst_ip="9.9.9.9", hostname="other.example"),
        ],
    )
    result = correlate(db, 1)
    assert (result.hostnames_filled, result.apps_filled) == (0, 0)

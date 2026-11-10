import struct

import pytest

from active_checks import CheckError, heartbeat_request, validate_heartbeat_response, validate_request
from packet_observer import DecodeError, Window, decode_gtpu, parse_ss


def gtpu(flags, extension):
    return struct.pack("!BBHI", flags, 255, len(extension), 42) + extension


def test_qfi_extension_and_optional_quartet():
    pdu = decode_gtpu(gtpu(0x37, bytes.fromhex("0009078501108900") + b"payload"))
    assert (pdu.teid, pdu.sequence, pdu.npdu, pdu.qfi) == (42, 9, 7, 9)
    assert pdu.payload == b"payload"
    assert decode_gtpu(gtpu(0x32, bytes.fromhex("00090000") + b"payload")).qfi is None


@pytest.mark.parametrize("value", [bytes.fromhex("0000008500"), bytes.fromhex("0000008502850900")])
def test_malformed_extension_never_reads_qfi(value):
    with pytest.raises(DecodeError):
        decode_gtpu(gtpu(0x34, value))


def test_tcp_socket_rtt_and_unknown_retransmission():
    flows, evidence = parse_ss("ESTAB 0 0 192.0.2.1:100 192.0.2.2:80 sk:aa rtt:7.5/2\n",
                              b"k" * 32, "test-run", "source")
    assert flows[0]["rtt_seconds"] == .0075
    assert "retrans_total_snapshot" not in flows[0]
    assert evidence["retrans_missing"] == 1
    assert "192.0.2" not in str(flows)


def test_distinct_anchor_match_requires_same_scope_and_packet():
    window = Window(8, 3)
    for scope, source in [("a", "one"), ("b", "two"), ("a", "one")]:
        window.observe(dict(scope_id=scope, packet_id="packet", source_id=source), 1)
    assert window.report(2)["matched_identity_keys"] == 0
    window.observe(dict(scope_id="a", packet_id="packet", source_id="two"), 2)
    assert window.report(2)["matched_identity_keys"] == 1
    assert window.report(5)["matched_identity_keys"] == 0


def test_pfcp_heartbeat_validates_response_sequence_and_peer_scope():
    request = heartbeat_request(7, 100)
    response = request[:1] + b"\x02" + request[2:]
    assert validate_heartbeat_response(response, 7) == 100
    with pytest.raises(CheckError, match="sequence"):
        validate_heartbeat_response(response, 8)
    target = dict(host="192.0.2.1", port=8805, transport="pfcp_heartbeat",
                  addresses=["192.0.2.1"], isolated_test_peer=True, source_component="smf")
    with pytest.raises(CheckError, match="isolated"):
        validate_request(dict(target=target, allowlist=[target]))

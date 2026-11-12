import pytest

from packet_observer import capture_worker, parse_ss


def test_tcp_socket_rtt_and_unknown_retransmission():
    flows, evidence = parse_ss("ESTAB 0 0 192.0.2.1:100 192.0.2.2:80 sk:aa rtt:7.5/2\n",
                              b"k" * 32, "test-run", "source")
    assert flows[0]["rtt_seconds"] == .0075
    assert "retrans_total_snapshot" not in flows[0]
    assert evidence["retrans_missing"] == 1
    assert "192.0.2" not in str(flows)


def test_tcp_worker_reports_socket_snapshot(monkeypatch, capsys):
    import json
    import packet_observer

    def read_ss(argv, **kwargs):
        assert argv == ["ss", "-H", "-n", "-t", "-i", "-e", "-O"]
        return b"ESTAB 0 0 192.0.2.1:100 192.0.2.2:80 sk:aa rtt:7.5/2 retrans:0/2\n"

    def stop_after_snapshot(_):
        raise InterruptedError

    monkeypatch.setattr(packet_observer, "bounded_command", read_ss)
    monkeypatch.setattr(packet_observer.time, "sleep", stop_after_snapshot)
    with pytest.raises(InterruptedError):
        capture_worker(dict(tcp_flows=True, packet_identity_key="k" * 32,
                            packet_run_id="test", source="pod"))
    snapshot = json.loads(capsys.readouterr().out)
    assert snapshot["tcp_success"]
    assert snapshot["capability"] == {"tcp_flows": "available"}
    assert snapshot["flows"][0]["retrans_total_snapshot"] == 2
    assert "192.0.2" not in str(snapshot)

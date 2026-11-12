"""Portable offline checks; no Kubernetes, BPF attachment or production traffic."""

import importlib.util
import sys
from pathlib import Path
from xml.etree.ElementTree import fromstring

sys.path.insert(0, str(Path(__file__).parent))
from prometheus_client.core import CounterMetricFamily, GaugeMetricFamily
from node_probe import NodeCollector, collect_qdisc_metrics, pod_processes, sched_snapshot
from packet_observer import PortableTcpFlows
from split_observer import procedures


def test_node_diagnostics_starts_with_tcp_flows_enabled(monkeypatch):
    monkeypatch.setenv("NODE_NAME", "test-node")
    monkeypatch.setenv("NADOR_PACKET_IDENTITY_KEY", "a" * 32)
    collector = NodeCollector({
        "tcp_flows": True, "packet_run_id": "test", "split_signaling": False,
        "off_cpu": False, "attributed_drops": False, "kernel_drops": False,
    })
    assert isinstance(collector.tcp_flows, PortableTcpFlows)


def test_qdisc_drops_preserve_zero_and_do_not_invent_missing_counters():
    backlog = GaugeMetricFamily("backlog", "backlog", labels=["interface", "handle"])
    drops = CounterMetricFamily("drops", "drops", labels=["interface", "handle"])
    collect_qdisc_metrics([
        {"dev": "eth0", "handle": "10:", "backlog": 64584, "drops": 32243},
        {"dev": "eth1", "handle": "0:", "backlog": 0, "drops": 0},
        {"dev": "eth2", "handle": "0:", "backlog": 0},
    ], [], backlog, drops)
    assert [sample.value for sample in backlog.samples] == [64584, 0, 0]
    assert [(sample.labels["interface"], sample.value) for sample in drops.samples] == [
        ("eth0", 32243), ("eth1", 0),
    ]
def test_schedstat_all_threads(tmp_path):
    process = tmp_path / "123"
    for tid, values in (("123", "1000000000 2000000000 3"), ("124", "2000000000 4000000000 5")):
        path = process / "task" / tid
        path.mkdir(parents=True)
        (path / "schedstat").write_text(values)
    assert sched_snapshot(process) == (3.0, 6.0, 8, 2)


def test_cgroup_v2_uid(tmp_path):
    uid = "aa-bb"
    path = tmp_path / "123"
    path.mkdir()
    (path / "cgroup").write_text("0::/kubepods.slice/kubepods-burstable-podaa_bb.slice/cri-containerd-ab.scope")
    assert [(key, proc.name) for key, proc in pod_processes(tmp_path, {uid})] == [(uid, "123")]
    assert list(pod_processes(tmp_path, {"different"})) == []


def test_pdml_multiple_pdus_do_not_get_flattened():
    packet = fromstring('<packet><proto name="f1ap"><field name="f1ap.procedureCode" show="5"/></proto><proto name="e1ap"><field name="e1ap.procedureCode" show="8"/></proto></packet>')
    assert list(procedures(packet)) == [("f1ap", "5"), ("e1ap", "8")]


def test_invalid_procedure_and_other_protocol_are_ignored():
    packet = fromstring('<packet><proto name="ngap"><field name="ngap.procedureCode" show="2"/></proto><proto name="f1ap"><field name="f1ap.procedureCode" show="invalid"/></proto></packet>')
    assert list(procedures(packet)) == []

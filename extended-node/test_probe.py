"""Portable offline checks; no Kubernetes, BPF attachment or production traffic."""

import importlib.util
import sys
from pathlib import Path
from xml.etree.ElementTree import fromstring

sys.path.insert(0, str(Path(__file__).parent))
from node_probe import pod_processes, sched_snapshot
from split_observer import procedures


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

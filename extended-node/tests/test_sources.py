import ctypes as ct
import importlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from nador_kernel import AttributedDrops, KernelSources, OffCPU
from nador_kernel.offcpu import classify_state, state_masks
from nador_kernel.procfs import discover_tasks, namespace_index, task_stat
from .fakes import FakeBPF, Identity, Interval, StackKey, Total

SWITCH_FORMAT = '''field:pid_t prev_pid; offset:0; size:4; signed:1;
field:long prev_state; offset:8; size:8; signed:1;
print fmt: __print_flags(REC->prev_state & (256 - 1), "|",
 { 1, "S" }, { 2, "D" }, { 4, "T" }, { 8, "t" },
 { 16, "X" }, { 32, "Z" }, { 64, "P" }, { 128, "I" }),
 REC->prev_state & 256 ? "+" : ""
'''
DROP_FORMAT = 'field:void * skbaddr; offset:8;\nfield:enum skb_drop_reason reason; offset:24;'
PODS = {"a": ("ns", "pod-a", "amf"), "b": ("ns", "pod-b", "upf")}


def write_stat(path, pid, start, state="S"):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"{pid} (worker (tricky) name) {state} " + "0 " * 18 + f"{start} 0 0\n")


class Fixture(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.proc = self.root / "proc"
        self.trace = self.root / "trace"
        for event, fmt in (("sched/sched_switch", SWITCH_FORMAT),
                           ("sched/sched_process_exit", "field:pid_t pid;"),
                           ("skb/kfree_skb", DROP_FORMAT)):
            path = self.trace / "events" / event / "format"
            path.parent.mkdir(parents=True)
            path.write_text(fmt)
        self.host = self.root / "host-net"
        self.host.touch()
        (self.proc / "1/ns").mkdir(parents=True)
        (self.proc / "1/ns/net").symlink_to(self.host)

    def namespace(self, name):
        path = self.root / name
        path.touch()
        return path

    def process(self, pid=10, start=100, namespace=None, threads=()):
        path = self.proc / str(pid)
        write_stat(path / "stat", pid, start)
        write_stat(path / "task" / str(pid) / "stat", pid, start)
        for tid, ticks in threads:
            write_stat(path / "task" / str(tid) / "stat", tid, ticks)
        ns = path / "ns/net"
        ns.parent.mkdir(parents=True, exist_ok=True)
        if ns.is_symlink():
            ns.unlink()
        ns.symlink_to(namespace or self.namespace(f"net-{pid}"))
        return path

    def offcpu(self, **kwargs):
        obj = OffCPU(True, bpf_factory=FakeBPF, tracefs_root=self.trace, clock_ticks=100, **kwargs)
        self.addCleanup(obj.close)
        return obj

    def drops(self, **kwargs):
        obj = AttributedDrops(True, bpf_factory=FakeBPF, tracefs_root=self.trace, **kwargs)
        self.addCleanup(obj.close)
        return obj


class CapabilityTests(Fixture):
    def test_disabled_imports_without_bcc_or_side_effects(self):
        factory = Mock(side_effect=AssertionError("must not load BCC"))
        for cls in (OffCPU, AttributedDrops):
            obj = cls(bpf_factory=factory)
            self.assertEqual(obj.snapshot()["status"]["state"], "disabled")
        factory.assert_not_called()
        result = subprocess.run(
            [sys.executable, "-B", "-c", "import nador_kernel, sys; assert 'bcc' not in sys.modules"],
            capture_output=True, text=True, check=False,
            cwd=Path(__file__).resolve().parents[1])
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_disabled_adapters_do_not_discover_proc(self):
        sources = KernelSources({})
        with patch("nador_kernel.offcpu.discover_tasks", side_effect=AssertionError):
            sources.reconcile([], {}, "/not/proc", "node")
        self.assertFalse(sources.snapshot()["off_cpu"]["status"]["available"])

    def test_armed_is_not_success_or_zero(self):
        obj = self.offcpu()
        obj.reconcile([("a", self.process())], PODS, self.proc, "n")
        snap = obj.snapshot()
        self.assertEqual(snap["status"]["state"], "armed_unobserved")
        self.assertFalse(snap["status"]["available"])
        self.assertIsNone(snap["tasks"][0]["runnable_ns"])
        self.assertIsNone(snap["tasks"][0]["completed_intervals"])

    def test_attach_failure_and_missing_attachment_are_evidenced(self):
        failure = Mock(side_effect=PermissionError("denied"))
        obj = OffCPU(True, bpf_factory=failure, tracefs_root=self.trace)
        self.assertEqual(obj.snapshot()["status"]["state"], "unavailable")
        self.assertIn("denied", str(obj.snapshot()["status"]["errors"]))
        bpf = FakeBPF(text="")
        bpf.tracepoint_fds.pop(b"sched:sched_process_exit")
        obj = OffCPU(True, bpf_factory=lambda **_: bpf, tracefs_root=self.trace)
        self.assertIsNone(obj.bpf)
        self.assertTrue(bpf.cleaned)

    def test_missing_formats_and_unknown_masks_do_not_load(self):
        factory = Mock()
        path = self.trace / "events/sched/sched_switch/format"
        path.write_text("no interpretable mask")
        obj = OffCPU(True, bpf_factory=factory, tracefs_root=self.trace)
        self.assertEqual(obj.snapshot()["status"]["state"], "unavailable")
        factory.assert_not_called()
        obj = AttributedDrops(True, bpf_factory=factory, tracefs_root=self.root / "missing")
        self.assertFalse(obj.snapshot()["status"]["available"])
        factory.assert_not_called()

    def test_old_drop_tracepoint_is_not_silently_supported(self):
        path = self.trace / "events/skb/kfree_skb/format"
        path.write_text("field:void * skbaddr;")
        factory = Mock()
        obj = AttributedDrops(True, bpf_factory=factory, tracefs_root=self.trace)
        self.assertIn("requires", str(obj.snapshot()["status"]["errors"]))
        factory.assert_not_called()

    def test_invalid_capacities_and_clock_ticks(self):
        for value in (0, -1, 65537, True, "4096", 1.5):
            with self.assertRaises(ValueError):
                OffCPU(max_targets=value)
            with self.assertRaises(ValueError):
                AttributedDrops(max_keys=value)
        factory = Mock()
        obj = OffCPU(True, clock_ticks=3, bpf_factory=factory, tracefs_root=self.trace)
        self.assertEqual(obj.snapshot()["status"]["state"], "unavailable")
        factory.assert_not_called()

    def test_close_clears_success(self):
        obj = self.offcpu()
        bpf = obj.bpf
        bpf.diag(0, 10)
        self.assertTrue(obj.snapshot()["status"]["available"])
        obj.close()
        self.assertTrue(bpf.cleaned)
        self.assertEqual(obj.snapshot()["status"]["state"], "closed")
        self.assertFalse(obj.snapshot()["status"]["available"])


class SchedulerTests(Fixture):
    def test_masks_and_classification(self):
        preempt, blocked = state_masks(SWITCH_FORMAT)
        self.assertEqual((preempt, blocked), (256, 255))
        for state in (0, 256):
            self.assertEqual(classify_state(state, preempt, blocked), "runnable")
        for state in (1, 2, 4, 8, 128):
            self.assertEqual(classify_state(state, preempt, blocked), "blocked")
        for state in (-1, 512, 257):
            self.assertEqual(classify_state(state, preempt, blocked), "unknown")
        alternate = SWITCH_FORMAT.replace("256", "0x800")
        self.assertEqual(state_masks(alternate)[0], 2048)
        with self.assertRaises(ValueError):
            state_masks(SWITCH_FORMAT.replace("& 256 ?", "& 255 ?"))

    def test_all_threads_targeted_and_starttime_parsed(self):
        path = self.process(threads=((11, 101), (12, 102)))
        self.assertEqual(task_stat(path / "stat"), (10, "S", 100))
        obj = self.offcpu()
        obj.reconcile([("a", path)], PODS, self.proc, "n")
        table = obj.bpf["targets"]
        self.assertEqual(len(table.items()), 3)
        self.assertEqual(table[table.Key(11)].tgid, 10)
        self.assertEqual(table[table.Key(11)].start_ticks, 101)
        generation = obj.targets[11][3]
        obj.reconcile([("a", path)], PODS, self.proc, "n")
        self.assertEqual(obj.targets[11][3], generation)

    def test_unknown_vs_observed_zero_and_counters(self):
        obj = self.offcpu()
        obj.reconcile([("a", self.process())], PODS, self.proc, "n")
        obj.bpf.diag(0, 20)
        self.assertIsNone(obj.snapshot()["tasks"][0]["blocked_ns"])
        gen = obj.targets[10][3]
        table = obj.bpf["totals"]
        table[Identity(10, gen)] = Total(500, 0, 70, 3)
        task = obj.snapshot()["tasks"][0]
        self.assertEqual(task["runnable_ns"], 500)
        self.assertEqual(task["blocked_ns"], 0)
        self.assertEqual(task["unknown_ns"], 70)
        self.assertEqual(task["completed_intervals"], 3)

    def test_reuse_owner_change_and_removal_clear_all_generation_state(self):
        obj = self.offcpu(off_cpu_stacks=True)
        path = self.process()
        obj.reconcile([("a", path)], PODS, self.proc, "n")
        old = obj.targets[10][3]
        for name in ("starts", "pending"):
            obj.bpf[name][Identity(10, old)] = Interval(100, 10**9, 1, 7)
        obj.bpf["totals"][Identity(10, old)] = Total(0, 100, 0, 1)
        obj.bpf["exited"][Identity(10, old)] = ct.c_ubyte(1)
        obj.bpf["blocked_stacks"][StackKey(10, old, 7)] = ct.c_ulonglong(1)
        self.process(start=200)
        obj.reconcile([("a", path)], PODS, self.proc, "n")
        new = obj.targets[10][3]
        self.assertGreater(new, old)
        for name in ("starts", "pending", "totals", "exited", "blocked_stacks"):
            self.assertEqual(obj.bpf[name].items(), [])
        obj.reconcile([("b", path)], PODS, self.proc, "n")
        self.assertGreater(obj.targets[10][3], new)
        obj.reconcile([], PODS, self.proc, "n")
        self.assertEqual(obj.targets, {})
        self.assertEqual(obj.bpf["targets"].items(), [])

    def test_exit_tombstone_is_not_rearmed_in_same_generation(self):
        obj = self.offcpu()
        path = self.process()
        obj.reconcile([("a", path)], PODS, self.proc, "n")
        gen = obj.targets[10][3]
        obj.bpf["exited"][Identity(10, gen)] = ct.c_ubyte(1)
        obj.reconcile([("a", path)], PODS, self.proc, "n")
        self.assertEqual(obj.targets[10][3], gen)
        self.assertEqual(obj.bpf["exited"][Identity(10, gen)].value, 1)

    def test_late_old_generation_entries_pruned(self):
        obj = self.offcpu()
        path = self.process()
        obj.reconcile([("a", path)], PODS, self.proc, "n")
        obj.bpf["totals"][Identity(10, 99999)] = Total(100, 100, 0, 2)
        obj.reconcile([("a", path)], PODS, self.proc, "n")
        self.assertEqual(obj.bpf["totals"].items(), [])

    def test_discovery_is_bounded_and_failure_revokes_target(self):
        path = self.process(threads=((11, 101), (12, 102)))
        obj = self.offcpu(max_targets=2)
        discovery = obj.reconcile([("a", path)], PODS, self.proc, "n")
        self.assertEqual(len(obj.targets), 2)
        self.assertFalse(discovery["complete"])
        self.assertEqual(discovery["omitted_threads"], 1)
        (path / "stat").unlink()
        obj.reconcile([("a", path)], PODS, self.proc, "n")
        self.assertEqual(obj.targets, {})

    def test_map_update_failure_detaches_and_read_failure_is_unknown(self):
        obj = self.offcpu()
        obj.bpf["targets"].fail_write = True
        bpf = obj.bpf
        obj.reconcile([("a", self.process())], PODS, self.proc, "n")
        self.assertTrue(bpf.cleaned)
        self.assertFalse(obj.snapshot()["status"]["available"])
        obj = self.offcpu()
        obj.reconcile([("a", self.proc / "10")], PODS, self.proc, "n")
        obj.bpf.diag(0, 1)
        obj.bpf["totals"].fail_read = True
        snap = obj.snapshot()
        self.assertEqual(snap["status"]["state"], "read_error")
        self.assertIsNone(snap["tasks"][0]["runnable_ns"])

    def test_map_loss_evidence_and_undecoded_bounded_stacks(self):
        obj = self.offcpu(off_cpu_stacks=True, max_stacks=32, max_stack_keys=64)
        obj.reconcile([("a", self.process())], PODS, self.proc, "n")
        gen = obj.targets[10][3]
        obj.bpf.diag(0, 2)
        obj.bpf.diag(1, 1)
        obj.bpf["blocked_stacks"][StackKey(10, gen, 5)] = ct.c_ulonglong(12)
        snap = obj.snapshot()
        self.assertEqual(snap["status"]["state"], "degraded")
        self.assertFalse(snap["status"]["complete"])
        self.assertEqual(snap["blocked_stacks"][0]["samples"], 12)
        self.assertEqual(snap["blocked_stacks"][0]["stack_id"], 5)
        self.assertFalse(snap["stack_sampling"]["decoded"])
        self.assertEqual(snap["stack_sampling"]["max_stacks"], 32)
        self.assertNotIn("address", json.dumps(snap))
        obj.bpf.diag(7, 3)
        self.assertEqual(obj.snapshot()["status"]["diagnostics"]["stack_errors"], 3)


class DropTests(Fixture):
    def test_stat_inode_is_used_not_symlink_text(self):
        net = self.namespace("actual-net")
        path = self.process(namespace=net)
        with patch("nador_kernel.procfs.os.stat", wraps=__import__("os").stat) as stat:
            index = namespace_index([("a", path)], PODS, self.proc)
        self.assertEqual(index["owners"][net.stat().st_ino], ("a",))
        stat.assert_any_call(path / "ns/net")

    def test_initial_history_unattributed_then_stable_window_unique(self):
        net = self.namespace("unique-net")
        obj = self.drops()
        obj.reconcile([("a", self.process(namespace=net))], PODS, self.proc, "n")
        inode = net.stat().st_ino
        obj.bpf.drop(inode, 2, 99999, 5)
        first = obj.snapshot()["records"][0]
        self.assertEqual(first["ownership_reason"], "no_window_baseline")
        self.assertIsNone(first["uid"])
        obj.bpf.drop(inode, 2, 99999, 8)
        record = obj.snapshot()["records"][0]
        self.assertEqual(record["raw_count"], 8)
        self.assertEqual(record["window_count"], 3)
        self.assertEqual(record["reason_code"], 99999)
        self.assertEqual(record["ownership"], "unique_in_inventory")
        self.assertEqual(record["uid"], "a")

    def test_shared_namespace_and_host_namespace_are_ambiguous(self):
        net = self.namespace("shared-net")
        processes = [("a", self.process(10, namespace=net)),
                     ("b", self.process(20, namespace=net))]
        obj = self.drops()
        obj.reconcile(processes, PODS, self.proc, "n")
        obj.bpf.drop(net.stat().st_ino, 2, 4, 1)
        obj.snapshot()
        record = obj.snapshot()["records"][0]
        self.assertEqual(record["ownership"], "ambiguous")
        self.assertEqual(record["candidate_uids"], ["a", "b"])
        self.assertIsNone(record["uid"])
        obj.reconcile([("a", self.process(30, namespace=self.host))], PODS, self.proc, "n")
        obj.bpf.drop(self.host.stat().st_ino, 4, 5, 1)
        records = obj.snapshot()["records"]
        host = next(r for r in records if r["netns_inode"] == self.host.stat().st_ino)
        self.assertEqual(host["ownership_reason"], "host_namespace")
        self.assertIsNone(host["uid"])

    def test_threads_and_processes_in_same_pod_are_not_multiple_owners(self):
        net = self.namespace("pod-net")
        index = namespace_index([("a", self.process(10, namespace=net)),
                                 ("a", self.process(20, namespace=net))], PODS, self.proc)
        self.assertEqual(index["owners"][net.stat().st_ino], ("a",))

    def test_ownership_change_and_return_within_window_not_uniquely_assigned(self):
        net = self.namespace("churn-net")
        path = self.process(namespace=net)
        obj = self.drops()
        obj.reconcile([("a", path)], PODS, self.proc, "n")
        obj.snapshot()
        obj.reconcile([("b", path)], PODS, self.proc, "n")
        obj.reconcile([("a", path)], PODS, self.proc, "n")
        obj.bpf.drop(net.stat().st_ino, 2, 3, 4)
        record = obj.snapshot()["records"][0]
        self.assertEqual(record["ownership_reason"], "ownership_changed")
        self.assertIsNone(record["uid"])

    def test_missing_device_namespace_ifindex_and_read_errors_are_separate(self):
        obj = self.drops()
        for location in range(1, 6):
            obj.bpf.drop(0, 0, 7, location, location)
        records = obj.snapshot()["records"]
        self.assertEqual(len(records), 5)
        self.assertEqual({r["location"] for r in records}, {
            "missing_skb", "missing_dev", "missing_ifindex", "missing_netns", "read_error"})
        self.assertTrue(all(r["ownership"] == "unattributed" and r["uid"] is None for r in records))
        self.assertTrue(all(r["netns_inode"] is None for r in records))

    def test_partial_discovery_no_false_unique_and_unknown_namespace(self):
        net = self.namespace("partial-net")
        path = self.process(namespace=net)
        obj = self.drops()
        obj.reconcile([("a", path), ("b", self.proc / "999")], PODS, self.proc, "n")
        obj.snapshot()
        obj.bpf.drop(net.stat().st_ino, 2, 8, 3)
        record = obj.snapshot()["records"][0]
        self.assertEqual(record["ownership_reason"], "incomplete_discovery")
        self.assertIsNone(record["uid"])
        obj.reconcile([("a", path)], PODS, self.proc, "n")
        obj.snapshot()
        obj.bpf.drop(123456, 2, 8, 1)
        record = next(r for r in obj.snapshot()["records"] if r["netns_inode"] == 123456)
        self.assertEqual(record["ownership_reason"], "namespace_not_in_inventory")

    def test_snapshot_read_failure_has_no_zero_records_and_preserves_evidence(self):
        obj = self.drops()
        obj.bpf.drop(1000, 2, 4, 7)
        obj.bpf["counts"].fail_read = True
        snap = obj.snapshot()
        self.assertEqual(snap["records"], [])
        self.assertFalse(snap["status"]["available"])
        self.assertEqual(snap["status"]["state"], "read_error")
        self.assertIn("snapshot", str(snap["status"]["errors"]))

    def test_zero_events_not_false_success_and_overflow_visible(self):
        obj = self.drops()
        self.assertEqual(obj.snapshot()["status"]["state"], "armed_unobserved")
        obj.bpf.diag(0, 10)
        obj.bpf.diag(1, 10)
        snap = obj.snapshot()
        self.assertEqual(snap["status"]["state"], "degraded")
        self.assertFalse(snap["status"]["complete"])
        self.assertEqual(snap["status"]["diagnostics"]["map_failures"], 10)


class IntegrationAndSourceTests(Fixture):
    def test_switches_and_legacy_policy_even_on_load_failure(self):
        for selected in (True, False):
            sources = KernelSources({"off_cpu": True, "off_cpu_stacks": True,
                                     "attributed_drops": selected, "kernel_drops": True},
                                    offcpu_options={"bpf_factory": FakeBPF, "tracefs_root": self.trace},
                                    drop_options={"tracefs_root": self.root / "missing"})
            self.addCleanup(sources.close)
            self.assertEqual(sources.use_legacy_drop_reasons, not selected)
            self.assertTrue(sources.offcpu.stack_sampling)
            path = self.process()
            sources.reconcile(iter([("a", path)]), PODS, self.proc, "node")
            self.assertEqual(sources.snapshot()["off_cpu"]["node"], "node")

    def test_json_serializable_snapshots(self):
        obj = self.drops()
        obj.reconcile([("a", self.process())], PODS, self.proc, "n")
        json.dumps(obj.snapshot())
        obj = self.offcpu()
        obj.reconcile([("a", self.proc / "10")], PODS, self.proc, "n")
        json.dumps(obj.snapshot())

    def test_generated_source_contracts_not_kernel_validation(self):
        scheduler = self.offcpu(off_cpu_stacks=True, max_targets=17)
        source = scheduler.bpf.text
        self.assertNotIn("@", source)
        self.assertIn("#if TASK_REPORT_MAX != 256", source)
        self.assertIn("bpf_ktime_get_ns()", source)
        self.assertIn("&task->start_boottime", source)
        self.assertIn("saved.cookie != cookie", source)
        self.assertIn("TRACEPOINT_PROBE(sched, sched_process_exit)", source)
        self.assertIn("exited.update(&key, &one)", source)
        self.assertIn("BPF_HASH(targets, u32, struct target, 17)", source)
        self.assertIn("stacks.get_stackid(args, 0)", source)
        self.assertNotIn("BPF_F_REUSE_STACKID", source)
        self.assertNotIn("BPF_F_USER_STACK", source)
        drop_source = self.drops().bpf.text
        for field in ("&skb->dev", "&dev->ifindex", "&dev->nd_net.net", "&net->ns.inum"):
            self.assertIn("bpf_probe_read_kernel", drop_source)
            self.assertIn(field, drop_source)
        self.assertNotIn("bpf_get_current_pid_tgid", drop_source)
        self.assertNotIn("bpf_get_current_task", drop_source)
        self.assertNotIn("511", drop_source)


if __name__ == "__main__":
    unittest.main()

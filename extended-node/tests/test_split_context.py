import copy
from dataclasses import FrozenInstanceError
import math
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from split_context import ID_FIELDS, SETUPS, SplitContextTracker
from .fixture_factory import field, packet, pdu
from .probe_tshark import write_probe

FIXTURES = Path(__file__).parent / "fixtures"
SCOPE = "node-A:pod-uid:anchor-A:generation-1"


class TrackerTests(unittest.TestCase):
    def setUp(self):
        self.tracker = SplitContextTracker()

    def send(self, now=0, *, tracker=None, scope=SCOPE, protocol="f1ap", code=5,
             kind="initiatingMessage", ids=(7,), tx=None, cgis=(), capture_time="auto", **transport):
        if capture_time == "auto":
            capture_time = 1000 + now
        result = (tracker or self.tracker).consume(
            packet(pdu(protocol, code, kind, ids, tx, cgis), capture_time=capture_time, **transport), now, scope)
        self.assertEqual(len(result), 1)
        return result[0]

    def complete(self, now=1, **kwargs):
        return self.send(now, kind="successfulOutcome", ids=(7, 9), reverse=True, **kwargs)

    def test_all_configured_setups_success_and_failure(self):
        for (protocol, code), mode in SETUPS.items():
            for outcome in ("successfulOutcome", "unsuccessfulOutcome"):
                with self.subTest(protocol=protocol, code=code, outcome=outcome):
                    tracker = SplitContextTracker()
                    args = dict(tracker=tracker, protocol=protocol, code=code,
                                ids=(7,) if mode == "ue" else (), tx=4 if mode == "transaction" else None)
                    self.assertEqual(self.send(10, **args).status, "pending")
                    args["ids"] = (7, 9) if mode == "ue" and outcome == "successfulOutcome" else args["ids"]
                    result = self.send(12, kind=outcome, reverse=True, **args)
                    self.assertEqual(result.status, "matched")
                    self.assertEqual(result.duration_seconds, 2)
                    self.assertEqual(result.timestamp_basis, "capture")
                    self.assertEqual(tracker.snapshot()["timings"][(protocol, code, outcome, "capture")], (1, 2))

    def test_missing_assoc_is_explicit_even_with_endpoints(self):
        result = self.send(assoc=None)
        self.assertEqual(result.reason, "missing_assoc_index")
        self.assertFalse(result.local_ids)
        self.assertFalse(self.tracker.snapshot()["contexts"])

    def test_missing_ids_do_not_borrow_from_other_pdu_or_packet(self):
        pkt = packet(pdu(ids=()), pdu(ids=(99,)))
        field(pkt, "f1ap.GNB_CU_UE_F1AP_ID", 666)
        results = self.tracker.consume(pkt, 0, SCOPE)
        self.assertEqual(results[0].reason, "missing_primary_ue_id")
        self.assertEqual(results[1].local_ids, ((ID_FIELDS["f1ap"][0], 99),))
        self.assertEqual(self.tracker.snapshot()["pending"], 1)

    def test_wrong_spelling_and_nested_reference_ids_not_accepted(self):
        for name in ("f1ap.gNB_CU_UE_F1AP_ID", "f1ap.GNB_CU_UE_F1AP_ID"):
            pkt = packet(pdu(ids=()))
            value = field(pkt.find("proto[@name='f1ap']"), "f1ap.nested_reference")
            field(value, name, 7)
            result = self.tracker.consume(pkt, 0, SCOPE)[0]
            self.assertEqual(result.reason, "missing_primary_ue_id")

    def test_repeated_ids_even_equal_are_ambiguous(self):
        for second in (7, 8):
            pkt = packet(pdu())
            value = pkt.find(".//field[@name='f1ap.value_element']")
            field(value, "f1ap.GNB_CU_UE_F1AP_ID", second)
            self.assertEqual(self.tracker.consume(pkt, 0, SCOPE)[0].reason, "ambiguous_identifiers")

    def test_duplicate_start_preserves_first_capture_timestamp(self):
        self.send(1, capture_time=100)
        self.assertEqual(self.send(3, capture_time=100).status, "duplicate")
        result = self.complete(5, capture_time=102)
        self.assertEqual(result.duration_seconds, 2)
        self.assertEqual(self.complete(6, capture_time=102).status, "suppressed")
        self.assertEqual(sum(n for n, _ in self.tracker.snapshot()["timings"].values()), 1)

    def test_duplicate_does_not_extend_pending_ttl(self):
        tracker = SplitContextTracker(pending_ttl=5)
        self.send(0, tracker=tracker)
        self.send(4, tracker=tracker)
        self.assertEqual(self.complete(5, tracker=tracker).status, "suppressed")
        self.assertEqual(tracker.snapshot()["pending"], 0)
        self.assertFalse(tracker.snapshot()["timings"])

    def test_conflicting_initiation_poisoned_not_overwritten(self):
        self.send(1)
        result = self.send(2, cgis=(("00f110", "0000000010"),))
        self.assertEqual(result.reason, "conflicting_initiation")
        self.assertEqual(self.complete(3).status, "suppressed")
        self.assertFalse(self.tracker.snapshot()["timings"])

    def test_wrong_direction_does_not_match(self):
        self.send()
        result = self.send(1, kind="successfulOutcome", ids=(7, 9))
        self.assertEqual(result.reason, "unmatched_outcome")
        self.assertEqual(self.complete(2).status, "matched")

    def test_wrong_procedure_transaction_or_primary_does_not_match(self):
        self.send(code=1, tx=3, ids=())
        for now, code, tx in ((1, 1, 4), (2, 3, 3)):
            result = self.send(now, protocol="f1ap", code=code, tx=tx, ids=(), kind="successfulOutcome", reverse=True)
            self.assertNotEqual(result.status, "matched")
        self.assertEqual(self.send(3, code=1, tx=3, ids=(), kind="successfulOutcome", reverse=True).status, "matched")

    def test_response_without_peer_id_is_not_safe_success(self):
        self.send()
        self.assertEqual(self.send(1, kind="successfulOutcome", reverse=True).reason, "success_requires_both_ids")

    def test_conflicting_peer_ids_poison_pending(self):
        self.send(ids=(7, 8))
        self.assertEqual(self.complete().reason, "conflicting_outcome_ids")
        self.assertEqual(self.complete(2).status, "suppressed")

    def test_multiple_associations_reusing_ids_fixture(self):
        packets = ET.parse(FIXTURES / "association_reuse.pdml").getroot().findall("packet")
        for index, pkt in enumerate(packets):
            frame = ET.SubElement(pkt, "proto", name="frame")
            field(frame, "frame.time_epoch", 1000 + index)
        results = [self.tracker.consume(pkt, index, SCOPE)[0] for index, pkt in enumerate(packets)]
        self.assertEqual([r.status for r in results], ["pending", "pending", "matched"])
        self.assertEqual(results[-1].duration_seconds, 1)
        self.assertEqual(self.tracker.snapshot()["pending"], 1)
        self.assertEqual(len(self.tracker.snapshot()["associations"]), 2)

    def test_same_assoc_index_different_endpoint_tuple_stays_separate(self):
        self.send(0)
        self.send(1, endpoints=("192.0.2.3", "192.0.2.4"))
        self.assertEqual(self.complete(3).duration_seconds, 3)
        self.assertEqual(self.tracker.snapshot()["pending"], 1)

    def test_same_addresses_different_ports_stay_separate(self):
        self.send(0, ports=(38472, 10000))
        self.send(1, ports=(38472, 10001))
        self.assertEqual(self.complete(2, ports=(38472, 10001)).duration_seconds, 1)
        self.assertEqual(self.tracker.snapshot()["pending"], 1)

    def test_capture_anchors_and_generations_never_match(self):
        for different_scope in ("node-A:pod-uid:anchor-B:generation-1", "node-A:pod-uid:anchor-A:generation-2"):
            tracker = SplitContextTracker()
            self.send(tracker=tracker)
            self.assertEqual(self.complete(tracker=tracker, scope=different_scope).reason, "unmatched_outcome")
            self.assertEqual(tracker.snapshot()["pending"], 1)

    def test_no_cross_protocol_match(self):
        self.send()
        self.assertEqual(self.complete(protocol="e1ap", code=8).reason, "unmatched_outcome")
        self.assertEqual(self.tracker.snapshot()["pending"], 1)

    def test_assoc_index_restart_clears_previous_context(self):
        self.send()
        result = self.complete(assoc=2)
        self.assertEqual(result.reason, "unmatched_outcome")
        snap = self.tracker.snapshot()
        self.assertEqual(snap["pending"], 0)
        self.assertTrue(all(a.assoc_index == 2 for a in snap["associations"]))

    def test_verification_tags_are_directional_and_change_invalidates(self):
        self.send(0)
        self.complete(1)
        self.send(2, ids=(20,))
        self.assertEqual(self.send(3, ids=(20, 21), kind="successfulOutcome", reverse=True, tag="0x33333333").reason, "unmatched_outcome")
        self.assertEqual(self.tracker.snapshot()["pending"], 0)

    def test_init_restart_control_without_ap_pdu_invalidates(self):
        self.send()
        result = self.tracker.consume(packet(chunks=(1,), tag=0, init="0x1234", capture_time=1001), 1, SCOPE)
        self.assertEqual(result, ())
        self.assertEqual(self.tracker.snapshot()["pending"], 0)
        self.assertEqual(self.complete(2).reason, "unmatched_outcome")

    def test_init_retransmission_does_not_clear_new_pending(self):
        init = packet(chunks=(1,), tag=0, init="0x1234", capture_time=1000)
        self.tracker.consume(init, 0, SCOPE)
        self.send(1)
        self.tracker.consume(init, 2, SCOPE)
        self.assertEqual(self.complete(3).status, "matched")

    def test_sctp_close_invalidates(self):
        for chunk in (6, 7, 8, 14):
            tracker = SplitContextTracker()
            self.send(tracker=tracker)
            tracker.consume(packet(chunks=(chunk,), capture_time=1001), 1, SCOPE)
            self.assertFalse(tracker.snapshot()["contexts"])
            self.assertEqual(self.complete(2, tracker=tracker).reason, "unmatched_outcome")

    def test_missing_or_zero_verification_tag_untrackable(self):
        pkt = packet(pdu())
        parent = pkt.find("proto[@name='sctp']")
        parent.remove(parent.find("field[@name='sctp.verification_tag']"))
        self.assertEqual(self.tracker.consume(pkt, 0, SCOPE)[0].reason, "missing_verification_tag")
        self.assertEqual(self.send(1, tag=0).reason, "zero_verification_tag")

    def test_release_clears_only_matching_protocol_association_ids(self):
        self.send(ids=(7, 9))
        self.send(1, ids=(20, 21))
        self.send(2, protocol="e1ap", code=8, ids=(7, 9))
        self.assertEqual(self.send(3, code=6, ids=(7, 9)).status, "released")
        contexts = self.tracker.snapshot()["contexts"]
        self.assertEqual(len(contexts), 2)
        self.assertEqual(self.complete(4).reason, "released_ids")
        self.assertEqual(len(self.tracker.snapshot()["contexts"]), 2)

    def test_release_missing_id_is_not_wildcard(self):
        self.send()
        self.assertEqual(self.send(1, code=6).reason, "release_requires_both_ids")
        self.assertEqual(self.tracker.snapshot()["pending"], 1)

    def test_e1_release(self):
        self.send(protocol="e1ap", code=8)
        self.assertEqual(self.send(1, protocol="e1ap", code=11, ids=(7, 9)).status, "released")
        self.assertEqual(self.tracker.snapshot()["pending"], 0)

    def test_protocol_reset_and_interface_release_invalidate(self):
        for code in (0, 26):
            tracker = SplitContextTracker()
            self.send(tracker=tracker)
            self.assertEqual(self.send(1, tracker=tracker, code=code, ids=()).status, "invalidated")
            self.assertFalse(tracker.snapshot()["contexts"])
            self.assertEqual(self.complete(2, tracker=tracker).status, "suppressed")

    def test_bundle_fixture_does_not_flatten_identifiers_or_cgis(self):
        pkt = ET.parse(FIXTURES / "bundle.pdml").getroot().find("packet")
        frame = ET.SubElement(pkt, "proto", name="frame")
        field(frame, "frame.time_epoch", 1000)
        results = self.tracker.consume(pkt, 0, SCOPE)
        self.assertEqual([r.local_ids[0][1] for r in results], [10, 20, 30])
        self.assertEqual([len(r.cgis) for r in results], [1, 0, 0])
        self.assertEqual(self.tracker.snapshot()["pending"], 3)

    def test_cgis_do_not_cartesian_join_or_carry_forward(self):
        result = self.send(code=11, cgis=(("00f110", "0000000010"), ("00f120", "0000000020")))
        self.assertEqual([(f.plmn_hex, f.cell_hex) for f in result.cgis],
                         [("00f110", "0000000010"), ("00f120", "0000000020")])
        self.assertFalse(self.send(1, code=11).cgis)
        self.assertFalse(self.tracker.snapshot()["contexts"][0].cgis)

    def test_orphan_or_invalid_cgi_not_exposed(self):
        pkt = packet(pdu(code=11))
        wrapper = pkt.find(".//field[@name='f1ap.initiatingMessage_element']")
        field(wrapper, "f1ap.pLMN_Identity", value="00f110")
        nested = field(wrapper, "f1ap.other")
        field(nested, "f1ap.nRCellIdentity", value="0000000010")
        self.assertFalse(self.tracker.consume(pkt, 0, SCOPE)[0].cgis)
        self.assertFalse(self.send(1, code=11, cgis=(("bogus", "0000000010"),)).cgis)

    def test_cgis_on_e1_and_no_imsi_rnti_join(self):
        result = self.send(protocol="e1ap", code=8, cgis=(("00f110", "0000000010"),))
        self.assertEqual(result.cgis[0].cell_field, "e1ap.nR_Cell_Identity")
        self.assertEqual(result.local_ids, (("GNB_CU_CP_UE_E1AP_ID", 7),))
        self.assertNotIn("imsi", repr(self.tracker.snapshot()).lower())

    def test_timeout_and_idle_scrape_expiry(self):
        tracker = SplitContextTracker(pending_ttl=2, context_ttl=3, association_ttl=10)
        self.send(tracker=tracker)
        snap = tracker.snapshot(3)
        self.assertEqual(snap["pending"], 0)
        self.assertEqual(snap["contexts"], ())
        self.assertFalse(tracker.snapshot(10)["associations"])

    def test_scope_teardown(self):
        self.send()
        self.tracker.reset_scope(SCOPE)
        self.assertFalse(self.tracker.snapshot()["contexts"])
        self.assertFalse(self.tracker.snapshot()["associations"])

    def test_timing_only_configured_reviewed_procedures(self):
        tracker = SplitContextTracker(setup_procedures=())
        self.assertEqual(self.send(tracker=tracker).reason, "timing_not_configured")
        self.assertFalse(tracker.snapshot()["pending"])
        self.send(1, code=7)
        self.assertFalse(self.tracker.snapshot()["timings"])
        with self.assertRaises(ValueError):
            SplitContextTracker(setup_procedures=(("f1ap", 7),))

    def test_capture_time_not_parser_latency(self):
        self.send(1, capture_time=100.0)
        result = self.complete(20, capture_time=100.125)
        self.assertEqual(result.duration_seconds, .125)
        self.assertEqual(result.packet_time, 100.125)

    def test_missing_capture_time_default_has_no_processing_fallback(self):
        result = self.send(capture_time=None)
        self.assertEqual(result.reason, "missing_or_ambiguous_capture_time")
        self.assertFalse(self.tracker.snapshot()["pending"])
        self.assertIsNone(result.duration_seconds)

    def test_bad_capture_timestamps(self):
        for value in ("NaN", "inf", "-1.0", "1e3", "", "1.2garbage"):
            with self.subTest(value=value):
                tracker = SplitContextTracker()
                self.assertEqual(self.send(tracker=tracker, capture_time=value).reason, "invalid_capture_time")

    def test_duplicate_capture_timestamp_field_rejected(self):
        pkt = packet(pdu())
        field(pkt.find("proto[@name='frame']"), "frame.time_epoch", 1000)
        self.assertEqual(self.tracker.consume(pkt, 0, SCOPE)[0].reason, "missing_or_ambiguous_capture_time")

    def test_backward_capture_time_does_not_emit_duration(self):
        self.send(capture_time=1000)
        self.assertEqual(self.complete(1, capture_time=999).reason, "capture_time_regression")
        self.assertFalse(self.tracker.snapshot()["timings"])
        self.assertEqual(self.tracker.snapshot()["pending"], 0)

    def test_observation_clock_regression_is_rejected(self):
        self.send(10)
        self.assertEqual(self.complete(9).reason, "time_regression")
        self.assertFalse(self.tracker.snapshot()["timings"])
        with self.assertRaises(ValueError):
            self.tracker.snapshot(9)

    def test_explicit_processing_basis_is_labeled(self):
        tracker = SplitContextTracker(timestamp_basis="processing")
        self.send(0, tracker=tracker, capture_time=None)
        result = self.complete(1, tracker=tracker, capture_time=None)
        self.assertEqual(result.duration_seconds, 1)
        self.assertEqual(result.timestamp_basis, "processing")
        self.assertIn(("f1ap", 5, "successfulOutcome", "processing"), tracker.snapshot()["timings"])

    def test_bounded_pending_context_association_and_guards(self):
        tracker = SplitContextTracker(max_pending=1, max_contexts=1, max_associations=1, max_quarantine=2)
        self.send(tracker=tracker)
        self.assertEqual(self.send(1, tracker=tracker, ids=(8,)).reason, "pending_capacity")
        self.assertEqual(self.send(2, tracker=tracker, endpoints=("192.0.2.3", "192.0.2.4")).reason, "association_capacity")
        snap = tracker.snapshot()
        self.assertLessEqual(snap["pending"], 1)
        self.assertLessEqual(len(snap["contexts"]), 1)
        self.assertLessEqual(len(snap["associations"]), 1)
        self.assertLessEqual(snap["quarantine"] + snap["release_guards"], 2)

    def test_quarantine_overflow_fails_closed(self):
        tracker = SplitContextTracker(max_quarantine=1)
        self.send(tracker=tracker)
        self.complete(1, tracker=tracker)
        self.send(2, tracker=tracker, ids=(20,))
        self.send(3, tracker=tracker, ids=(20, 21), kind="successfulOutcome", reverse=True)
        self.assertGreater(tracker.snapshot()["timing_disabled_until"], 3)
        self.assertEqual(self.send(4, tracker=tracker, ids=(30,)).reason, "timing_capacity_quarantine")

    def test_configuration_validation(self):
        for kwargs in ({"pending_ttl": 0}, {"context_ttl": math.inf}, {"max_pending": 0},
                       {"max_contexts": True}, {"timestamp_basis": "rtt"}):
            with self.assertRaises(ValueError):
                SplitContextTracker(**kwargs)
        for now in (math.nan, math.inf, "0", True):
            with self.assertRaises(ValueError):
                self.tracker.consume(packet(pdu()), now, SCOPE)

    def test_malformed_and_nested_wrappers_not_flattened(self):
        pkt = packet(pdu())
        ET.SubElement(pkt, "proto", name="_ws.malformed")
        self.assertEqual(self.tracker.consume(pkt, 0, SCOPE)[0].reason, "malformed_pdu")
        pkt = packet(pdu())
        wrapper = pkt.find(".//field[@name='f1ap.initiatingMessage_element']")
        wrapper.append(pdu().find(".//field[@name='f1ap.initiatingMessage_element']"))
        self.assertEqual(self.tracker.consume(pkt, 0, SCOPE)[0].reason, "nested_pdu_wrappers")

    def test_missing_wrapper_is_not_procedure_count_session(self):
        proto = ET.Element("proto", name="f1ap")
        field(proto, "f1ap.procedureCode", 5)
        self.assertEqual(self.tracker.consume(packet(proto), 0, SCOPE)[0].reason, "missing_pdu_wrapper")

    def test_ipv6_canonicalization(self):
        self.send(ipv6=True, endpoints=("2001:db8::1", "2001:db8::2"))
        result = self.complete(1, ipv6=True, endpoints=("2001:0db8:0:0:0:0:0:1", "2001:db8::2"))
        self.assertEqual(result.status, "matched")

    def test_snapshot_is_detached_and_observations_immutable(self):
        self.send()
        snap = self.tracker.snapshot()
        snap["counters"].clear()
        self.assertTrue(self.tracker.snapshot()["counters"])
        with self.assertRaises(FrozenInstanceError):
            snap["contexts"][0].status = "modified"

    def test_cgi_capacity_no_partial_context(self):
        tracker = SplitContextTracker(max_cgis_per_pdu=1)
        result = self.send(tracker=tracker, cgis=(("00f110", "0000000010"), ("00f120", "0000000020")))
        self.assertEqual(result.reason, "cgi_capacity")
        self.assertFalse(tracker.snapshot()["contexts"])

    def test_prometheus_real_registry_and_detached_generator(self):
        try:
            from prometheus_client import CollectorRegistry, generate_latest
        except ImportError:
            self.skipTest("optional prometheus_client unavailable")
        self.send()
        self.complete()
        families = tuple(self.tracker.collect(("node", "pod"), ("node-A", "pod-A"), observation_time=2))
        class Collector:
            def collect(self):
                yield from families
        registry = CollectorRegistry()
        registry.register(Collector())
        rendered = generate_latest(registry).decode()
        self.assertIn('timestamp_basis="capture"', rendered)
        self.assertIn("nador_split_setup_observation_seconds_count", rendered)
        self.assertIn("nador_split_context_events_total", rendered)
        self.assertNotIn("192.0.2", rendered)
        self.assertNotIn(SCOPE, rendered)
        self.assertNotIn("GNB_CU_UE_F1AP_ID", rendered)
        with self.assertRaises(ValueError):
            self.tracker.collect(("timestamp_basis",), ("x",))


@unittest.skipUnless(shutil.which("tshark"), "optional tshark unavailable")
class TsharkShapeTests(unittest.TestCase):
    def test_real_decoder_fields_all_setup_pdu_kinds(self):
        with tempfile.TemporaryDirectory(prefix="split-offline-") as directory:
            root = write_probe(directory)
        packets = root.findall("packet")
        self.assertEqual(len(packets), 15)
        groups = [("f1ap", 1), ("e1ap", 3), ("e1ap", 4), ("f1ap", 5), ("e1ap", 8)]
        for group, (protocol, code) in enumerate(groups):
            subset = packets[group * 3:group * 3 + 3]
            with self.subTest(protocol=protocol, code=code):
                tracker = SplitContextTracker()
                first = tracker.consume(subset[0], 0, SCOPE)[0]
                second = tracker.consume(subset[1], 10, SCOPE)[0]
                self.assertEqual((first.status, second.status), ("pending", "matched"))
                self.assertEqual(second.duration_seconds, 1)
                tracker = SplitContextTracker()
                tracker.consume(subset[0], 0, SCOPE)
                failed = tracker.consume(subset[2], 20, SCOPE)[0]
                self.assertEqual(failed.status, "matched")
                self.assertEqual(failed.kind, "unsuccessfulOutcome")
                self.assertEqual(failed.duration_seconds, 2)
                if code == 5:
                    self.assertEqual(first.cgis[0].cell_hex, "0000000010")
                if SETUPS[(protocol, code)] == "ue":
                    self.assertEqual(second.local_ids, tuple(zip(ID_FIELDS[protocol], (7, 9))))


if __name__ == "__main__":
    unittest.main()

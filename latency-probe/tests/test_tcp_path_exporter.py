import unittest
from unittest.mock import patch

import exporter


class TcpPathMetrics(unittest.TestCase):
    def test_recent_history_evictions_are_exported_separately(self):
        exporter.observe_tcp_corr_stats_event({"mode": "core", "repeat_history_evicted_count": 0})
        exporter.observe_tcp_corr_stats_event({"mode": "core", "repeat_history_evicted_count": 3})
        samples = exporter.tcp_repeat_history_evictions_total.collect()[0].samples
        total = next(sample for sample in samples if sample.name.endswith("_total"))
        self.assertEqual(total.value, 3)
        self.assertEqual(total.labels["mode"], "core")

    def test_variation_histogram_exports_seconds_without_flow_labels(self):
        with patch.object(exporter, "TEID_UE_MAP", {
            "192.0.2.3|0x0000002b": {"imsi": "003", "slice_id": "01:000003"},
        }):
            event = dict(teid="0x0000002b", outer_dst_ip="192.0.2.3", direction="downlink")
            for delta in (4000000, 3000000, 0, -1):
                exporter.observe_tcp_rtt_variation(dict(event, variation_ns=delta))
        samples = exporter.tcp_rtt_variation_seconds.collect()[0].samples
        count = next(sample for sample in samples if sample.name.endswith("_count"))
        total = next(sample for sample in samples if sample.name.endswith("_sum"))
        self.assertEqual(count.value, 3)
        self.assertAlmostEqual(total.value, 0.007)
        self.assertEqual(count.labels["direction"], "downlink")
        self.assertEqual(count.labels["slice"], "01:000003")
        self.assertNotIn("flow_id", count.labels)

    def test_signals_resolve_teid_in_the_receiving_endpoint_scope(self):
        mapping = {
            "192.0.2.1|0x0000002a": {"imsi": "001", "slice_id": "01:000001"},
            "192.0.2.2|0x0000002a": {"imsi": "002", "slice_id": "01:000002"},
        }
        signals = (
            ("retransmission_candidate", exporter.tcp_retransmission_candidates_total),
            ("reset", exporter.tcp_resets_observed_total),
        )
        with patch.object(exporter, "TEID_UE_MAP", mapping):
            for signal, counter in signals:
                exporter.observe_tcp_path_signal(dict(
                    teid="0x0000002a", outer_dst_ip="192.0.2.2",
                    signal=signal, direction="uplink",
                ))
                samples = [sample for sample in counter.collect()[0].samples
                           if sample.name.endswith("_total")]
                self.assertEqual(len(samples), 1)
                self.assertEqual(samples[0].value, 1)
                self.assertEqual(samples[0].labels["imsi"], "002")
                self.assertEqual(samples[0].labels["slice"], "01:000002")
                self.assertEqual(samples[0].labels["direction"], "uplink")


if __name__ == "__main__":
    unittest.main()

import queue
import unittest

from oneway import NS, TTL, Pairer, clock_interval, slice_inventory
from upf_transit import Transit

TUNNEL = "0a000001:0000002a"


class UpfTransitTests(unittest.TestCase):
    def test_both_directions_with_n3_slice_only(self):
        for proto, transport in ((6, "tcp"), (17, "udp")):
            for uplink, direction in ((1, "uplink"), (0, "downlink")):
                collector = Transit()
                collector.slices = {TUNNEL: "01:ffffff"}
                n3 = (NS if uplink else NS + 200_000, 1, 2, bytes.fromhex("0a000001"), 42, proto, uplink, 0)
                n6 = (NS + 200_000 if uplink else NS, 1, 2, bytes(4), 0, proto, uplink, 1)
                for event in (n6, n3):
                    collector.observe(event, 2 * NS)
                collector.flush(2 * NS + TTL)
                self.assertEqual(collector.slice_total[transport, direction, "01:ffffff"], .0002)

    def test_repeated_fingerprint_is_not_guessed(self):
        collector = Transit()
        n3 = (NS, 1, 2, bytes.fromhex("0a000001"), 42, 17, 1, 0)
        n6 = (NS + 10, 1, 2, bytes(4), 0, 17, 1, 1)
        for event in (n3, n6, n3):
            collector.observe(event, 2 * NS)
        collector.flush(2 * NS + TTL)
        self.assertEqual(collector.events[("udp", "uplink"), "ambiguous"], 1)
        self.assertFalse(collector.slice_hist)


class OneWayTests(unittest.TestCase):
    def test_sample_log_uses_uncertainty_from_each_pair(self):
        samples = queue.Queue(maxsize=1)
        pair = Pairer(2_000_000, samples)
        pair.slices = {TUNNEL: "01:ffffff"}
        for identity in ("a"*32, "b"*32):
            pair.ingest("upf", [(identity, "udp", "downlink", NS, 350_000, TUNNEL)], 2*NS)
            pair.ingest("gnb", [(identity, "udp", "downlink", NS+10_000_000, 470_000, TUNNEL)], 2*NS)
        pair.flush(2*NS+TTL)
        self.assertEqual(samples.get_nowait(), {
            "event": "nador_n3_oneway_sample",
            "protocol": "udp",
            "direction": "downlink",
            "slice": "01:ffffff",
            "receive_timestamp_ns": NS + 10_000_000,
            "delay_ns": 10_000_000,
            "clock_uncertainty_ns": 820_000,
            "gnb_clock_uncertainty_ns": 470_000,
            "upf_clock_uncertainty_ns": 350_000,
        })
        self.assertEqual(pair.hist["udp", "downlink"][-1], 2)
        self.assertIn(b"nador_n3_oneway_sample_log_dropped_total 1", pair.render())

    def test_clock_bracket_does_not_assume_symmetric_delay(self):
        self.assertEqual(clock_interval(0, 110, 120, 30), (90, 110))
        with self.assertRaises(ValueError):
            clock_interval(0, 110, 200, 30)

    def test_uplink_udp_and_downlink_tcp(self):
        for protocol, direction, roles in (
            ("udp", "uplink", ("gnb", "upf")), ("tcp", "downlink", ("upf", "gnb")),
        ):
            pair = Pairer(2_000_000)
            for i, role in enumerate(roles):
                pair.ingest(role, [("a"*32, protocol, direction, NS+i*10_000_000, 1000, TUNNEL)], 2*NS)
            pair.flush(2*NS+TTL)
            self.assertEqual(pair.events[(protocol, direction), "matched"], 1)
            self.assertAlmostEqual(pair.total[protocol, direction], .01)
            self.assertIn(b"nador_n3_oneway_seconds_bucket", pair.render())

    def test_ambiguous_stale_and_uncertain_are_not_samples(self):
        pair = Pairer(2_000_000)
        row = ("a"*32, "udp", "uplink", NS, 1_100_000, TUNNEL)
        pair.ingest("gnb", [row, row, ("b"*32, *row[1:]), ("c"*32, "udp", "uplink", -4*NS, 0, TUNNEL)], 2*NS)
        pair.ingest("upf", [row, ("b"*32, *row[1:])], 2*NS)
        pair.flush(2*NS+TTL)
        labels = ("udp", "uplink")
        self.assertEqual(pair.events[labels, "ambiguous"], 1)
        self.assertEqual(pair.events[labels, "invalid_clock"], 1)
        self.assertEqual(pair.events[labels, "uncertain_pair"], 1)
        self.assertEqual(pair.hist[labels][-1], 0)

    def test_endpoint_scoping_and_conflicts(self):
        row = {"slice_id": "01:ffffff", "ul_teid": "0x2a", "upf_n3_ip": "10.0.0.1"}
        other = dict(row, slice_id="02:000001", upf_n3_ip="10.0.0.2")
        self.assertEqual(slice_inventory([row, other]), {TUNNEL: "01:ffffff", "0a000002:0000002a": "02:000001"})
        self.assertEqual(slice_inventory([row, dict(row, slice_id="02:000001")])[TUNNEL], "unknown")

    def test_per_slice_and_released_mapping(self):
        for released in (False, True):
            pair = Pairer(2_000_000)
            pair.slices = {TUNNEL: "01:ffffff"}
            row = ("a"*32, "udp", "uplink", NS, 0, TUNNEL)
            pair.ingest("gnb", [row], 2*NS)
            pair.ingest("upf", [row], 2*NS)
            if released:
                pair.slices.clear()
            pair.flush(2*NS+TTL)
            label = "unknown" if released else "01:ffffff"
            self.assertIn(f'slice="{label}"'.encode(), pair.render())
            self.assertEqual(pair.slice_hist["udp", "uplink", label][-1], 1)

    def test_identical_fingerprints_do_not_pair_across_tunnels(self):
        pair = Pairer(2_000_000)
        row = ("a"*32, "udp", "uplink", NS, 0, TUNNEL)
        pair.ingest("gnb", [row], 2*NS)
        pair.ingest("upf", [(*row[:-1], "0a000002:0000002a")], 2*NS)
        pair.flush(2*NS+TTL)
        self.assertEqual(pair.events[("udp", "uplink"), "unmatched"], 2)

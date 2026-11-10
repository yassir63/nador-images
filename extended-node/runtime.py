"""Poll independently of Prometheus scrapes and expose snapshot age."""

import logging
import threading
import time

from prometheus_client.core import GaugeMetricFamily


class CachedCollector:
    def __init__(self, collector, interval):
        self.collector = collector
        self.interval = interval
        self.lock = threading.Lock()
        self.snapshot = []
        self.updated = 0
        self.ok = 0
        threading.Thread(target=self.poll, daemon=True).start()

    def poll(self):
        while True:
            try:
                snapshot = list(self.collector.collect())
                with self.lock:
                    self.snapshot, self.updated, self.ok = snapshot, time.time(), 1
            except Exception:
                logging.exception("Collector polling failed")
                with self.lock:
                    self.ok = 0
            time.sleep(self.interval)

    def collect(self):
        with self.lock:
            snapshot, updated, ok = self.snapshot, self.updated, self.ok
        success = GaugeMetricFamily("nador_extended_poll_success", "Last polling attempt completed", value=ok)
        timestamp = GaugeMetricFamily("nador_extended_snapshot_timestamp_seconds", "Last complete collector snapshot", value=updated)
        yield success
        yield timestamp
        # Expire stale native samples, but preserve the health metadata.
        if time.time() - updated <= max(30, self.interval * 3):
            yield from snapshot

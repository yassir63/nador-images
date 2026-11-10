"""Bounded passive F1AP/E1AP message evidence. No inferred subscriber joins."""

import logging
import subprocess
import threading
import time
import xml.etree.ElementTree as ET
import uuid
from collections import Counter

from prometheus_client.core import GaugeMetricFamily
from split_context import SplitContextTracker

LOG = logging.getLogger("nador-split-signaling")


def procedures(packet):
    """One observation per decoded protocol PDU, including bundled SCTP PDUs."""
    for proto in packet.iter("proto"):
        protocol = proto.get("name")
        if protocol not in {"f1ap", "e1ap"}:
            continue
        fields = list(proto.iter("field"))
        codes = [f.get("show") for f in fields if f.get("name") == protocol + ".procedureCode"]
        for code in codes:
            if code and code.isdigit() and 0 <= int(code) <= 255:
                yield protocol, code


class Worker:
    def __init__(self, pid, identity):
        self.pid, self.identity = pid, identity
        self.process = None
        self.lock = threading.Lock()
        self.counts = Counter()
        self.last = 0
        self.error = 0
        self.tracker = SplitContextTracker()
        self.stopped = threading.Event()
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    def run(self):
        while not self.stopped.is_set():
            scope = uuid.uuid4().hex
            try:
                self.process = subprocess.Popen(
                    ["nsenter", "-t", self.pid, "-n", "tshark", "-n", "-i", "any",
                     "-f", "sctp", "-Y", "f1ap || e1ap", "-l", "-T", "pdml"],
                    stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, bufsize=0,
                )
                root = None
                for event, element in ET.iterparse(self.process.stdout, events=("start", "end")):
                    if root is None:
                        root = element
                    if event == "end" and element.tag == "packet":
                        with self.lock:
                            self.tracker.consume(element, time.monotonic(), scope)
                            for protocol, code in procedures(element):
                                self.counts[(protocol, code)] += 1
                                self.last = time.time()
                        root.clear()
                with self.lock:
                    self.error += 1
            except (OSError, ET.ParseError):
                with self.lock:
                    self.error += 1
            finally:
                with self.lock:
                    self.tracker.reset_scope(scope)
                if self.process:
                    self.process.terminate()
                    try:
                        self.process.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        self.process.kill()
                        self.process.wait()
            self.stopped.wait(2)

    def stop(self):
        self.stopped.set()
        if self.process:
            self.process.terminate()
        self.thread.join(timeout=3)


class SplitCapture:
    def __init__(self, limit):
        self.workers = {}
        self.limit = limit
        self.omitted = 0

    def reconcile(self, active):
        # All selected pods are scoped independently. Portability needs netns access.
        for uid in list(self.workers):
            if uid not in active or self.workers[uid].pid != active[uid][0]:
                self.workers.pop(uid).stop()
        self.omitted = 0
        for uid, (pid, identity) in active.items():
            if uid not in self.workers:
                if len(self.workers) >= self.limit:
                    self.omitted += 1
                    continue
                self.workers[uid] = Worker(pid, identity)

    def collect(self):
        labels = ["node", "namespace", "pod", "component"]
        running = GaugeMetricFamily("nador_split_capture_running", "Capture process alive, not proof of protocol visibility", labels=labels)
        errors = GaugeMetricFamily("nador_split_capture_restarts", "Cumulative parser/process restarts for this capture worker", labels=labels)
        last = GaugeMetricFamily("nador_split_last_message_timestamp_seconds", "Last decoded F1AP/E1AP PDU observation", labels=labels)
        messages = GaugeMetricFamily("nador_split_pdus_observed", "Cumulative decoded PDUs per worker; both endpoints may observe the same PDU", labels=labels + ["protocol", "procedure_code"])
        context_families = {}
        for worker in self.workers.values():
            with worker.lock:
                process = worker.process
                running.add_metric(worker.identity, int(process is not None and process.poll() is None))
                errors.add_metric(worker.identity, worker.error)
                last.add_metric(worker.identity, worker.last)
                for (protocol, code), count in worker.counts.items():
                    messages.add_metric(worker.identity + [protocol, code], count)
                for family in worker.tracker.collect(labels, worker.identity, time.monotonic()):
                    existing = context_families.setdefault(family.name, family)
                    if existing is not family:
                        existing.samples.extend(family.samples)
        yield from (running, errors, last, messages)
        yield from context_families.values()
        yield GaugeMetricFamily("nador_split_capture_targets_omitted", "Sources omitted due to capture limit", value=self.omitted)

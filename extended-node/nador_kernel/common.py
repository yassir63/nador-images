"""BCC lifetime and conservative capability evidence shared by both sources."""

import ctypes as ct
import time
from pathlib import Path


def number(value):
    return int(value.value if hasattr(value, "value") else value)


def bounded_size(value):
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 65536:
        raise ValueError("map capacity must be an integer between 1 and 65536")
    return value


def trace_format(event, root=None):
    roots = [Path(root)] if root is not None else [
        Path("/sys/kernel/tracing"), Path("/sys/kernel/debug/tracing")
    ]
    failures = []
    for base in roots:
        path = base / "events" / event.replace(":", "/") / "format"
        try:
            return path.read_text(), str(path)
        except OSError as exc:
            failures.append(str(exc))
    raise RuntimeError("tracepoint format unavailable: " + "; ".join(failures))


def read_diagnostics(bpf, names):
    table = bpf["diagnostics"]
    return {name: number(table[ct.c_int(i)]) for i, name in enumerate(names)}


class Source:
    def __init__(self, enabled):
        self.enabled = bool(enabled)
        self.bpf = None
        self.node = None
        self.started_ns = None
        self.errors = []
        self.evidence = {}
        self.closed = False

    def error(self, stage, exc):
        self.errors.append({"stage": stage, "error": f"{type(exc).__name__}: {exc}"})
        self.errors = self.errors[-32:]

    def load(self, source, events, factory):
        try:
            if factory is None:
                from bcc import BPF
                factory = BPF
            self.bpf = factory(text=source)
            attached = {key.decode() if isinstance(key, bytes) else key
                        for key in self.bpf.tracepoint_fds}
            if not set(events).issubset(attached):
                raise RuntimeError("BCC did not attach every required tracepoint")
            self.evidence["attached_tracepoints"] = sorted(attached)
            self.started_ns = time.monotonic_ns()
        except Exception as exc:
            self.error("load_attach", exc)
            self._cleanup()

    def _cleanup(self):
        if self.bpf is not None:
            try:
                self.bpf.cleanup()
            except Exception as exc:
                self.error("cleanup", exc)
            self.bpf = None

    def close(self):
        self._cleanup()
        self.closed = True

    def status(self, diagnostics=None, read_ok=True):
        diagnostics = diagnostics or {}
        attached = self.bpf is not None
        observed = diagnostics.get("events", 0) > 0
        if self.closed:
            state = "closed"
        elif not self.enabled:
            state = "disabled"
        elif not attached:
            state = "unavailable"
        elif not read_ok:
            state = "read_error"
        elif not observed:
            state = "armed_unobserved"
        elif diagnostics.get("map_failures", 0):
            state = "degraded"
        else:
            state = "tracing"
        return {
            "state": state,
            "enabled": self.enabled,
            "attached": attached,
            "observed": observed,
            "available": attached and observed and read_ok and not self.closed,
            "complete": attached and observed and read_ok and not self.closed
                        and not any(diagnostics.get(name, 0) for name in (
                            "map_failures", "identity_mismatches", "clock_errors",
                            "discarded_pending", "stack_errors", "stack_map_failures")),
            "started_monotonic_ns": self.started_ns,
            "diagnostics": diagnostics,
            "evidence": dict(self.evidence),
            "errors": list(self.errors),
        }

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

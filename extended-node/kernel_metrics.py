"""Prometheus projection of conservative kernel-source snapshots."""

from collections import defaultdict

from prometheus_client.core import GaugeMetricFamily


def kernel_metrics(snapshot, node):
    status_metric = GaugeMetricFamily("nador_kernel_source_state", "Kernel source capability and coverage state", labels=["node", "source", "state"])
    complete = GaugeMetricFamily("nador_kernel_source_complete", "Observation available without detected tracing gaps; not proof of no unobserved loss", labels=["node", "source"])
    diagnostics = GaugeMetricFamily("nador_kernel_source_diagnostic_count", "Cumulative diagnostic counts since probe start", labels=["node", "source", "diagnostic"])
    for source in ("off_cpu", "attributed_drops"):
        data = snapshot[source]
        status = data["status"]
        status_metric.add_metric([node, source, status["state"]], 1)
        complete.add_metric([node, source], int(status["complete"]))
        for name, count in status["diagnostics"].items():
            diagnostics.add_metric([node, source, name], count)
    yield status_metric
    yield complete
    yield diagnostics
    labels = ["node", "namespace", "pod", "component", "state"]
    intervals = GaugeMetricFamily("nador_nf_off_cpu_seconds_snapshot", "Completed off-CPU durations over currently tracked task generations; can decrease when tasks exit", labels=labels)
    counts = GaugeMetricFamily("nador_nf_off_cpu_completed_intervals_snapshot", "Completed off-CPU intervals over currently tracked task generations", labels=labels[:-1])
    totals = defaultdict(lambda: [0, 0, 0, 0])
    for task in snapshot["off_cpu"]["tasks"]:
        if task["runnable_ns"] is None:
            continue
        identity = tuple([node, *task["pod"]])
        for index, key in enumerate(("runnable_ns", "blocked_ns", "unknown_ns", "completed_intervals")):
            totals[identity][index] += task[key]
    for identity, values in totals.items():
        for state, value in zip(("runnable", "blocked", "unknown"), values[:3]):
            intervals.add_metric(list(identity) + [state], value / 1e9)
        counts.add_metric(list(identity), values[3])
    yield intervals
    yield counts
    tasks = {task["uid"]: task["pod"] for task in snapshot["off_cpu"]["tasks"]}
    stacks = GaugeMetricFamily("nador_nf_blocked_stack_samples_snapshot", "Bounded kernel stack IDs without symbol or causal interpretation", labels=["node", "namespace", "pod", "component", "stack_id"])
    stack_counts = defaultdict(int)
    for row in snapshot["off_cpu"]["blocked_stacks"]:
        if row["uid"] in tasks:
            stack_counts[tuple([node, *tasks[row["uid"]], str(row["stack_id"])])] += row["samples"]
    for identity, count in stack_counts.items():
        stacks.add_metric(list(identity), count)
    yield stacks
    drops = GaugeMetricFamily("nador_packet_drop_window_observations", "Observed skb free reasons in this polling window; namespace attribution is not causal NF attribution", labels=["node", "namespace", "pod", "component", "netns_inode", "ifindex", "reason_code", "location", "ownership", "ownership_reason"])
    for row in snapshot["attributed_drops"]["records"]:
        if row["window_count"] is None:
            continue
        identity = [node, *(row["pod"] or ["", "", ""]),
                    str(row["netns_inode"] or 0), str(row["ifindex"] or 0),
                    str(row["reason_code"]), row["location"], row["ownership"], row["ownership_reason"]]
        drops.add_metric(identity, row["window_count"])
    yield drops

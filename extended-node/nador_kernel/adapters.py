"""Integration switches without modifying or importing the legacy probe."""

from .drops import AttributedDrops
from .offcpu import OffCPU


class KernelSources:
    def __init__(self, config, *, offcpu_options=None, drop_options=None):
        self.offcpu = OffCPU(enabled=config.get("off_cpu", False),
                             off_cpu_stacks=config.get("off_cpu_stacks", False),
                             **(offcpu_options or {}))
        self.drops = AttributedDrops(enabled=config.get("attributed_drops", False), **(drop_options or {}))
        # Selection, not successful attachment, suppresses legacy double attach.
        self.use_legacy_drop_reasons = bool(config.get("kernel_drops", False)
                                            and not config.get("attributed_drops", False))

    def reconcile(self, processes, pods, proc_root, node):
        processes = list(processes)
        if self.offcpu.enabled:
            self.offcpu.reconcile(processes, pods, proc_root, node)
        if self.drops.enabled:
            self.drops.reconcile(processes, pods, proc_root, node)

    def snapshot(self):
        return {"off_cpu": self.offcpu.snapshot(), "attributed_drops": self.drops.snapshot(),
                "use_legacy_drop_reasons": self.use_legacy_drop_reasons}

    def close(self):
        self.offcpu.close()
        self.drops.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

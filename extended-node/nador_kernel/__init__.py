"""Opt-in, source-only kernel diagnostics. Importing never loads BCC."""

from .adapters import KernelSources
from .drops import AttributedDrops
from .offcpu import OffCPU

__all__ = ["OffCPU", "AttributedDrops", "KernelSources"]

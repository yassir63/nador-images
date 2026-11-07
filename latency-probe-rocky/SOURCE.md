# Latency probe: original runtime with fragmentation fix

This source build uses the recovered Rocky runtime documented in
`versions/latency-probe/runtime-2026w43.json`, not a prebuilt probe image.
The preceding unpatched rebuild matched all 312 installed RPM version strings
from the original image. Python application dependencies and libbpf/bpftool
source revisions are pinned in the Dockerfile and requirements file.

The probe source is the recovered `2026w43` source with the subsequent
IPv4-fragmentation fix applied to `gtp_latency.bpf.c`:

- Ignore non-initial outer IPv4 fragments when decoding UDP/GTP headers.
- Reject fragmented inner IPv4 packets for TCP latency matching.
- Validate inner IPv4 and TCP header lengths.
- Compute TCP payload length using the inner IP total length rather than the
  current skb length, including when outer fragmentation shortens that skb.

The patched BPF source is byte-identical to the current `latency-probe` source
(`9efac5b5a258d7503a01ec3b2219e2439422445ca20a0a3adb092d99dcaedc6c`).
Other recovered probe source files remain unchanged. `SHA256SUMS` records the
source that is actually built, including the patch.

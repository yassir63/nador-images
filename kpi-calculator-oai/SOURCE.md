# OAI KPI calculator source build

Upstream: https://github.com/Ziyad-Mabrouk/5g-monarch

The upstream calculator is in `kpi_computation/standard/app/kpi_calculator.py`
(inspected at commit `1ff82311726e88c797807b46d23252af9429be8b`).
Its MIT license and author attribution are retained.

The OAI-specific variant was previously packaged in
`ghcr.io/ziyad-mabrouk/kpi-calculator-oai@sha256:611e3d906082d8b9809c6f231cf13a84d5f2ccc597fad770c867d56da7045b8c`.
Our checked-in source preserves the tested cleanup from commit
`cc2fb205ca284a55492ae72600c0e23a9e01ce7f`: remove the obsolete
`mac_throughput` export and its computation, retain UE-count and PRB-saturation
computation, clear stale saturation series, and tolerate an empty saturation result.
UE goodput remains supplied by the gNB parser, not synthesized here.

The Dockerfile now installs this source on the official Python image, without
inheriting any calculator application layers. Python 3.10.20, Debian trixie,
`/exporter`, port 9000, `MONARCH_THANOS_URL`, and `UPDATE_PERIOD` are retained.
The seven application dependency versions were recovered from the old image's
installed package metadata and are pinned in `requirements.txt`.
The official base is a digest-pinned refreshed build of the same Python/distro
version; its OS layers are not byte-identical to the historical base.

This change does not modernize the remaining LCID/PRB queries or claim they work
with every OAI log format. Live scenario validation remains necessary.

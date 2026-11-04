# FiveG Lens Images

Source code for the monitoring containers used by [FiveG Lens](https://github.com/yassir63/fiveg-lens).

The component runtime sources originate from the recorded local build directories.
The controller default probe reference now points to GHCR; packet processing and discovery logic are unchanged.
The controller builds from an official Python image, and the latency probe builds from Debian.
Both standalone versions passed the initial image builds and packaged Python checks.
They have not yet been validated in a live 5G deployment.
`common/` contains the shared tunnel-identity module. All images target Linux amd64.

| Component | Selected version | Docker build context |
| --- | --- | --- |
| `controller` | `2026w45` | `.` |
| `throughput-probe` | `2026w44` | `.` |
| `latency-probe` | `2026w45` | `.` |
| `ue-mapper` | `2026w45-ml` (prepared, not published) | `.` |
| `amf-sniffer` | `2026w45-ml` (prepared, not published) | `.` |
| `smf-sniffer` | `2026w45-ml` (prepared, not published) | `.` |
| `user-plane-path` | `2026w45-ml` (prepared, not published) | `.` |
| `packet-pairer` | `2026w43` | `.` |
| `kpi-calculator-oai` | `2026w43-radio-scoped` | `kpi-calculator-oai` |

`images.json` lists the build contexts and GHCR names. The initial eight images have been published and are publicly pullable from GHCR.
Dockerfiles expect the listed context; for example, the controller uses the repository root,
while the OAI calculator uses its own directory.

## Automatic builds and publication

The workflow checks and builds changed components on pull requests and pushes to `main`.
Successful `main` builds publish automatically to GHCR using `GITHUB_TOKEN`; pull requests do not publish.
The `ml-observability` branch also publishes, but only the four ML collector
images with separate `-ml` version tags. It does not rebuild/retag the stable
controller, latency or throughput images, and does not propose main monitoring
default changes. Each ML publication also receives an exact commit tag.
Shared `common/` changes rebuild its consumers. Initial pushes and manual runs build every image.
Changing the workflow, `images.json` or `.dockerignore` rebuilds every image.

Every publication gets the configured version tag and a `sha-<full-commit>` tag.
The version tag follows subsequent builds; use the commit tag or digest to select an exact build.
Image labels link the build to its source repository and commit. A build record with the digest and
source hashes is retained as a workflow artifact for 90 days; commit-tagged images and Git history
provide the longer-term source link. These checks do not exercise the Linux eBPF verifier or a live 5G network.

New GHCR packages may initially be private; make them public in GitHub Packages before unauthenticated deployment.

## Version history

`versions/<component>/<tag>.json` records the original published image, digest, changes and source evidence.
Current records include source-file SHA-256 hashes. Five components were checked against their published
Python script layers; the controller and probes match recorded build-source hashes.
Historical records without an exact source snapshot say so explicitly. Keep existing version records
unchanged and add a new record for each subsequent version.
The initial GHCR publications are also archived as `versions/<component>/sha-<commit>.json`,
with their registry digests, source hashes and workflow link.
Source origins are relative to the original CodeDev directory, without personal absolute paths.

## Optional ML observability collectors

This repository owns the runtime sources and Dockerfiles. FiveG Lens owns the
deployment settings, Helm assets and experiment artifact collection; there is
no need to regenerate image sources from a FiveG Lens checkout.

- `amf-sniffer/ngap_metrics.py` adds N2 PDU-session resource setup timing,
  outcomes and correlation diagnostics to the current AMF sniffer. Enable with
  `AMF_NGAP_METRICS_ENABLED=true`; port 9102 by default.
- `smf-sniffer/pfcp_metrics.py` adds PFCP session establishment timing and Cause
  outcomes to the current SMF sniffer. Enable with
  `SMF_PFCP_METRICS_ENABLED=true`; port 9104 by default.
- `common/observation_runtime.py` connects those optional collectors to the
  existing packet loops without replacing the scoped mapper logic.
- `ue-mapper/mapper_coverage.py` extends `/metrics` with bounded context coverage
  and Redis collection health, retaining `fiveg_ue_session_info`.
- `user-plane-path/probe.py` is a separate external Linux interface/GTP-U probe.
  FiveG Lens injects it into selected gNB/UPF pods and sets port 9403. Standalone
  default port is 9103. AF_PACKET capture requires Linux and `NET_RAW` capability.

The `2026w45-ml` source records intentionally have no image digest: these changes
have not been built, published or tested in a live deployment. Historical version
records are unchanged. Protocol metrics are local observations; missing or
expired observations alone do not prove network faults.

Build from the repository root, selecting your desired local tag:

```bash
docker build --platform linux/amd64 -f amf-sniffer/Dockerfile -t amf-sniffer:ml-test .
docker build --platform linux/amd64 -f smf-sniffer/Dockerfile -t smf-sniffer:ml-test .
docker build --platform linux/amd64 -f ue-mapper/Dockerfile -t ue-mapper:ml-test .
docker build --platform linux/amd64 -f user-plane-path/Dockerfile -t user-plane-path:ml-test .
```

The existing workflow now tests collectors before building. It discovers the
new path-probe image through `images.json`. Its publication is reported in update
proposals but does not change default monitoring images or enable the feature:
select its published reference explicitly with `ObservabilitySettings.path_image`.

## Existing base-image dependencies

The controller builds from `python:3.11-slim` and installs its Python dependencies and kubectl directly.
The latency probe compiles from source in a Debian build stage and uses a Debian runtime; it does not inherit an older probe image.
The OAI calculator inherits `ghcr.io/ziyad-mabrouk/kpi-calculator-oai` by digest and adapts its calculator.
The OAI calculator base and its original licences/attribution remain in place.
Controller and latency build recipes changed. The controller default probe reference also changed to GHCR;
packet processing and discovery logic are unchanged.

Original contributions are licensed under the BSD 3-Clause Clear licence in `LICENSE`.
Inherited code, container bases and external dependencies retain their original licences.

## Monitoring update proposals

After the selected images all build, pass checks and publish, the workflow proposes their commit tags
in `fiveg-lens/src/fiveg_lens/assets/images.json`. Each build batch has its own pull request, containing
source links and image digests. It changes no other monitoring files and never merges or deploys automatically.
Without `MONITORING_REPO_TOKEN`, image publication still works and this optional step is skipped.
The token must grant Contents and Pull requests write access to the `fiveg-lens` repository.

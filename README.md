# NADOR Images

Source code for the monitoring containers used by [NADOR](https://github.com/ifran-project/nador).

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
| `ue-mapper` | `2026w43` | `.` |
| `amf-sniffer` | `2026w43` | `.` |
| `smf-sniffer` | `2026w43` | `.` |
| `packet-pairer` | `2026w43` | `.` |
| `kpi-calculator-oai` | `2026w43-radio-scoped` | `kpi-calculator-oai` |

`images.json` lists the build contexts and GHCR names. The initial eight images have been published and are publicly pullable from GHCR.
Dockerfiles expect the listed context; for example, the controller uses the repository root,
while the OAI calculator uses its own directory.

## Automatic builds and publication

The workflow checks and builds changed components on pull requests and pushes to `main`.
Successful `main` builds publish to `ghcr.io/yassir63` using the `GHCR_PUBLISH_TOKEN`
Actions secret (a classic token for `yassir63` with `write:packages`). Pull requests do not publish.
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
in the NADOR monitoring image manifest. Each build batch has its own pull request, containing
source links and image digests. It changes no other monitoring files and never merges or deploys automatically.
Without `MONITORING_REPO_TOKEN`, image publication still works and this optional step is skipped.
Use a separate fine-grained token with `ifran-project` as the resource owner
and Contents and Pull requests write access to `ifran-project/nador`.
The proposals target that repository's `main` branch.

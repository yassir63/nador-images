"""Select successful, commit-tagged builds in the monitoring image manifest."""

import argparse
import json
from pathlib import Path


# Change only images with successful publication records, preserving other selections.
def apply_records(manifest: dict, records: list[dict], images: dict) -> str:
    """Update defaults and return a reviewable pull-request description."""
    lines = ["Select these successfully built and published monitoring images.", "",
             "| Component | Selected image | Digest |", "| --- | --- | --- |"]
    details = []
    for record in records:
        component = record["component"]
        sha = record["source_commit"]
        reference = images[component]["ghcr_image"].rsplit(":", 1)[0] + ":sha-" + sha
        if reference not in record["tags"]:
            raise ValueError(f"Missing commit-tagged publication for {component}")
        target = images[component].get("monitoring_target")
        if not target:
            source = f"https://github.com/{record['source_repository']}/commit/{sha}"
            lines.append(f"| {component} (opt-in; no default changed) | `{reference}` | `{record['digest']}` |")
            details.append(f"- {component}: [{record['source_change']}]({source}); select through ObservabilitySettings.path_image.")
            continue
        group, key = target.split(".")
        if group == "probes":
            manifest[group][key] = reference
        else:
            repository, tag = reference.rsplit(":", 1)
            manifest[group][key].update(repository=repository, image_tag=tag)
        manifest.setdefault("builds", {})[component] = {
            key: record[key] for key in ("digest", "source_repository", "source_commit", "source_change")
        }
        source = f"https://github.com/{record['source_repository']}/commit/{sha}"
        lines.append(f"| {component} | `{reference}` | `{record['digest']}` |")
        details.append(f"- {component}: [{record['source_change']}]({source})")
    lines.extend(["", *details])
    lines.extend(["", "Only default image selections change. Explicit scenario overrides remain in effect.",
                  "Merge after review to select these images for future deployments; this PR does not redeploy anything."])
    return "\n".join(lines) + "\n"


# Read CI publication records and update the checked-out monitoring repository.
def main() -> None:
    """Write one manifest update and its pull-request body without network access."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--images", type=Path, required=True)
    parser.add_argument("--records", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--body-file", type=Path, required=True)
    args = parser.parse_args()
    images = json.loads(args.images.read_text())
    records = [json.loads(path.read_text()) for path in sorted(args.records.rglob("build-record.json"))]
    manifest = json.loads(args.manifest.read_text())
    body = apply_records(manifest, records, images)
    args.manifest.write_text(json.dumps(manifest, indent=2) + "\n")
    args.body_file.write_text(body)


if __name__ == "__main__":
    main()

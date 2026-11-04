"""Select image builds from the central manifest and changed source paths."""

import json
import os
import subprocess
from pathlib import Path


def select_components(images: dict, changed: list[str] | None, ref: str = "") -> list[dict]:
    """Rebuild shared consumers and components whose files changed."""
    all_images = changed is None or any(
        path in {"images.json", ".dockerignore"} or path.startswith(".github/")
        for path in changed
    )
    selected = [
        {"component": name, **config}
        for name, config in images.items()
        if all_images
        or any(path.startswith(name + "/") for path in changed)
        or (config["context"] == "." and any(path.startswith("common/") for path in changed))
    ]
    if ref == "refs/heads/ml-observability":
        ml_components = {"amf-sniffer", "smf-sniffer", "ue-mapper", "user-plane-path"}
        selected = [item for item in selected if item["component"] in ml_components]
        if any(not item["current_version"].endswith("-ml") for item in selected):
            raise ValueError("ML branch publications require separate -ml version tags")
    return selected


def main() -> None:
    """Write the selected matrix for GitHub Actions; initial/manual runs build all."""
    images = json.loads(Path("images.json").read_text())
    base = os.environ.get("BASE_SHA", "")
    changed = None
    if os.environ["GITHUB_EVENT_NAME"] != "workflow_dispatch" and base.strip("0"):
        changed = subprocess.check_output(
            ["git", "diff", "--name-only", base, "HEAD"], text=True
        ).splitlines()
    matrix = json.dumps({"include": select_components(images, changed, os.environ.get("GITHUB_REF", ""))})
    with Path(os.environ["GITHUB_OUTPUT"]).open("a") as output:
        output.write("matrix=" + matrix + "\n")
    print(matrix)


if __name__ == "__main__":
    main()

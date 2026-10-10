#!/usr/bin/env python3
import tarfile
import zipfile
from pathlib import Path

from check_privacy import credential_values, forbidden

secrets = credential_values()
artifacts = list(Path("dist").glob("*.whl")) + list(Path("dist").glob("*.tar.gz"))
if len(artifacts) != 2:
    raise SystemExit("Build wheel and source distribution before checking")
for artifact in artifacts:
    if artifact.suffix == ".whl":
        with zipfile.ZipFile(artifact) as archive:
            entries = [(name, archive.read(name)) for name in archive.namelist()]
    else:
        with tarfile.open(artifact) as archive:
            entries = [
                (item.name, archive.extractfile(item).read())
                for item in archive.getmembers()
                if item.isfile()
            ]
    asset_names = {Path(name).name for name, _ in entries if "/workspace/static/" in name}
    if asset_names != {"index.html", "app.js", "style.css"}:
        raise SystemExit("Workspace assets missing or unexpected in distribution")
    for name, data in entries:
        if forbidden(name) or any(secret in data for secret in secrets):
            raise SystemExit("Private data in distribution: " + name)
print("Distribution privacy gate passed")

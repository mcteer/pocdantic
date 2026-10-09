#!/usr/bin/env python3
import argparse
import json
import re
from pathlib import Path

from pocdantic.evidence import load_evidence


def check_feature(root: Path):
    for file in [
        Path(".specify/memory/constitution.md"),
        *(
            root / name
            for name in (
                "spec.md",
                "plan.md",
                "tasks.md",
                "research.md",
                "data-model.md",
                "contracts/runtime.md",
            )
        ),
    ]:
        if not file.is_file() or not file.read_text().strip():
            raise SystemExit("Missing Spec Kit artifact: " + str(file))
        if re.search(r"\[NEEDS CLARIFICATION|\[PROJECT_NAME\]|\[FEATURE NAME\]", file.read_text()):
            raise SystemExit("Unresolved specification placeholder")
    checklists = list((root / "checklists").glob("*.md"))
    if not checklists:
        raise SystemExit("Missing requirements review: " + str(root))
    for file in checklists:
        if "- [ ]" in file.read_text():
            raise SystemExit("Requirements review incomplete: " + str(file))
    items = load_evidence(root / "acceptance.json")
    print(
        f"Spec gate passed: {root}; "
        f"{sum(item.status == 'blocked' for item in items)} live criteria blocked"
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--runtime-only", action="store_true")
    features = parser.add_mutually_exclusive_group()
    features.add_argument("--all-features", action="store_true")
    features.add_argument("--feature-directory", type=Path)
    args = parser.parse_args()
    if not Path("uv.lock").is_file():
        raise SystemExit("Missing lockfile")
    if args.runtime_only:
        if args.all_features or args.feature_directory:
            parser.error("--runtime-only cannot be combined with feature selection")
        from pocdantic.runtime import load_definitions
        from pocdantic.settings import Settings

        load_definitions(Settings(_env_file=None).profiles_file)
        print("Runtime configuration gate passed")
        return
    if args.feature_directory:
        roots = [args.feature_directory]
    elif args.all_features:
        roots = sorted(path.parent for path in Path("specs").glob("*/spec.md"))
    elif Path(".specify/feature.json").is_file():
        roots = [Path(json.loads(Path(".specify/feature.json").read_text())["feature_directory"])]
    else:
        roots = sorted(path.parent for path in Path("specs").glob("*/spec.md"))
        if len(roots) > 1:
            raise SystemExit("Select --feature-directory or --all-features")
    if not roots:
        raise SystemExit("No feature specifications found")
    for root in roots:
        check_feature(root)


if __name__ == "__main__":
    main()

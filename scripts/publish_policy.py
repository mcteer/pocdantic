"""The repository's publishable harness paths. Private working material stays local."""

from pathlib import PurePosixPath

ROOT_FILES = {
    ".gitignore",
    ".env.example",
    "README.md",
    "CONTRIBUTING.md",
    "AGENTS.md",
    "pyproject.toml",
    "uv.lock",
    "compose.yaml",
}


def generated_private(name: str) -> bool:
    p = PurePosixPath(name)
    if p.name in {
        "run.json",
        "events.jsonl",
        "bindings.jsonl",
        "delivery.json",
        "integrity.json",
        "definitions.json",
        "context.json",
        "manifest.json",
        "closeout.json",
        "closeout.md",
        "report.json",
        "report.md",
    }:
        return True
    return p.suffix in {".json", ".md", ".raw", ".jsonl"} and p.name.startswith(
        ("source-", "artifact-", "observation-", "review-", "report-", "transaction-", "closeout-")
    )


def publishable(name: str) -> bool:
    p = PurePosixPath(name)
    if generated_private(name):
        return False
    if name in ROOT_FILES:
        return True
    if name.startswith("specs/"):
        return p.suffix in {".md", ".json"} and not {"private", "evidence"} & set(p.parts)
    if name in {"docs/usage.md", "docs/configuration.md"}:
        return True
    if name.startswith("docs/adr/"):
        return p.suffix == ".md"
    if name.startswith(".specify/templates/"):
        return p.suffix == ".md"
    if name.startswith(".specify/scripts/bash/"):
        return p.suffix == ".sh"
    if name in {
        ".specify/.gitignore",
        ".specify/memory/constitution.md",
        ".specify/workflows/secure-poc/workflow.yml",
        ".specify/THIRD_PARTY_LICENSE.txt",
    }:
        return True
    # Keep the former package path eligible for immutable Git-history checks.
    if name in {
        "src/agent/workspace/static/index.html",
        "src/agent/workspace/static/app.js",
        "src/agent/workspace/static/style.css",
    }:
        return True
    if name.startswith(("src/agent/", "src/pocdantic/")):
        return p.suffix == ".py"
    if name.startswith("tests/"):
        return p.suffix == ".py"
    if name.startswith("config/"):
        return p.suffix in {".json", ".sql"}
    if name.startswith("scripts/"):
        return p.suffix in {".py", ".sh"}
    return name in {
        ".githooks/pre-commit",
        ".githooks/pre-push",
        ".github/workflows/ci.yml",
        ".github/pull_request_template.md",
        ".github/CODEOWNERS",
    }

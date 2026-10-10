"""Narrow allowlist shared by publication checks.

Generated evidence remains private even if placed inside an otherwise allowed tree.
The historical package path remains eligible only for immutable Git-history checks.
"""

import hashlib
import json
import re
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
    """Recognize generated validation, source, review, report, and closeout artifacts by
    name.
    """
    p = PurePosixPath(name)
    if p.name in {
        "providers.draft.json",
        "providers.readiness.json",
        "provider-secrets.json",
        "run.json",
        "anchor.json",
        "state.json",
        "recovery-receipt.json",
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
        (
            "source-",
            "artifact-",
            "observation-",
            "review-",
            "report-",
            "transaction-",
            "closeout-",
            "recovery-receipt-",
        )
    )


def private_content(name: str, data: bytes) -> bool:
    """Reject intact private recovery/native JSON even after its filename is changed.

    Inspect only data artifacts, so maintained Python tests may contain synthetic native
    examples. The detector complements fixed private-path and credential-value checks.
    """
    if PurePosixPath(name).suffix not in {".json", ".jsonl"}:
        return False
    try:
        values = [json.loads(data)] if data.lstrip().startswith((b"{", b"[")) else []
    except (ValueError, UnicodeError, RecursionError):
        try:
            values = [json.loads(line) for line in data.splitlines() if line.strip()]
        except (ValueError, UnicodeError, RecursionError):
            return False
    parts = PurePosixPath(name).parts
    example_name = name
    if len(parts) == 3 and re.fullmatch(r"pocdantic-[0-9][A-Za-z0-9.]+", parts[0]):
        example_name = str(PurePosixPath(*parts[1:]))
    # This exact immutable synthetic example alone is exempt. A modified or renamed
    # enrollment still fails private-content detection, including inside distributions.
    if (
        example_name == "config/providers.example.json"
        and hashlib.sha256(data).hexdigest()
        == "f03b8175792c3604077e8ab0d04e487c7f18af60fd88b99b11ea3a8552f0d091"
    ):
        return False
    pending = list(values)
    while pending:
        value = pending.pop()
        if isinstance(value, list):
            pending.extend(value)
        elif isinstance(value, dict):
            synthetic_policy = example_name == "config/response.example.json" and value == {
                "schema_version": 1,
                "intake_mode": "local_only",
                "sources": [],
                "audience": None,
                "workload_definition": "demo-agent",
                "environment_digest": "0" * 64,
                "issuer": "https://id.example",
                "automatic_cleanup": False,
            }
            if (
                {"installation_id", "source_policy_digest", "bindings"} <= value.keys()
                or {"installation_id", "draft_digest", "bindings"} <= value.keys()
                or {"action_id", "binding", "enrollment_digest"} <= value.keys()
                or {"observation_id", "binding_id", "source_digest"} <= value.keys()
                or {"acquisition_id", "ownership", "credential_path"} <= value.keys()
                or {"acquisition_id", "ownership", "actor_subject", "mount"} <= value.keys()
                or {"notice_id", "notice_revision", "resource_generation"} <= value.keys()
                or {"tenant_origin", "api_client_id", "entitlements", "source_digest"}
                <= value.keys()
                or {"installation_id", "policy_digest", "incidents"} <= value.keys()
                or {"installation_id", "recovery_mode", "recovery_installation_id"} <= value.keys()
                or {"intake_mode", "sources", "audience", "automatic_cleanup"} <= value.keys()
                and not synthetic_policy
                or {"kind", "root_run_id", "request_id", "issuer", "subject"} <= value.keys()
                or {"incident_id", "source", "event_id", "payload_digest"} <= value.keys()
                or {"incident_id", "source", "event_id", "instructions"} <= value.keys()
                or {"environment_digest", "source_instance", "records"} <= value.keys()
                or {"installation_id", "environment_digest", "attempts"} <= value.keys()
                or value.get("type") in ("request", "response")
                and isinstance(value.get("request"), dict)
                or "lease_id" in value
                and isinstance(value.get("data"), dict)
                and {"username", "password"} <= value["data"].keys()
                or {"incident_id", "operation_id", "source_digests", "environment_digest"}
                <= value.keys()
            ):
                return True
            for text in value.values():
                if isinstance(text, str) and (
                    re.search(
                        r"https://[^\s]+[?&](?:sig|signature|code|token|api_key)=", text, re.I
                    )
                    or re.search(r"(?:^|\s)password\s*=", text, re.I)
                    or re.search(r"(?:postgres(?:ql)?://)[^\s/@]+:[^\s/@]+@", text, re.I)
                ):
                    return True
            pending.extend(value.values())
    return False


def publishable(name: str) -> bool:
    """Allow only maintained repository artifacts after excluding generated private
    evidence.
    """
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

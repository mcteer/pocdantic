"""Synthetic private evidence builders; never read the operator's real integration state."""

import json
import os
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest


@pytest.fixture
def closeout_project(tmp_path, monkeypatch):
    """Return an isolated project with poisoned credentials and denied effect constructors."""
    import socket
    import subprocess

    import httpx

    from agent.settings import Settings

    attempts = []
    process = subprocess.Popen

    def denied(*args, **kwargs):
        """Fail any accidental provider setup or effect in the local closeout workflow."""
        attempts.append(True)
        raise AssertionError("closeout effect attempted")

    monkeypatch.setattr(Settings, "__init__", denied)
    monkeypatch.setattr(httpx.AsyncClient, "__init__", denied)
    monkeypatch.setattr(httpx.Client, "__init__", denied)
    monkeypatch.setattr(socket.socket, "connect", denied)
    monkeypatch.setattr(socket.socket, "connect_ex", denied)

    def root_discovery_only(arguments, *args, **kwargs):
        """Allow only bounded CLI Git root discovery; all other subprocesses remain denied."""
        if arguments == ["git", "rev-parse", "--show-toplevel"] and kwargs.get("cwd") == tmp_path:
            return process(arguments, *args, **kwargs)
        return denied(arguments, *args, **kwargs)

    monkeypatch.setattr(subprocess, "Popen", root_discovery_only)
    monkeypatch.setenv("BEARER_TOKEN", "synthetic-poison-do-not-read")
    monkeypatch.setenv("VAULT_ADDR", "https://invalid.example")
    monkeypatch.chdir(tmp_path)
    yield tmp_path
    assert not attempts, "closeout attempted a provider, network or subprocess effect"


def private_file(path, value):
    """Write owned regular synthetic input bytes with the required private mode."""
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    data = value if isinstance(value, bytes) else json.dumps(value).encode()
    path.write_bytes(data)
    os.chmod(path, 0o600)
    return path


def instant(offset=0):
    """Produce a timezone-aware UTC timestamp around the real test clock."""
    return (datetime.now(UTC) + timedelta(seconds=offset)).isoformat()


def inventory():
    """Build a complete structural inventory whose capabilities are explicitly unproven."""
    return {
        "schema_version": 1,
        "implementation_digest": "a" * 64,
        "dependency_digest": "b" * 64,
        "definitions": [{"reference": "agent-fixture", "digest": "c" * 64}],
        "policies": [{"reference": "read-policy", "digest": "d" * 64}],
        "datasets": [{"reference": "fixture", "digest": "e" * 64}],
        "owners": [
            "agent_engineering",
            "verify_owner",
            "vault_owner",
            "vip_owner",
            "customer_security",
        ],
        "sources": [
            {
                "profile_id": str(uuid4()),
                "product": "vault",
                "version": "test-v1",
                "edition": "synthetic",
                "instance": "fixture-instance",
                "cluster": "cluster-fixture",
                "namespace": "fixture",
                "format": "native-facts-v1",
                "schema_digest": "f" * 64,
                "capabilities": {"audit": "unavailable"},
                "clock_uncertainty": 0.0,
                "reporting_delay": 1200,
                "selectors": [],
            }
        ],
    }


def reviewed_facts(project, *, provenance="native", omit=None):
    """Build source-shaped original records for every criterion, then review exact digests.

    These are synthetic fixtures simulating an owner's native export, not product evidence.
    The fixture exercises extraction rather than writing computed assessment rows.
    """
    from agent.closeout.catalog import RULES
    from agent.closeout.models import Inventory, byte_digest, digest, now, validate
    from agent.closeout.review import PRODUCT_ROLE, record
    from agent.closeout.sources import import_source
    from agent.closeout.store import Store

    labels = list(dict.fromkeys(label for values in RULES.values() for label in values))
    scope = str(uuid4())
    stamp = now() - timedelta(seconds=60)
    moments = {label: stamp + timedelta(seconds=20) for label in labels}
    for label, seconds in [
        ("absent-before", 0),
        ("native-discovery", 2),
        ("notification-before-enrollment", 3),
        ("entity-ceiling-binding", 8),
        ("approval-before-issue", 9),
        ("scoped-issuance", 10),
        ("native-trigger", 12),
        ("native-user-risk", 15),
        ("automatic-session-revoke", 17),
        ("user-suspended", 18),
        ("teams-received", 19),
        ("exact-revoke", 25),
    ]:
        moments[label] = stamp + timedelta(seconds=seconds)
    records = {product: [] for product in ("application", "verify", "vault", "vip", "customer")}
    operation = {
        "operation": "read",
        "target_ref": "fixture",
        "request_digest": "a" * 64,
        "policy_digest": "d" * 64,
        "scope_digest": "e" * 64,
        "result": "success",
        "mechanism": "unknown",
        "issued": 0,
    }
    cleanup = {
        "lease_ref": "lease-fixture",
        "action": "revoke",
        "completion_event": "exact-revoke",
        "after_result": "denied",
        "outstanding": 0,
    }
    discovery = {
        "candidate_ref": "candidate",
        "source_object_ref": "origin",
        "classification": "unknown_agent",
        "activity_event": "native-discovery",
        "absent_event": "absent-before",
        "finding_event": "native-discovery",
        "notification_ref": "notification-before-enrollment",
        "registration_event": "entity-ceiling-binding",
    }
    for label in labels:
        if label == omit:
            continue
        kind, product, values = "operation_result", "vault", operation.copy()
        if label in {"deployed-secret-scan", "adapter-isolation"}:
            product = "application"
            values.update(deployment_digest="a" * 64)
            values.update(
                {"embedded_secrets": 0}
                if label == "deployed-secret-scan"
                else {"adapter_isolated": True}
            )
        elif label == "no-permission-group":
            values["permission_groups"] = 0
        elif label == "lease-ttl":
            values.update(operation="issue", issued=1, lease_ref="lease-fixture", ttl_seconds=120.0)
        elif label in {"signed-obo-rar", "same-jwt-invalid"}:
            kind, product = "jwt_validation", "verify"
            values = {
                "token_digest": "a" * 64,
                "expires_at": (stamp + timedelta(seconds=200)).isoformat(),
                "issuer": "issuer",
                "audience_ref": "vault",
                "subject_ref": "human",
                "verifier_ref": "independent",
                "result": "denied" if label == "same-jwt-invalid" else "success",
                "mechanism": "jwt_invalid" if label == "same-jwt-invalid" else "unknown",
            }
        elif label == "scoped-issuance":
            values.update(operation="issue", issued=1)
        elif label in {
            "sql-write-denied",
            "outside-ceiling",
            "vault-policy-denied",
            "zero-issuance",
        }:
            values.update(operation="write", result="denied", mechanism="policy_denied")
        elif label == "child-read":
            values["policy_digest"] = "b" * 64
        elif label == "parent-write":
            values.update(operation="write")
        elif label in {"exact-revoke", "automatic-secret-cleanup", "generation-after-check"}:
            kind, values = "cleanup_result", cleanup.copy()
        elif label in {"approval-before-issue", "denied-zero-issue", "timeout-zero-issue"}:
            kind, product = "approval_result", "verify"
            decision = {
                "approval-before-issue": "approve",
                "denied-zero-issue": "deny",
                "timeout-zero-issue": "timeout",
            }[label]
            values = {
                "action_digest": "a" * 64,
                "resource_digest": digest("resource"),
                "parameters_digest": "e" * 64,
                "requester_digest": digest({"actor": "agent", "subject": "human"}),
                "transaction_ref": label,
                "decision": decision,
                "decision_event": label,
                "issued": 1 if decision == "approve" else 0,
                "effects": 1 if decision == "approve" else 0,
                "issuance_event": "scoped-issuance" if decision == "approve" else None,
            }
        elif label == "lineage-audit":
            kind, product = "lineage", "application"
            values = {
                "parent_ref": "parent",
                "child_ref": "child",
                "parent_policy": "d" * 64,
                "child_policy": "b" * 64,
                "child_read_event": "child-read",
                "parent_write_event": "parent-write",
            }
        elif label in {"automatic-session-revoke", "user-suspended", "teams-received"}:
            kind, product = "session_result", "verify"
            values = {
                "session_ref": "session",
                "user_ref": "human",
                "action": {
                    "automatic-session-revoke": "revoke",
                    "user-suspended": "suspend",
                    "teams-received": "notify",
                }[label],
                "existing_session": "denied",
                "new_session": "denied",
                "automatic_event": "native-user-risk",
                "notification_ref": "teams-received",
            }
        elif label in {
            "absent-before",
            "native-discovery",
            "notification-before-enrollment",
            "native-user-risk",
            "native-secret-detection",
            "native-trigger",
        }:
            kind, product, values = "discovery_result", "vip", discovery.copy()
            values["classification"] = {
                "native-user-risk": "user_compromise",
                "native-secret-detection": "secret_misuse",
                "native-trigger": "agent_compromise",
            }.get(label, "unknown_agent")
        elif label in {"independent-bootstrap", "native-svid", "independent-relying"}:
            kind = "jwt_validation"
            product = {
                "independent-bootstrap": "verify",
                "native-svid": "vault",
                "independent-relying": "application",
            }[label]
            values = {
                "token_digest": "b" * 64 if label == "independent-bootstrap" else "c" * 64,
                "expires_at": (stamp + timedelta(seconds=200)).isoformat(),
                "issuer": "issuer",
                "audience_ref": "vault",
                "subject_ref": "agent",
                "verifier_ref": product,
                "result": "success",
                "mechanism": "unknown",
            }
        elif label == "entity-ceiling-binding":
            kind = "registration_result"
            values = {
                "entity_ref": "agent",
                "owner_ref": "owner",
                "ceiling_ref": "ceiling",
                "registration_event": "entity-ceiling-binding",
                "readback_digest": "a" * 64,
                "policy_digest": "d" * 64,
                "bootstrap_ref": "independent-bootstrap",
                "issuance_ref": "native-svid",
                "relying_ref": "independent-relying",
            }
        elif label == "native-revocation-timing":
            kind, product = "timing", "vip"
            values = {
                "trigger_event": "native-trigger",
                "end_event": "exact-revoke",
                "trigger_at": moments["native-trigger"].isoformat(),
                "end_at": moments["exact-revoke"].isoformat(),
                "trigger_uncertainty": 0.0,
                "end_uncertainty": 0.0,
            }
        elif label == "customer-receipt":
            kind, product = "witness", "customer"
            values = {
                "meeting_at": moments[label].isoformat(),
                "participants": ["customer_security"],
                "witnessed_digest": "a" * 64,
                "attestation_ref": "meeting",
            }
        elif label == "vault-human-actor-audit":
            kind = "identity_mapping"
            values = {
                "issuer": "issuer",
                "subject_ref": "human",
                "entity_ref": "human-entity",
                "alias_ref": "alias",
                "mount_ref": "mount",
                "category": "human",
                "mapping_event": "mapping",
            }
        records[product].append(
            {
                "source_event_id": label,
                "occurred_at": moments[label].isoformat(),
                "operation_ref": label
                if label in {"denied-zero-issue", "timeout-zero-issue"}
                else "flow",
                "actor": "agent",
                "subject": "human",
                "resource": "resource",
                "generation": 1,
                "obligation": label,
                "fact_kind": kind,
                "values": values,
            }
        )
    for label in ("denied-zero-issue", "timeout-zero-issue"):
        records["vault"].append(
            {
                "source_event_id": "vault-" + label,
                "occurred_at": moments[label].isoformat(),
                "operation_ref": label,
                "actor": "agent",
                "subject": "human",
                "resource": "resource",
                "generation": 1,
                "obligation": label,
                "fact_kind": "operation_result",
                "values": operation
                | {"operation": "deny", "result": "denied", "mechanism": "policy_denied"},
            }
        )
    inv = inventory()
    inv["policies"].append({"reference": "child-policy", "digest": "b" * 64})
    template = inv["sources"][0] | {"capabilities": {"audit": "supported"}}
    inv["sources"] = [
        {
            **template,
            "profile_id": str(uuid4()),
            "product": product,
            "proof_labels": [r["obligation"] for r in rows],
            "selectors": [{"field": field, "pointer": "/" + field} for field in rows[0]],
        }
        for product, all_rows in records.items()
        for rows in [all_rows[i : i + 16] for i in range(0, len(all_rows), 16)]
    ]
    store = Store(project)
    head = store.prepare(validate(Inventory, inv))
    for profile in store.inventory(head).sources:
        raw = json.dumps(
            [r for r in records[profile.product] if r["obligation"] in profile.proof_labels]
        ).encode()
        head = store.head(head.dossier_id)
        ref = import_source(
            store,
            head,
            {
                "profile_id": str(profile.profile_id),
                "format": "native-facts-v1",
                "provenance": provenance,
                "input_digest": byte_digest(raw),
                "observed_at": instant(),
                "environment_digest": digest(store.inventory(head)),
                "scope": scope,
                "complete": True,
            },
            raw,
        )
        source = store.read(head.dossier_id, ref)
        base = {
            "reviewer": "fixture-owner",
            "role": PRODUCT_ROLE[profile.product],
            "observed_at": instant(-1),
            "decision": "approve",
            "rationale": "reviewed original fixture extraction",
            "attestations": [str(ref.object_id)],
        }
        record(
            store,
            store.head(head.dossier_id),
            base
            | {
                "kind": "source-profile",
                "subject_id": str(profile.profile_id),
                "expected_digest": digest(profile),
            },
        )
        record(
            store,
            store.head(head.dossier_id),
            base
            | {
                "kind": "source",
                "subject_id": str(ref.object_id),
                "expected_digest": ref.seal_digest,
                "extraction_digest": digest(
                    {"facts": source["facts"], "normalized": source["normalized"]}
                ),
            },
        )
    return store, store.head(head.dossier_id)

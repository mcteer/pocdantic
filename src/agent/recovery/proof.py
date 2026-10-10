"""Verify reviewed native Vault pairs without retaining raw provider evidence.

The private envelope adds operator-attested instance/environment provenance to native
records. It cannot authenticate an export: explicit review remains the trust boundary.
Only exact acquisition linkage, pre-execution ACL denial, and synchronous cleanup
are supported; missing or HMAC-protected linking fields fail closed.
"""

import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path

from agent.validation.store import StoreError, decode_json, no_symlinks

from .models import Receipt, now, valid_handle
from .store import RecoveryError, check_stat


@dataclass(frozen=True, repr=False)
class Proof:
    """Private derived candidate; importing a handle alone never clears recovery."""

    receipt: Receipt
    lease_handle: str | None


def invalid():
    """Reject unsupported evidence using one credential-free public reason."""
    raise RecoveryError("recovery_evidence_invalid")


def read_source(store, source):
    """Read one owner-only, non-linked local artifact with bounded strict decoding."""
    path = Path(source).absolute()
    try:
        path.relative_to(store.project / ".local")
        if path.is_relative_to(store.root):
            invalid()
        no_symlinks(path)
        for parent in path.parents:
            if parent == store.project:
                break
            check_stat(parent.stat(follow_symlinks=False), directory=True)
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            before = os.fstat(fd)
            check_stat(before)
            if before.st_size > 2 * 1024 * 1024:
                invalid()
            with os.fdopen(os.dup(fd), "rb") as stream:
                raw = stream.read(2 * 1024 * 1024 + 1)
            after = path.stat(follow_symlinks=False)
            check_stat(after)
            if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
                invalid()
            if len(raw) > 2 * 1024 * 1024 or (before.st_dev, before.st_ino) != (
                after.st_dev,
                after.st_ino,
            ):
                invalid()
            try:
                value = decode_json(raw)
            except StoreError:
                lines = raw.splitlines()
                if not 3 <= len(lines) <= 201:
                    invalid()
                header = decode_json(lines[0])
                if not isinstance(header, dict) or "records" in header:
                    invalid()
                value = header | {"records": [decode_json(line) for line in lines[1:]]}
                # Header wrapping must not relax the overall depth limit for JSONL.
                value = decode_json(json.dumps(value, allow_nan=False).encode())
        finally:
            os.close(fd)
        return value, hashlib.sha256(raw).hexdigest()
    except Exception:
        invalid()


def native_pair(records, *, path, operation, namespace, correlation=None):
    """Require a unique native pair agreeing on all effect-binding request fields."""
    selected = [
        r for r in records if isinstance(r, dict) and r.get("request", {}).get("path") == path
    ]
    if len(selected) != 2:
        invalid()
    requests = [r for r in selected if r.get("type") == "request"]
    responses = [r for r in selected if r.get("type") == "response"]
    if len(requests) != 1 or len(responses) != 1:
        invalid()
    request, response = requests[0], responses[0]
    a, b = request.get("request"), response.get("request")
    if not isinstance(a, dict) or not isinstance(b, dict):
        invalid()
    for key in ("id", "path", "operation", "namespace", "headers", "data"):
        first = json.dumps(a.get(key), sort_keys=True, allow_nan=False)
        second = json.dumps(b.get(key), sort_keys=True, allow_nan=False)
        if first != second:
            invalid()
    identifier = a.get("id")
    if (
        not isinstance(identifier, str)
        or not 0 < len(identifier) <= 1024
        or identifier.startswith("hmac-")
    ):
        invalid()
    if a.get("operation") != operation or a.get("namespace", {}).get("path") != namespace:
        invalid()
    if correlation is not None and a.get("headers", {}).get("x-correlation-id") != [
        str(correlation)
    ]:
        invalid()
    return request, response, identifier


def allowed(record):
    """Read explicit native policy evaluation without truthiness coercion."""
    return record.get("auth", {}).get("policy_results", {}).get("allowed")


def handles(response):
    """Collect supported lease locations, rejecting conflicting native observations."""
    value = response.get("response", {})
    if not isinstance(value, dict) or not isinstance(value.get("data", {}), dict):
        invalid()
    found = [
        v for v in (value.get("lease_id"), value.get("data", {}).get("lease_id")) if v is not None
    ]
    if len(set(found)) > 1:
        invalid()
    return found[0] if found else None


def verify_sources(store, item, sources, reviewer):
    """Bind at most two reviewed private exports to this incident's current revision."""
    try:
        if (
            not 1 <= len(sources) <= 2
            or not isinstance(reviewer, str)
            or not 0 < len(reviewer.strip()) <= 64
        ):
            invalid()
        records, digests = [], []
        for source in sources:
            envelope, digest = read_source(store, source)
            if not isinstance(envelope, dict) or set(envelope) != {
                "schema_version",
                "environment_digest",
                "source_instance",
                "records",
            }:
                invalid()
            if type(envelope["schema_version"]) is not int or envelope["schema_version"] != 1:
                invalid()
            if (
                envelope["environment_digest"] != item.environment_digest
                or envelope["source_instance"] != store.settings.vault_addr
            ):
                invalid()
            if not isinstance(envelope["records"], list):
                invalid()
            records.extend(envelope["records"])
            digests.append(digest)
        if not 2 <= len(records) <= 200 or len(set(digests)) != len(digests):
            invalid()
        if any(
            not isinstance(r, dict) or r.get("type") not in {"request", "response"} for r in records
        ):
            invalid()
        request, response, identifier = native_pair(
            records,
            path=item.credential_path,
            operation="read",
            namespace=store.settings.vault_namespace,
            correlation=item.operation_id,
        )
        if item.native_request_id is not None and item.native_request_id != identifier:
            invalid()
        handle = handles(response)
        outcome = "lease_identified"
        if (
            allowed(request) is False
            and allowed(response) is False
            and response.get("error") == "permission denied"
            and not handle
            and not response.get("response")
        ):
            outcome = "not_issued"
        elif (
            request.get("error")
            or response.get("error")
            or allowed(request) is not True
            or allowed(response) is not True
            or not valid_handle(item.credential_path, handle)
        ):
            invalid()
        if item.lease_handle is not None and item.lease_handle != handle:
            invalid()
        cleanup = [r for r in records if r.get("request", {}).get("path") == "sys/leases/revoke"]
        if cleanup:
            if outcome == "not_issued":
                invalid()
            cr, cs, cleanup_id = native_pair(
                records,
                path="sys/leases/revoke",
                operation="update",
                namespace=store.settings.vault_namespace,
            )
            if cleanup_id == identifier:
                invalid()
            data = cr["request"].get("data")
            if (
                not isinstance(data, dict)
                or set(data) != {"lease_id", "sync"}
                or data.get("lease_id") != handle
                or data.get("sync") is not True
            ):
                invalid()
            if (
                cr.get("error")
                or cs.get("error")
                or allowed(cr) is not True
                or allowed(cs) is not True
                or "response" not in cs
                or not isinstance(cs["response"], dict)
                or cs["response"].get("data")
                or cs["response"].get("warnings")
                or cs["response"].get("lease_id")
            ):
                invalid()
            outcome = "revoked"
        if len(records) != 2 + len(cleanup):
            invalid()
        receipt = Receipt(
            outcome=outcome,
            incident_id=item.incident_id,
            incident_revision=item.revision,
            operation_id=item.operation_id,
            environment_digest=item.environment_digest,
            native_request_id=identifier,
            native_response_id=identifier,
            source_digests=tuple(digests),
            reviewer_label=reviewer.strip(),
            reviewed_at=now(),
        )
        return Proof(receipt, handle)
    except RecoveryError:
        raise
    except Exception:
        invalid()

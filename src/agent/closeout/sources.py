"""Bounded source extraction and descriptor-safe capture of existing private evidence.

Provider evidence is parsed from original bytes using reviewed fixed profiles. Capture snapshots
existing schema-valid member state and runs pure reducers; it never constructs legacy stores or
replays effects. Native facts remain ineligible until source/profile extraction review is present.
"""

import binascii
import fnmatch
import json
import re
import time
from pathlib import Path
from types import SimpleNamespace
from uuid import UUID, uuid5

from .models import (
    CloseoutError,
    Correlation,
    Fact,
    FactValues,
    ImportManifest,
    Source,
    byte_digest,
    canonical,
    decode,
    digest,
    fresh_id,
    now,
    require,
    validate,
)
from .store import checked_stat, deadline_check, no_links, read_owned, runtime_digest

SECRET_KEYS = frozenset(
    {
        "password",
        "passwd",
        "access_token",
        "refresh_token",
        "id_token",
        "client_secret",
        "authorization",
        "bearer_token",
        "private_key",
        "secret_key",
        "credential",
    }
)


def reject_secrets(raw):
    """Reject recognizable secret-bearing source content without returning diagnostic text."""
    require(not re.search(rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY", raw))
    require(
        not re.search(
            rb"(?:hvs\.[A-Za-z0-9_-]{20,}|s\.[A-Za-z0-9]{20,}|gh[pousr]_[A-Za-z0-9]{30,})", raw
        )
    )
    for match in re.finditer(rb'["\'](?:client_token|token)["\']\s*:\s*([^,}\r\n]+)', raw, re.I):
        value = match.group(1).strip()
        # Vault audit tokens are irreversible keyed HMACs. Plaintext token values
        # are never required for closeout and must not enter even private imports.
        require(value in {b"null", b'""'} or re.fullmatch(rb'"hmac-sha256:[0-9a-f]{64}"', value))

    for token in re.findall(rb"[A-Za-z0-9_-]{2,}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", raw):
        import base64

        try:
            part = token.split(b".")[0]
            header = json.loads(base64.urlsafe_b64decode(part + b"=" * (-len(part) % 4)))
            require(not isinstance(header, dict) or "alg" not in header)
        except (UnicodeError, json.JSONDecodeError, binascii.Error):
            pass
    require(
        not any(
            re.search(rb'["\']' + key.encode() + rb'["\']\s*:', raw, re.I) for key in SECRET_KEYS
        )
    )
    require(not re.search(rb"\bBearer\s+\S+", raw, re.I))
    require(not re.search(rb"https://[^\s]+[?&](?:sig|signature|code|token|api_key)=", raw, re.I))
    require(not re.search(rb"postgres(?:ql)?://[^\s/@]+:[^\s/@]+@", raw, re.I))
    require(not re.search(rb"(?:^|\s)password\s*=", raw, re.I))


def pointer(value, path):
    """Resolve an exact bounded JSON Pointer; no wildcard, expression or implicit fallback."""
    require(isinstance(path, str) and len(path) <= 256 and "*" not in path)
    if path == "":
        return value
    require(path.startswith("/"))
    try:
        for item in path[1:].split("/"):
            require(not re.search(r"~(?![01])", item), "source_unsupported")
            item = item.replace("~1", "/").replace("~0", "~")
            if isinstance(value, list):
                require(
                    item == "0" or item.isdigit() and not item.startswith("0"), "source_unsupported"
                )
            value = value[int(item)] if isinstance(value, list) and item.isdigit() else value[item]
        return value
    except (KeyError, IndexError, TypeError, ValueError):
        raise CloseoutError("source_unsupported") from None


def profile_for(inventory, profile_id):
    """Resolve one explicitly selected source profile in the frozen inventory."""
    profile = next((p for p in inventory.sources if str(p.profile_id) == str(profile_id)), None)
    require(profile is not None, "source_unsupported")
    return profile


def extract_facts(profile, manifest, raw, source_id):
    """Independently extract and validate typed facts from exact source record locations."""
    require(profile.proof_labels, "source_unsupported")
    data = decode(raw)
    rows = pointer(data, profile.records_pointer)
    single = not isinstance(rows, list)
    rows = [rows] if single else rows
    require(len(rows) <= 10000, "capacity_exceeded")
    facts, seen = [], {}
    for i, row in enumerate(rows):
        selected = {s.field: pointer(row, s.pointer) for s in profile.selectors}
        required = {"source_event_id", "occurred_at", "operation_ref"}
        require(required <= selected.keys(), "source_unsupported")
        event_id = selected["source_event_id"]
        require(isinstance(event_id, str) and event_id not in seen, "evidence_conflict")
        seen[event_id] = digest(row)
        values = selected.get(
            "values",
            {key[7:]: value for key, value in selected.items() if key.startswith("values_")},
        )
        allowed = (
            {"values", "fact_kind", "obligation"}
            | required
            | {"actor", "subject", "resource", "generation"}
            | {"values_" + k for k in FactValues.model_fields}
        )
        require(selected.keys() <= allowed, "source_unsupported")
        correlation = validate(
            Correlation,
            {
                "scope": str(manifest.scope),
                "environment_digest": manifest.environment_digest,
                "operation": selected["operation_ref"],
                **{
                    k: selected[k]
                    for k in ("actor", "subject", "resource", "generation")
                    if k in selected
                },
            },
        )
        location = profile.records_pointer + ("/" + str(i) if not single else "")
        labels = [selected["obligation"]] if "obligation" in selected else profile.proof_labels
        require(all(label in profile.proof_labels for label in labels), "source_unsupported")
        for label in labels:
            fact = validate(
                Fact,
                {
                    "fact_id": str(uuid5(source_id, event_id + ":" + label)),
                    "kind": selected.get("fact_kind", profile.fact_kind),
                    "obligation": label,
                    "source_event_id": event_id,
                    "occurred_at": selected["occurred_at"],
                    "correlation": correlation.model_dump(mode="json"),
                    "values": values,
                    "record_pointer": location,
                },
            )
            require(profile.clock_uncertainty is not None, "source_unsupported")
            require((fact.occurred_at - now()).total_seconds() <= profile.clock_uncertainty)
            require(
                (fact.occurred_at - manifest.observed_at).total_seconds()
                <= profile.clock_uncertainty
            )
            facts.append(fact)
    return facts


def legacy_rows(profile, manifest, raw):
    """Reuse declared audit/Verify/Logfire field parsers without changing their proof strength."""
    from agent.validation.importers import logfire_record, vault_record, verify_record

    fmt = manifest.format
    shim = SimpleNamespace(
        format_version=2 if fmt.endswith("v2") else 1,
        source_instance=profile.instance,
        native_project_id=None,
    )
    if fmt.startswith("vault-audit"):
        rows = []
        for line in raw.splitlines():
            require(len(line) <= 65536, "capacity_exceeded")
            if line.strip():
                rows.append(vault_record(decode(line), shim).model_dump(mode="json"))
    else:
        data = decode(raw)
        values = data if isinstance(data, list) else data.get("events", data.get("rows", []))
        require(isinstance(values, list), "source_unsupported")
        parser = verify_record if fmt.startswith("verify") else logfire_record
        rows = [parser(v, shim).model_dump(mode="json") for v in values]
    require(len(rows) <= 10000, "capacity_exceeded")
    return rows


def import_source(store, head, manifest_value, raw):
    """Append original bytes and independently parsed records, never an acceptance decision."""
    manifest = validate(ImportManifest, manifest_value)
    inventory = store.inventory(head)
    require(manifest.environment_digest == digest(inventory), "context_mismatch")
    require(byte_digest(raw) == manifest.input_digest, "integrity_failed")
    require(len(raw) <= 10 * 1024 * 1024, "capacity_exceeded")
    profile = profile_for(inventory, manifest.profile_id)
    require(profile.format == manifest.format, "source_unsupported")
    require(manifest.observed_at <= now(), "schema_invalid")
    source_id = fresh_id()
    facts, normalized = [], []
    if manifest.format == "attachment-v1":
        require(len(raw) <= 5 * 1024 * 1024, "capacity_exceeded")
        if manifest.media_type == "image/png":
            from .attachments import png

            png(raw)
        elif manifest.media_type == "image/jpeg":
            from .attachments import jpeg

            jpeg(raw)
        else:
            require(manifest.media_type == "text/plain")
            raw.decode("utf-8")
            require(not re.search(rb"^\s*<(?:!doctype\s+html|html|svg|script)(?:\s|>)", raw, re.I))
            require(not raw.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")))
        reject_secrets(raw)
    else:
        reject_secrets(raw)
        if manifest.format == "native-facts-v1":
            facts = extract_facts(profile, manifest, raw, source_id)
        elif manifest.format in {"vault-activity-v1", "execution-roster-v1", "entity-mapping-v1"}:
            from .counting import parse_records

            normalized = parse_records(manifest.format, raw, manifest)
        else:
            normalized = legacy_rows(profile, manifest, raw)
    # One dossier budget counts all activity artifacts, including baseline/final sets.
    old_count = sum(
        len(v.get("normalized", []))
        for _, v in store.records(head, "source")
        if v.get("format") == "vault-activity-v1"
    )
    if manifest.format == "vault-activity-v1":
        require(old_count + len(normalized) <= 10000, "capacity_exceeded")
    value = Source(
        source_id=source_id,
        profile_id=profile.profile_id,
        format=manifest.format,
        provenance=manifest.provenance,
        environment_digest=manifest.environment_digest,
        scope=manifest.scope,
        captured_at=now(),
        observed_at=manifest.observed_at,
        raw_digest=byte_digest(raw),
        schema_digest=profile.schema_digest,
        facts=facts,
        normalized=normalized,
        manifest=manifest,
        implementation_digest=runtime_digest(),
    )
    return store.append(
        head.dossier_id, head.revision, "source", value, {"source.raw": raw}, object_id=source_id
    )


class SnapshotPath:
    """Minimal path view for legacy pure reducers, backed only by captured in-memory bytes."""

    def __init__(self, files, name, child=None):
        """Keep membership lookup detached from the operator's mutable original directory."""
        self.files, self.name, self.child = files, name, child

    def glob(self, pattern):
        """Yield deterministic captured filenames for legacy artifact enumeration."""
        return [Path(n) for n in sorted(self.files) if fnmatch.fnmatch(n, pattern)]

    def __truediv__(self, name):
        """Produce a membership-only child without filesystem access."""
        return SnapshotPath(self.files, name, name)

    def exists(self):
        """Check the captured file inventory rather than current source state."""
        return self.child in self.files


class SnapshotWriter:
    """Read-only adapter satisfying existing pure validation reducer contracts."""

    def __init__(self, files, name):
        """Wrap captured bytes and the original typed run identity without creating a store."""
        self.files, self.path = files, SnapshotPath(files, name)

    def read_bytes(self, name):
        """Return exactly captured bytes; missing members use the legacy safe error class."""
        from agent.validation.store import StoreError

        if name not in self.files:
            raise StoreError("evidence_missing")
        return self.files[name]

    def read_json(self, name):
        """Decode strict captured JSON without persisting a derived report."""
        return decode(self.read_bytes(name))

    def inventory(self):
        """Expose exact hashes used to detect member reference closure drift."""
        return {n: byte_digest(b) for n, b in self.files.items()}


def snapshot_directory(path, names=None):
    """Read a fixed member directory twice and reject moved/changed file inventories."""
    deadline = time.monotonic() + 30
    no_links(path)
    require(path.is_dir(), "evidence_missing")
    checked_stat(path.lstat(), directory=True)
    selected = sorted(
        names if names is not None else [p.name for p in path.iterdir() if p.is_file()]
    )
    require(len(selected) <= 98, "capacity_exceeded")
    before_names = sorted(p.name for p in path.iterdir())
    original_identity = path.lstat().st_ino
    files = {}
    for name in selected:
        deadline_check(deadline)
        require(name == Path(name).name and name not in {".", ".."}, "storage_invalid")
        files[name] = read_owned(path / name, deadline=deadline)
        reject_secrets(files[name])
    require(original_identity == path.lstat().st_ino, "input_changed")
    require(before_names == sorted(p.name for p in path.iterdir()), "input_changed")
    for name, data in files.items():
        require(read_owned(path / name, deadline=deadline) == data, "input_changed")
    return files


def evaluate_member(kind, object_id, files, source_path):
    """Apply maintained pure reducers at the actual clock and return qualified native facts."""
    native, result, context = False, {}, None
    if kind == "validation":
        from agent.validation.models import CloseoutSnapshot, ValidationRun
        from agent.validation.report import rebuild_report

        if "run.json" in files:
            run = ValidationRun.model_validate(decode(files["run.json"]))
            require(run.validation_id == object_id, "integrity_failed")
            value = rebuild_report(SnapshotWriter(files, str(object_id)), persist=False)
            result = value.model_dump(mode="json")
            native = run.mode == "live"
            context = (
                decode(files["context.json"]).get("digest") if "context.json" in files else None
            )
        else:
            snapshot = CloseoutSnapshot.model_validate(decode(files["closeout.json"]))
            require(snapshot.snapshot_id == object_id, "integrity_failed")
            require("manifest.json" in files, "integrity_failed")
            # Immutable old snapshots retain their manifest but need complete run recapture
            # before any fifteen-row native claim is eligible.
            result = snapshot.model_dump(mode="json")
            context = None
    elif kind == "governance":
        from agent.governance.models import Journal
        from agent.governance.report import closeout
        from agent.governance.store import Anchor, Seal
        from agent.validation.models import canonical as legacy_canonical

        state = Journal.model_validate(decode(files["state.json"]))
        anchor = Anchor.model_validate(decode(files["anchor.json"]))
        seal = Seal.model_validate(decode(files["control.lock"]))
        root_info = source_path.stat()
        require(
            anchor.root_identity == (root_info.st_dev, root_info.st_ino)
            and anchor.environment == state.environment,
            "integrity_failed",
        )
        require(
            set(anchor.file_identities)
            == {"anchor.json", "control.lock", "effect.lock", "service.lock"},
            "integrity_failed",
        )
        require(
            state.installation_id == anchor.installation_id == seal.installation_id,
            "integrity_failed",
        )
        require(
            seal.revision == state.revision
            and seal.state_digest == byte_digest(legacy_canonical(state)),
            "integrity_failed",
        )
        info = (source_path / "state.json").stat()
        require(seal.state_identity == (info.st_dev, info.st_ino), "integrity_failed")
        for name, expected in anchor.file_identities.items():
            actual = (source_path / name).lstat()
            checked_stat(actual)
            require(expected == (actual.st_dev, actual.st_ino), "integrity_failed")
        result = closeout(state, object_id)
        result["cleanup_outstanding"] = any(
            c.candidate_id == object_id and c.unresolved for c in state.credentials
        ) or any(
            r.candidate_id == object_id and r.state in {"submitted", "uncertain", "conflict"}
            for r in state.registrations
        )
        native = any(
            e.candidate_id == object_id and e.provenance == "native" for e in state.evidence
        )
        context = state.environment
    elif kind == "response":
        from agent.response.models import ResponseAnchor, SourcePolicy
        from agent.response.providers.journal import ResponseJournalV2
        from agent.validation.closeout import provider_closeout
        from agent.validation.models import canonical as legacy_canonical

        state = ResponseJournalV2.model_validate(decode(files["state.json"]))
        anchor = ResponseAnchor.model_validate(decode(files["anchor.json"]))
        require(state.installation_id == anchor.installation_id, "integrity_failed")
        policy = SourcePolicy.model_validate(decode(files["policy.json"]))
        require(
            policy.environment_digest == state.environment_digest
            and byte_digest(legacy_canonical(policy)) == state.policy_digest,
            "integrity_failed",
        )
        if anchor.recovery_mode == "configured":
            from agent.recovery.models import Anchor as RecoveryAnchor
            from agent.recovery.models import parse_journal

            recovery_anchor = RecoveryAnchor.model_validate(
                decode(files["related-recovery-anchor.json"])
            )
            recovery = parse_journal(decode(files["related-recovery-state.json"]))
            require(
                recovery.installation_id
                == recovery_anchor.installation_id
                == anchor.recovery_installation_id,
                "integrity_failed",
            )
        result = provider_closeout(state, object_id)
        selected_incident = next(
            (incident for incident in state.incidents if incident.incident_id == object_id), None
        )
        require(selected_incident is not None, "evidence_missing")
        linked = {a.target_id for a in selected_incident.actions if a.kind == "revoke_exact"}
        result["cleanup_outstanding"] = any(
            a.status in {"planned", "submitted", "uncertain", "failed"}
            for a in selected_incident.actions
        )
        if anchor.recovery_mode == "configured":
            for identifier in linked:
                attempt = next((a for a in recovery.attempts if a.incident_id == identifier), None)
                result["cleanup_outstanding"] |= attempt is None or attempt.state != "resolved"
        native = any(
            o.source != "synthetic"
            for a in state.provider_actions
            if object_id in a.incidents
            for o in a.observations
        )
        context = state.environment_digest
    else:
        from .regression import evaluate

        result = evaluate(files, object_id)
    return result, native, context


def capture(store, head, kind, object_id):
    """Snapshot one typed member with full scoped history and zero source-store writes."""
    object_id = UUID(str(object_id))
    require(kind in {"validation", "response", "governance", "regression"})
    local = store.project / ".local"
    if kind == "validation":
        roots = [
            local / "validation" / str(object_id),
            local / "validation/closeouts" / str(object_id),
        ]
        found = [p for p in roots if p.exists()]
        require(len(found) == 1, "evidence_missing" if not found else "evidence_conflict")
        path, names = found[0], None
    elif kind in {"response", "governance"}:
        path = local / kind
        require(path.is_dir(), "evidence_missing")
        names = (
            ["state.json", "anchor.json", "control.lock", "effect.lock", "service.lock"]
            if kind == "governance"
            else ["state.json", "anchor.json", "policy.json"]
        )
    else:
        path, names = local / "security-regression" / str(object_id), None
    no_links(path)
    for parent in [local, *[p for p in path.parents if p.is_relative_to(local)]]:
        checked_stat(parent.lstat(), directory=True)
    files = snapshot_directory(path, names)
    if kind == "response":
        from agent.response.models import ResponseAnchor

        anchor = ResponseAnchor.model_validate(decode(files["anchor.json"]))
        if anchor.recovery_mode == "configured":
            related = snapshot_directory(local / "recovery", ["anchor.json", "state.json"])
            files.update({"related-recovery-" + name: raw for name, raw in related.items()})
    result, native, context = evaluate_member(kind, object_id, files, path)
    inv = store.inventory(head)
    profile = next(
        (
            p
            for p in inv.sources
            if p.member_environment_digest and p.member_environment_digest == context
        ),
        inv.sources[0],
    )
    native = native and context is not None and profile.member_environment_digest == context
    source_id = fresh_id()
    value = Source(
        source_id=source_id,
        profile_id=profile.profile_id,
        format=profile.format,
        provenance="native" if native else "synthetic" if kind == "regression" else "operator",
        environment_digest=digest(inv),
        scope=object_id,
        captured_at=now(),
        observed_at=now(),
        raw_digest=digest({n: byte_digest(b) for n, b in files.items()}),
        schema_digest=profile.schema_digest,
        origin_kind=kind,
        origin_id=object_id,
        origin_inventory={n: byte_digest(b) for n, b in files.items()},
        source_assessment=result,
        implementation_digest=runtime_digest(),
    )
    stored_files = {f"original-{i}.raw": data for i, data in enumerate(files.values())}
    stored_files["original-index.json"] = canonical(
        {n: f"original-{i}.raw" for i, n in enumerate(files)}
    )
    # Capture must recheck originals after evaluation too; a changed source cannot seal.
    for name, data in files.items():
        require(read_owned(original_path(path, name)) == data, "input_changed")
    return store.append(
        head.dossier_id, head.revision, "source", value, stored_files, object_id=source_id
    )


def current_origin(store, source):
    """Verify original source availability/drift without rewriting captured history."""
    if source.origin_kind == "import":
        return (
            "historical"
            if any(
                f.kind == "jwt_validation" and f.values.expires_at <= now() for f in source.facts
            )
            else "current"
        )
    local = store.project / ".local"
    if source.origin_kind in {"governance", "response"}:
        path = local / source.origin_kind
    elif source.origin_kind == "regression":
        path = local / "security-regression" / str(source.origin_id)
    else:
        candidates = [
            local / "validation" / str(source.origin_id),
            local / "validation/closeouts" / str(source.origin_id),
        ]
        found = [p for p in candidates if p.is_dir()]
        if len(found) != 1:
            return "missing" if not found else "invalid"
        path = found[0]
    if not path.is_dir() or any(
        not original_path(path, name).exists() for name in source.origin_inventory
    ):
        return "missing"
    for name, expected in source.origin_inventory.items():
        if byte_digest(read_owned(original_path(path, name))) != expected:
            return "historical"
    if source.origin_kind == "response" and (now() - source.captured_at).total_seconds() > 300:
        return "historical"
    return "current"


def original_path(root, name):
    """Resolve only fixed related recovery aliases, retaining raw originals outside packages."""
    if name in {"related-recovery-anchor.json", "related-recovery-state.json"}:
        return root.parent / "recovery" / name.removeprefix("related-recovery-")
    require(name == Path(name).name, "storage_invalid")
    return root / name

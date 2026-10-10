"""Bounded tenant-specific native JSON projection without executable selectors.

Only enrolled scalar paths become security content. Vendor display fields are ignored,
never copied into plans, traces or summaries. Root correlation uses registered ownership.
"""

import hashlib
from dataclasses import dataclass
from uuid import UUID

from agent.response.models import ResponseError, RiskSignal
from agent.validation.models import canonical
from agent.validation.store import decode_json

from .providers.models import Rule, require


@dataclass(frozen=True, repr=False)
class NativeProjection:
    """Normalized event plus private selected-field digest, without retaining raw payload."""

    signal: RiskSignal
    rule: Rule
    selected_digest: str
    enrollment_digest: str

    def __iter__(self):
        """Preserve two-value projection unpacking while exposing canonical digest to intake."""
        return iter((self.signal, self.rule))


def scalar(data, pointer):
    """Resolve restricted JSON Pointer to a scalar; containers and missing keys fail closed."""
    current = data
    for part in pointer.split("/")[1:]:
        key = part.replace("~1", "/").replace("~0", "~")
        if isinstance(current, dict):
            current = current[key]
        elif isinstance(current, list) and key.isdecimal() and str(int(key)) == key:
            current = current[int(key)]
        else:
            raise ValueError()
    if type(current) not in (str, int, bool, float) or current is None:
        raise ValueError()
    return current


def project(raw, profile, state):
    """Validate bounded shape and enrolled mapping, returning normalized signal/fixed rule."""
    try:
        require(len(raw) <= 65536, "signal_invalid")
        require(
            state.enrollment is not None and profile in state.enrollment.sources, "source_invalid"
        )
        data = decode_json(raw)
        require(isinstance(data, dict), "signal_invalid")
        pending, count = [(data, 0)], 0
        while pending:
            value, depth = pending.pop()
            require(depth <= 8, "signal_invalid")
            if isinstance(value, dict):
                # Credential-bearing event fields are unsupported even when not selected;
                # collectors must send a minimal event, never forward their authority.
                forbidden = {
                    "accesstoken",
                    "refreshtoken",
                    "password",
                    "clientsecret",
                    "authorization",
                    "cookie",
                    "bearertoken",
                    "privatekey",
                }
                require(
                    not any(
                        key.casefold().replace("_", "").replace("-", "") in forbidden
                        for key in value
                    ),
                    "signal_invalid",
                )
            if isinstance(value, (dict, list)):
                pending.extend(
                    (v, depth + 1) for v in (value.values() if isinstance(value, dict) else value)
                )
            else:
                count += 1
                require(count <= 128, "signal_invalid")
        for pointer, expected in profile.predicates.items():
            actual = scalar(data, pointer)
            require(type(actual) is type(expected) and actual == expected, "mapping_missing")
        fields = {key: scalar(data, pointer) for key, pointer in profile.pointers.items()}
        definition = profile.objects.get(fields["object"])
        require(definition is not None, "mapping_missing")
        rule = next(
            (
                r
                for r in state.enrollment.rules
                if r.source == profile.alias and r.native_rule == fields["rule"]
            ),
            None,
        )
        require(rule is not None and rule.scope in profile.allowed_scopes, "mapping_missing")
        if rule.scope == "definition":
            target = {"kind": "definition", "workload_definition": definition}
        else:
            request_id = UUID(fields["request_id"])
            roots = [
                r
                for r in state.runs
                if r.request_id == request_id and r.workload_definition == definition
            ]
            require(
                len(roots) == 1
                and roots[0].actor_issuer is not None
                and roots[0].actor_subject is not None,
                "mapping_missing",
            )
            binding_id = profile.object_bindings.get(fields["object"])
            binding = next(
                (b for b in state.enrollment.bindings if b.binding_id == binding_id), None
            )
            run = roots[0]
            require(
                binding is not None
                and binding.enabled
                and binding.workload_definition == definition,
                "mapping_missing",
            )
            if binding.kind in {"registration", "native_token"}:
                require(
                    (binding.actor_issuer, binding.actor_subject)
                    == (run.actor_issuer, run.actor_subject),
                    "mapping_missing",
                )
                if binding.kind == "native_token":
                    require(binding.ownership == run.ownership(), "mapping_missing")
            elif binding.kind == "user":
                require(
                    (binding.user_issuer, binding.user_subject) == (run.issuer, run.subject),
                    "mapping_missing",
                )
            else:
                require(False, "mapping_missing")
            target = {"kind": "root_run", "root_run_id": run.root_run_id}
        signal = RiskSignal(
            event_id=fields["event_id"],
            occurred_at=fields["occurred_at"],
            reason=rule.reason,
            target=target,
        )
        selected = fields | {"occurred_at": signal.occurred_at.isoformat()}
        if rule.scope == "root_run":
            selected["request_id"] = str(UUID(fields["request_id"]))
        return NativeProjection(
            signal,
            rule,
            hashlib.sha256(canonical(selected)).hexdigest(),
            hashlib.sha256(canonical(state.enrollment)).hexdigest(),
        )
    except ResponseError:
        raise
    except Exception:
        raise ResponseError("signal_invalid") from None

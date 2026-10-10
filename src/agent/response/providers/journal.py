"""Response snapshot v2; schema-1 records remain intact and readable for migration."""

from typing import Literal

from pydantic import Field, field_validator, model_validator

from agent.response.models import ResponseJournal

from .models import (
    Enrollment,
    IncidentPlan,
    NativeTokenAcquisition,
    ProbeAcquisition,
    ProviderAction,
    RecoveryDecision,
    SubjectHold,
)


class ResponseJournalV2(ResponseJournal):
    """Atomic provider authority and effects alongside unchanged local containment."""

    schema_version: Literal[2] = 2
    enrollment: Enrollment | None = None
    provider_decisions: tuple[RecoveryDecision, ...] = Field(default=(), max_length=1000)
    provider_plans: tuple[IncidentPlan, ...] = Field(default=(), max_length=1000)
    provider_actions: tuple[ProviderAction, ...] = Field(default=(), max_length=16000)
    subject_holds: tuple[SubjectHold, ...] = Field(default=(), max_length=1000)
    native_acquisitions: tuple[NativeTokenAcquisition, ...] = Field(default=(), max_length=1000)
    probe_acquisitions: tuple[ProbeAcquisition, ...] = Field(default=(), max_length=1000)

    @field_validator("schema_version", mode="before")
    @classmethod
    def version(cls, value):
        """Override the inherited v1 guard; old binaries still reject this new schema."""
        if type(value) is not int or value != 2:
            raise ValueError("response_storage_error")
        return value

    @model_validator(mode="after")
    def provider_integrity(self):
        """Reject dangling authority, acquisition capacity and cross-incident references."""
        ids = {i.incident_id for i in self.incidents}
        actions = {a.action_id for a in self.provider_actions}
        if (
            len(actions) != len(self.provider_actions)
            or any(
                d.predecessor not in actions or d.successor not in actions
                for d in self.provider_decisions
            )
            or len({p.incident_id for p in self.provider_plans}) != len(self.provider_plans)
            or any(
                p.incident_id not in ids or not set(p.action_ids) <= actions
                for p in self.provider_plans
            )
            or any(
                not set(a.incidents) <= ids or not set(a.dependencies) <= actions
                for a in self.provider_actions
            )
            or any(h.incident_id not in ids for h in self.subject_holds)
            or sum(
                a.state in {"intent", "submitted", "uncertain"} for a in self.native_acquisitions
            )
            > 64
            or sum(
                a.state not in {"denied_no_issuance", "cleaned"} for a in self.probe_acquisitions
            )
            > 16
        ):
            raise ValueError("provider_capacity")
        # Dependencies and retry lineage form a bounded acyclic graph. Reject cycles
        # iteratively so a hostile snapshot cannot exhaust Python's recursion limit.
        predecessors = [a.predecessor for a in self.provider_actions if a.predecessor]
        if len(set(predecessors)) != len(predecessors):
            raise ValueError("provider_evidence_invalid")
        by_id = {a.action_id: a for a in self.provider_actions}
        remaining = {}
        for action in self.provider_actions:
            edges = set(action.dependencies)
            if action.predecessor:
                if action.predecessor not in by_id:
                    raise ValueError("provider_evidence_invalid")
                previous = by_id[action.predecessor]
                if (
                    previous.kind,
                    previous.binding.key(),
                    previous.binding.generation,
                    previous.enrollment_digest,
                ) != (
                    action.kind,
                    action.binding.key(),
                    action.binding.generation,
                    action.enrollment_digest,
                ):
                    raise ValueError("provider_evidence_invalid")
                edges.add(action.predecessor)
            remaining[action.action_id] = edges
        children = {aid: set() for aid in remaining}
        ready = [aid for aid, edges in remaining.items() if not edges]
        for aid, edges in remaining.items():
            for parent in edges:
                children[parent].add(aid)
        visited = 0
        while ready:
            parent = ready.pop()
            visited += 1
            for child in children[parent]:
                remaining[child].discard(parent)
                if not remaining[child]:
                    ready.append(child)
        if visited != len(remaining):
            raise ValueError("provider_evidence_invalid")
        for records in (self.native_acquisitions, self.probe_acquisitions):
            if len({a.acquisition_id for a in records}) != len(records):
                raise ValueError("provider_evidence_invalid")
        native_keys = [a.binding.key() for a in self.native_acquisitions if a.binding]
        if len(set(native_keys)) != len(native_keys):
            raise ValueError("provider_evidence_invalid")
        observation_ids = [
            o.observation_id
            for a in (*self.provider_actions, *self.probe_acquisitions)
            for o in a.observations
        ]
        if len(set(observation_ids)) != len(observation_ids):
            raise ValueError("provider_evidence_invalid")
        for probe in self.probe_acquisitions:
            for observation in probe.observations:
                incident = next(
                    (i for i in self.incidents if i.incident_id == observation.incident_id), None
                )
                if not (
                    incident
                    and observation.path in {"dynamic_fresh", "dynamic_session"}
                    and observation.binding_id == probe.recovery_incident_id
                    and observation.enrollment_digest == probe.enrollment_digest
                    and observation.resource_generation == probe.ownership.generation
                    and any(
                        a.action_id == observation.action_id
                        and a.kind == "revoke_exact"
                        and a.target_id == probe.recovery_incident_id
                        for a in incident.actions
                    )
                ):
                    raise ValueError("provider_evidence_invalid")
        if self.enrollment and (
            self.enrollment.installation_id != self.installation_id
            or self.enrollment.environment_digest != self.environment_digest
            or self.enrollment.source_policy_digest != self.policy_digest
        ):
            raise ValueError("provider_policy_changed")
        return self


def parse_journal(data):
    """Select explicit snapshot version; never silently drop unknown provider state."""
    return (
        ResponseJournalV2 if data.get("schema_version") == 2 else ResponseJournal
    ).model_validate(data)


def result_reservation(state):
    """Reserve future bounded results before accepting any effect, consuming space as it is used.

    Charge shared actions once. An already accepted observation spends its reservation
    rather than requiring the same bytes again. Acquisition intent also reserves room
    for a returned handle and a late authorized action before credential dispatch.
    """
    from agent.validation.models import canonical

    held = {incident for hold in state.holds for incident in hold.incident_ids}
    held.update(
        i.incident_id
        for i in state.incidents
        if i.target.kind == "root_run" and i.target.root_run_id in state.root_holds
    )
    unfinished = {i.incident_id for i in state.incidents if i.phase != "settled"}
    total = 0
    for action in state.provider_actions:
        if action.state in {"planned", "submitted", "uncertain"} or (
            action.required and set(action.incidents) & (held | unfinished)
        ):
            # Revision integers are positive but deliberately not restricted to 64 bits;
            # account for their known serialized widths rather than assuming small values.
            observation_bound = (
                8192 + len(str(action.binding.generation)) + len(str(action.notice_revision))
            )
            total += max(0, 2048 + 16 * observation_bound - len(canonical(action.observations)))
    for acquisition in state.native_acquisitions:
        if acquisition.state not in {"intent", "submitted", "uncertain"}:
            continue
        late_plan = any(
            p.native_token_authorized
            and any(
                i.incident_id == p.incident_id and i.matches(acquisition.ownership)
                for i in state.incidents
            )
            for p in state.provider_plans
        )
        total += max(
            0,
            65536
            + (262144 if late_plan else 0)
            - len(
                canonical(
                    {
                        "binding": acquisition.binding,
                        "state": acquisition.state,
                        "submitted_at": acquisition.submitted_at,
                    }
                )
            ),
        )
    for probe in state.probe_acquisitions:
        if probe.state not in {"cleaned", "denied_no_issuance"}:
            bound = 8192 + len(str(probe.ownership.generation))
            total += max(0, 65536 + 16 * bound - len(canonical(probe)))
    return total

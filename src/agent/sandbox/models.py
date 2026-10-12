"""Closed sandbox/query contracts with byte bounds and no credential-bearing fields."""

import json
import math
from typing import Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictInt,
    StrictStr,
    field_validator,
    model_validator,
)

from agent.security import SecurityError


class BoundaryModel(BaseModel):
    """Reject coercion and unknown fields; immutable plans are not executable source."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


def bounded_text(value, maximum):
    """Measure encoded bytes, including multibyte input, before dispatch."""
    if type(value) is not str or not 1 <= len(value.encode("utf-8")) <= maximum:
        raise ValueError("invalid text size")
    return value


def encoded(value):
    """Encode finite JSON for private size checks, never diagnostic logging."""
    return json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":")).encode()


class QueryRequest(BoundaryModel):
    """An untrusted SELECT proposal with data parameters and no authority."""

    sql: StrictStr
    parameters: tuple[StrictInt | StrictStr, ...] = ()

    @field_validator("sql")
    @classmethod
    def sql_size(cls, value):
        """Limit parser input independently of interpreter memory."""
        return bounded_text(value, 8192)

    @field_validator("parameters", mode="before")
    @classmethod
    def sequence(cls, value):
        """Accept only JSON-like sequences and preserve strict scalar types."""
        if type(value) not in (list, tuple) or len(value) > 32:
            raise ValueError("invalid parameters")
        return tuple(value)

    @field_validator("parameters")
    @classmethod
    def values(cls, value):
        """Reject unsafe or oversized values before parser or database work."""
        for item in value:
            if type(item) is int and not -(2**63) <= item < 2**63:
                raise ValueError("integer range")
            if type(item) is str and len(item.encode()) > 1024:
                raise ValueError("string size")
        return value

    @model_validator(mode="after")
    def request_size(self):
        """Apply the whole-frame cap as well as individual field caps."""
        if len(encoded(self.model_dump(mode="json"))) > 16384:
            raise ValueError("request size")
        return self


class Predicate(BoundaryModel):
    """One typed comparison; only approved operations can reach the compiler."""

    column: Literal["id", "status"]
    operator: Literal["eq", "ne", "lt", "le", "gt", "ge"]
    parameter_index: int = Field(ge=1, le=32)


class Order(BoundaryModel):
    """An output-column ordering, with no arbitrary expression."""

    column: Literal["id", "status", "count"]
    direction: Literal["asc", "desc"] = "asc"


class ReadPlan(BoundaryModel):
    """Closed relational plan; compilation never executes model SQL or AST rendering."""

    relation: Literal["public.poc_records"] = "public.poc_records"
    kind: Literal["rows", "count", "grouped_count"]
    columns: tuple[Literal["id", "status"], ...] = ()
    predicates: tuple[Predicate, ...] = Field(default=(), max_length=8)
    order: tuple[Order, ...] = Field(default=(), max_length=2)
    limit: int = Field(default=100, ge=1, le=100)
    parameters: tuple[StrictInt | StrictStr, ...] = Field(default=(), max_length=32)

    @model_validator(mode="after")
    def closed_semantics(self):
        """Check every combination again after an untrusted parser worker responds."""
        QueryRequest(sql="plan", parameters=self.parameters)
        if self.kind == "rows":
            if not 1 <= len(self.columns) <= 2 or len(set(self.columns)) != len(self.columns):
                raise ValueError("projection")
            outputs = self.columns
        else:
            if self.columns:
                raise ValueError("aggregate projection")
            outputs = ("count",) if self.kind == "count" else ("status", "count")
        if self.kind == "count" and self.order:
            raise ValueError("aggregate ordering")
        if len({o.column for o in self.order}) != len(self.order):
            raise ValueError("duplicate ordering")
        if any(o.column not in outputs for o in self.order):
            raise ValueError("ordering scope")
        indices = {p.parameter_index for p in self.predicates}
        if indices != set(range(1, len(self.parameters) + 1)):
            raise ValueError("parameter references")
        for p in self.predicates:
            value = self.parameters[p.parameter_index - 1]
            if (p.column == "id" and type(value) is not int) or (
                p.column == "status" and (type(value) is not str or p.operator not in ("eq", "ne"))
            ):
                raise ValueError("comparison type")
        return self


def result_rows(rows, plan):
    """Validate database output and signal truncation without forwarding driver objects."""
    outputs = (
        plan.columns
        if plan.kind == "rows"
        else (("count",) if plan.kind == "count" else ("status", "count"))
    )
    if type(rows) is not list or len(rows) > plan.limit + 1:
        raise SecurityError("sandbox_result_invalid")
    result = []
    for row in rows:
        if type(row) is not dict or set(row) != set(outputs):
            raise SecurityError("sandbox_result_invalid")
        for key, value in row.items():
            if key == "status":
                valid = type(value) is str and len(value.encode()) <= 4096
            else:
                valid = type(value) is int and -(2**63) <= value < 2**63
                if key == "count":
                    valid = valid and value >= 0
            if not valid:
                raise SecurityError("sandbox_result_invalid")
        result.append(dict(row))
    value = {
        "rows": result[: plan.limit],
        "row_count": min(len(result), plan.limit),
        "truncated": len(result) > plan.limit,
    }
    if len(encoded(value)) > 65536:
        raise SecurityError("sandbox_rows_limit")
    return value


def program_payload(value):
    """Bound JSON depth, nodes and strings before allocating its serialized representation."""
    pending = [(value, 0)]
    visited = 0
    while pending:
        item, depth = pending.pop()
        visited += 1
        if visited > 1000 or depth > 16:
            raise SecurityError("sandbox_output_limit")
        if type(item) is str:
            if len(item) > 16384 or len(item.encode()) > 16384:
                raise SecurityError("sandbox_output_limit")
        elif type(item) in (list, tuple):
            if len(item) > 1000:
                raise SecurityError("sandbox_output_limit")
            pending.extend((v, depth + 1) for v in item)
        elif type(item) is dict:
            if len(item) > 1000 or any(type(k) is not str for k in item):
                raise SecurityError("sandbox_output_limit")
            pending.extend((v, depth + 1) for pair in item.items() for v in pair)
        elif item is None or type(item) in (bool, int):
            pass
        elif type(item) is float and math.isfinite(item):
            pass
        else:
            raise SecurityError("sandbox_output_limit")
    payload = encoded(value)
    if len(payload) > 16384:
        raise SecurityError("sandbox_output_limit")
    return payload


class BoundaryObservation(BoundaryModel):
    """Closed metadata vocabulary; no arbitrary exception or source payload field exists."""

    boundary: Literal[
        "model", "sandbox", "query_policy", "identity", "vault", "database", "cleanup"
    ]
    outcome: Literal["passed", "denied", "failed", "not_attempted", "unresolved", "cancelled"]
    reason: str | None = None

    @field_validator("reason")
    @classmethod
    def closed_reason(cls, value):
        """Accept only known project codes and the sandbox's fixed error catalog."""
        from agent.recovery.models import REASONS

        sandbox = {
            "sandbox_query_denied",
            "sandbox_result_invalid",
            "sandbox_rows_limit",
            "sandbox_database_unavailable",
            "sandbox_calls_limit",
            "sandbox_query_failed",
            "sandbox_closed",
            "sandbox_cancelled",
            "sandbox_unavailable",
            "sandbox_busy",
            "sandbox_output_limit",
            "sandbox_replay_denied",
            "sandbox_execution_failed",
            "sandbox_compute_limit",
            "sandbox_memory_limit",
            "sandbox_recursion_limit",
            "sandbox_wall_limit",
            "sandbox_syntax_invalid",
            "sandbox_not_exercised",
            "identity_expired",
            "policy_denied",
            "contained",
            "database_subject_invalid",
            "database_request_failed",
        }
        if value is not None and value not in sandbox and value not in REASONS:
            raise ValueError("unknown sandbox reason")
        return value

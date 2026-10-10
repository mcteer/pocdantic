"""Strict loading of sanitized, explicitly reviewed acceptance records.

Passing a software test does not automatically make vendor acceptance pass.
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, TypeAdapter, model_validator

CRITERIA = tuple(
    [f"UC1-{i:02}" for i in range(1, 6)]
    + [f"UC2-{i:02}" for i in range(1, 4)]
    + [f"UC3-{i:02}" for i in range(1, 5)]
    + [f"UC4-{i:02}" for i in range(1, 4)]
)


class Evidence(BaseModel):
    model_config = ConfigDict(extra="forbid")
    criterion: str
    status: Literal["blocked", "fail", "pass", "alternative"]
    owner: str
    reason: str
    source: Literal["none", "local", "live"] = "none"
    references: list[str] = Field(default_factory=list)
    reviewer: str | None = None
    observed_at: datetime | None = None

    @model_validator(mode="after")
    def validate_pass(self):
        """Require passing criteria to carry the mandatory review and evidence references."""
        if self.criterion not in CRITERIA:
            raise ValueError("unknown acceptance criterion")
        if self.status in {"pass", "alternative"}:
            if (
                self.source != "live"
                or not self.references
                or not self.reviewer
                or not self.observed_at
            ):
                raise ValueError("live source evidence, observation time and reviewer required")
        return self


def load_evidence(path: str | Path) -> list[Evidence]:
    """Load acceptance JSON and reject duplicate criterion IDs or invalid pass claims."""
    items = TypeAdapter(list[Evidence]).validate_python(json.loads(Path(path).read_text()))
    if sorted(x.criterion for x in items) != sorted(CRITERIA):
        raise ValueError("exactly one evidence record required for each of 15 criteria")
    return items

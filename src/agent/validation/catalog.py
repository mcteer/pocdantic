"""Packaged validation suites constrained to known scenario factories.

Catalog data selects trusted code; it cannot define arbitrary executable scenarios.
"""

import json
from importlib.resources import files
from pathlib import Path

from ..capabilities import CAPABILITY_FACTORIES
from ..evidence import CRITERIA
from .models import Catalog

FACTORIES = frozenset(
    (
        "delegated-read",
        "policy-denial",
        "injection-denial",
        "approval-denied",
        "approval-expired",
        "approval-replay",
        "approval-mutated",
        "cleanup-failure",
        "cleanup-cancelled",
        "delegated-database-read",
        "actor-only-denial",
        "phone-approved",
        "phone-denied",
    )
)


def load_catalog() -> Catalog:
    """Load strict suite definitions and reject duplicate or unsupported scenario mappings."""
    resource = files("agent.validation").joinpath("default_suites.json")
    # Editable installs expose source files; wheels carry the force-included resource.
    content = (
        resource.read_text()
        if resource.is_file()
        else (Path(__file__).parents[3] / "config/validation-suites.json").read_text()
    )
    catalog = Catalog.model_validate(json.loads(content))
    labels = [s.label for s in catalog.suites]
    scenarios = [s for suite in catalog.suites for s in suite.scenarios]
    if len(set(labels)) != len(labels) or len({s.label for s in scenarios}) != len(scenarios):
        raise ValueError("schema_invalid")
    for scenario in scenarios:
        if (
            scenario.factory not in FACTORIES
            or any(c not in CAPABILITY_FACTORIES for c in scenario.required_capabilities)
            or any(c not in CRITERIA for c in scenario.criteria)
        ):
            raise ValueError("schema_invalid")
    return catalog


def select_suite(catalog, label, names, mode, interactive):
    """Validate suite, scenario selection, mode, and explicit phone-interaction
    requirements.

    Return the suite and deterministic selected scenarios before any run is stored
    or any live provider is contacted.
    """
    suite = next((s for s in catalog.suites if s.label == label), None)
    if suite is None or suite.mode != mode:
        raise ValueError("invalid_selection")
    if suite.interactive and not interactive:
        raise ValueError("interactive_required")
    if suite.label == "live-phone" and (not names or len(names) != 1):
        raise ValueError("invalid_selection")
    selection = names if names is not None else [s.label for s in suite.scenarios]
    known = {s.label: s for s in suite.scenarios}
    if not 1 <= len(selection) <= 32 or len(set(selection)) != len(selection):
        raise ValueError("invalid_selection")
    if any(n not in known for n in selection):
        raise ValueError("invalid_selection")
    return suite, tuple(known[n] for n in selection)

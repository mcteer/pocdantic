"""Private simulated-source fixtures; these never establish vendor acceptance."""

from datetime import timedelta
from uuid import uuid4

from agent.gateway.config import bindings, digest, route_policy
from agent.gateway.models import EvidenceBundle, Observation, SpendControl, now
from agent.gateway.probes import cases
from agent.gateway.review import ReviewStore
from agent.settings import Settings


def configuration(protocol="openai-chat", **updates):
    """Return explicit synthetic Gateway settings without reading environment files."""
    values = (
        dict(
            model_mode="gateway",
            model=protocol + ":synthetic",
            gateway_region="us",
            gateway_route="synthetic",
            gateway_models=(protocol + ":synthetic",),
            gateway_api_key="synthetic-private-key",
        )
        | updates
    )
    return Settings(_env_file=None, **values)


def approval(root, settings, *, source="live", signatures=(), administration="reviewed"):
    """Exercise real review validation with simulated native evidence in a temporary root.

    The live label is deliberately simulated input to test approval rules. No fixture file
    is customer evidence or a real assertion about Pydantic enforcement.
    """
    store = ReviewStore(root)
    directory = uuid4().hex
    with store.directory(create=True) as fd:
        import os

        os.mkdir(directory, 0o700, dir_fd=fd)
    folder = root / ".local/gateway" / directory
    native = folder / "synthetic.txt"
    native.write_bytes(b"Synthetic native evidence, never customer acceptance")
    native.chmod(0o600)
    # Evidence fixtures describe an already observed event; a small past offset also
    # avoids wall-clock corrections between construction and strict future-time checks.
    observed_at = now() - timedelta(seconds=1)
    observation = Observation(case_id="administration", disposition="pass", observed_at=observed_at)
    policy = route_policy(settings)
    expected = bindings(settings, policy)
    bundle = EvidenceBundle(
        source=source,
        administration=administration,
        control_revision="0" * 64,
        **expected,
        controls={
            name: observation
            for name in (
                ("routing", "protection", "privacy")
                if administration == "operator-owned"
                else ("routing", "protection", "spending", "privacy")
            )
        },
        observations=tuple(
            Observation(case_id=name, disposition="pass", observed_at=observed_at)
            for name in cases(policy.protocol)
        ),
        manifest={native.name: digest(native.read_bytes())},
        error_signatures=signatures,
        spend=(
            None
            if administration == "operator-owned"
            else SpendControl(daily_usd=1, monthly_usd=10, require_pricing=True, blocking=True)
        ),
    )
    path = folder / "bundle.json"
    path.write_text(bundle.model_dump_json())
    path.chmod(0o600)
    if source == "live":
        store.approve(directory, "synthetic-reviewer", expected, cases(policy.protocol))
    return store, folder, expected

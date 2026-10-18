"""Explicit local review and fixed synthetic probes; no remote administration APIs."""

import json
from pathlib import Path

from .config import bindings, route_policy
from .models import GatewayError
from .probes import cases
from .review import ReviewStore


def add_gateway_parser(subparsers):
    """Expose only names, bounded review inputs and fixed synthetic case identifiers."""
    parser = subparsers.add_parser("gateway", help="Inspect and review model Gateway controls")
    commands = parser.add_subparsers(dest="gateway_command", required=True)
    status = commands.add_parser("status", help="Read local controls status without dispatch")
    status.add_argument("--format", choices=("text", "json"), default="text")
    test = commands.add_parser("probe", help="Send one fixed synthetic case; may incur model spend")
    test.add_argument("--case", required=True)
    test.add_argument("--format", choices=("text", "json"), default="text")
    review = commands.add_parser("review", help="Explicitly approve or reject local controls")
    review.add_argument("--decision", choices=("approve", "reject"), required=True)
    review.add_argument("--reviewer", required=True)
    review.add_argument("--evidence")
    review.add_argument("--valid-hours", type=float, default=24)


async def execute_gateway(args):
    """Produce closed output; reject works even when Settings or evidence cannot be loaded."""
    from agent.model_config import selected_model
    from agent.settings import Settings

    store = ReviewStore()
    try:
        if args.gateway_command == "review" and args.decision == "reject":
            store.reject(args.reviewer)
            print(json.dumps({"state": "rejected"}))
            return 0
        settings = Settings()
        policy = route_policy(settings)
        if policy is None:
            if args.gateway_command != "status":
                raise GatewayError("gateway_configuration_invalid")
            print(json.dumps({"state": "legacy-direct"}))
            return 0
        expected = bindings(settings, policy)
        if args.gateway_command == "status":
            review = store.admit(expected)
            attempts = store.attempts()
            print(
                json.dumps(
                    {
                        "state": "protected-reviewed",
                        "administration": review.administration,
                        "attempts": len(attempts),
                        "unknown_attempts": sum(e.stage == "unknown" for e in attempts),
                    }
                )
            )
            return 0
        if args.gateway_command == "review":
            if not args.evidence:
                raise GatewayError("gateway_review_required")
            path = Path(args.evidence).absolute()
            if path.parent != store.root / ".local/gateway":
                raise GatewayError("gateway_review_required")
            store.approve(
                path.name, args.reviewer, expected, cases(policy.protocol), args.valid_hours
            )
            print(json.dumps({"state": "protected-reviewed"}))
            return 0
        from .probes import probe

        model = selected_model(settings)
        try:
            result = await probe(settings, model, args.case)
            print(json.dumps(result))
            return 0 if result["disposition"] == "pass" else 3
        finally:
            await model._agent_gateway.aclose()
    except GatewayError as error:
        code = str(error)
        print(json.dumps({"state": "blocked", "reason_code": code}))
        return 3 if code == "gateway_review_required" else 2
    except Exception:
        print(json.dumps({"state": "blocked", "reason_code": "gateway_configuration_invalid"}))
        return 2

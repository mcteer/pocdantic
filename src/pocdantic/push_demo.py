import json
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import httpx

from .approval import ApprovalStore
from .capabilities import Dependencies, execute_simulated_write
from .oauth import OAuthClient
from .probe import oauth_config
from .schemas import Action, Principal
from .security import Audit, Containment, Policy, SecurityError
from .settings import Settings
from .verify import VerifyClient, identifier


async def push_demo(settings: Settings) -> dict:
    """Isolated possession/approval test; never authorizes a production agent session."""
    if not settings.verify_tenant_url:
        raise SecurityError("verify_tenant_missing")
    async with httpx.AsyncClient(timeout=15, follow_redirects=False) as http:
        token = await OAuthClient(oauth_config(settings, api=True), http).client_credentials()
        client = VerifyClient(settings.verify_tenant_url, token.access_token, http)
        inventory = await client.authenticators()
        devices = [
            item
            for item in inventory.get("authenticators", [])
            if item.get("enabled") and item.get("state") == "ACTIVE"
        ]
        if settings.verify_authenticator_id:
            devices = [item for item in devices if item["id"] == settings.verify_authenticator_id]
        if settings.verify_user_id:
            devices = [item for item in devices if item["owner"] == settings.verify_user_id]
        if len(devices) != 1:
            raise SecurityError("verify_select_exactly_one_device")
        device = devices[0]
        signature_data = await client.request("GET", "v1.0/authnmethods/signatures")
        factors = [
            item
            for item in signature_data.get("signatures", [])
            if item.get("enabled")
            and item.get("validated")
            and item.get("owner") == device["owner"]
            and item.get("attributes", {}).get("authenticatorId") == device["id"]
            and item.get("subType") == "userPresence"
        ]
        if len(factors) != 1:
            raise SecurityError("verify_signing_factor_missing")
        store, audit = ApprovalStore(), Audit()
        run_id = uuid4()
        action = Action(
            operation="infra.write", resource="sandbox/demo", parameters={"change": "restart"}
        )
        principal = Principal(
            issuer=settings.verify_tenant_url,
            subject=device["owner"],
            scopes=frozenset({"infra:write"}),
        )
        deps = Dependencies(
            principal, uuid4(), run_id, "parent", "push-demo", Policy(), Containment(), audit, store
        )
        deps.authorize(action)
        approval = store.create(principal.subject, run_id, action)
        transaction_id = await client.initiate(
            identifier(device["id"]), factors[0]["id"], approval, action
        )
        print(
            json.dumps(
                {
                    "status": "push_sent",
                    "target": "sandbox/demo",
                    "mode": "simulated",
                    "approval_id": str(approval.id),
                }
            ),
            flush=True,
        )
        approved = await client.wait_for_decision(device["id"], transaction_id, approval, store)
        result = (
            execute_simulated_write(deps, approval.id, action).model_dump(mode="json")
            if approved
            else {"status": "denied_or_expired"}
        )
        evidence = {
            "observed_at": datetime.now(UTC).isoformat(),
            "source": "live_verify",
            "mode": "simulated_write",
            "result": result,
            "audit": audit.events,
        }
        directory = Path(".local")
        directory.mkdir(mode=0o700, exist_ok=True)
        file = directory / "push-evidence.json"
        file.write_text(json.dumps(evidence, indent=2))
        file.chmod(0o600)
        return evidence

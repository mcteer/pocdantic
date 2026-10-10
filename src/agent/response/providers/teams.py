"""URL-only Teams Workflows notices with strictly generated safe card fields.

The enrolled workflow URL is a capability secret. It is used only for an explicit
notice action, never readiness/status/readback; HTTP acceptance is not delivery.
"""

import hashlib
from urllib.parse import urlsplit

from agent.validation.models import canonical

from .common import Result, acknowledged, request
from .models import require


def destination_digest(url, origin):
    """Fence a workflow by fixed host/path independently of its rotating URL signature."""
    parts = urlsplit(url)
    require(
        parts.scheme == "https"
        and parts.hostname
        and not parts.username
        and not parts.password
        and not parts.fragment
        and f"https://{parts.netloc}" == origin.rstrip("/"),
        "destination_invalid",
    )
    return hashlib.sha256(f"{origin.rstrip('/')}{parts.path}".encode()).hexdigest()


class TeamsAdapter:
    """Send one allowlisted advisory notice without actor credentials or remote text."""

    def __init__(self, http, secrets):
        """Retain private capability material and bounded injected HTTP transport."""
        self.http, self.secrets = http, secrets

    async def execute(self, action, *, read_only=False):
        """POST one generated card; independent imported receipt alone proves delivery."""
        require(not read_only, "unsupported")
        binding = action.binding
        require(binding.owner_confirmed and action.notice_id is not None, "mapping_missing")
        secret = self.secrets.get(binding.secret_alias)
        require(secret is not None, "missing_authority")
        url = secret.get_secret_value()
        parts = urlsplit(url)
        require(
            parts.scheme == "https"
            and parts.hostname
            and not parts.username
            and not parts.password
            and not parts.fragment
            and f"{parts.scheme}://{parts.netloc}" == binding.origin.rstrip("/"),
            "destination_invalid",
        )
        require(
            binding.destination_digest in {None, destination_digest(url, binding.origin)},
            "provider_policy_changed",
        )
        card = {
            "type": "message",
            "attachments": [
                {
                    "contentType": "application/vnd.microsoft.card.adaptive",
                    "content": {
                        "type": "AdaptiveCard",
                        "version": "1.4",
                        "body": [
                            {"type": "TextBlock", "text": "Incident response notice"},
                            {
                                "type": "FactSet",
                                "facts": [
                                    {"title": "Notice", "value": str(action.notice_id)},
                                    {"title": "Incident", "value": str(action.incidents[0])},
                                    {"title": "Scope", "value": action.scope},
                                    {"title": "Outcome", "value": "contained"},
                                ],
                            },
                        ],
                    },
                }
            ],
        }
        require(len(canonical(card)) <= 8192, "provider_capacity")
        status, _, fingerprint = await request(self.http, "POST", url, body=card)
        result = acknowledged(status, fingerprint)
        if result.state != "acknowledged":
            return result
        return Result(
            reason="notification_accepted", path="notification", source_digest=fingerprint
        )

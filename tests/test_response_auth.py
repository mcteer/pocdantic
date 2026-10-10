"""Response JWTs cannot borrow task or browser authority."""

import time

import httpx
import pytest
from pydantic import SecretStr

from agent.recovery.store import environment_digest
from agent.response.auth import SourceAuthenticator
from agent.response.models import ResponseError, SourcePolicy


@pytest.mark.parametrize(
    "change",
    [
        {"aud": "resource"},
        {"sub": "other"},
        {"scope": "tickets:read"},
        {"exp": 0},
        {"iat": int(time.time()) - 301},
        {"exp": int(time.time()) + 600},
    ],
)
async def test_reject_wrong_authority(workspace_settings, identity_provider, change):
    policy = SourcePolicy(
        intake_mode="relay",
        sources=[
            {
                "alias": "relay-source",
                "issuer": workspace_settings.oauth_issuer,
                "subject": "relay",
                "allowed_scopes": ["definition"],
            }
        ],
        audience="response",
        workload_definition=workspace_settings.workload_definition,
        issuer=workspace_settings.oauth_issuer,
        environment_digest=environment_digest(workspace_settings),
    )
    async with httpx.AsyncClient(transport=httpx.MockTransport(identity_provider.handle)) as http:
        auth = SourceAuthenticator(workspace_settings, policy, http)
        token = (
            identity_provider.access(
                sub="relay",
                aud="response",
                scope="response:submit",
                exp=int(time.time()) + 200,
                **change,
            )
            if not set(change) & {"sub", "aud", "scope", "exp"}
            else identity_provider.access(
                **(
                    {
                        "sub": "relay",
                        "aud": "response",
                        "scope": "response:submit",
                        "exp": int(time.time()) + 200,
                    }
                    | change
                )
            )
        )
        with pytest.raises(ResponseError, match="source_invalid"):
            await auth.verify(SecretStr(token))


async def test_accept_exact_source(workspace_settings, identity_provider):
    policy = SourcePolicy(
        intake_mode="relay",
        sources=[
            {
                "alias": "relay-source",
                "issuer": workspace_settings.oauth_issuer,
                "subject": "relay",
                "allowed_scopes": ["definition"],
            }
        ],
        audience="response",
        workload_definition=workspace_settings.workload_definition,
        issuer=workspace_settings.oauth_issuer,
        environment_digest=environment_digest(workspace_settings),
    )
    async with httpx.AsyncClient(transport=httpx.MockTransport(identity_provider.handle)) as http:
        source = await SourceAuthenticator(workspace_settings, policy, http).verify(
            SecretStr(
                identity_provider.access(
                    sub="relay", aud="response", scope="response:submit", exp=int(time.time()) + 200
                )
            )
        )
        assert source.alias == "relay-source"

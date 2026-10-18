"""CLI review/probe admission cannot act as arbitrary model or credential tooling."""

import argparse
import json

import pytest

from agent.gateway.commands import add_gateway_parser, execute_gateway
from agent.gateway.probes import cases


def test_probe_parser_has_no_prompt_or_file_override():
    """Only a named fixed case can reach the synthetic probe entry point."""
    parser = argparse.ArgumentParser()
    add_gateway_parser(parser.add_subparsers(dest="command"))
    with pytest.raises(SystemExit):
        parser.parse_args(["gateway", "probe", "--case", "synthetic", "--prompt", "private"])
    assert len(cases("openai-chat")) == 100


@pytest.mark.asyncio
async def test_rejection_does_not_load_broken_settings(tmp_path, monkeypatch, capsys):
    """Malformed live inputs cannot disable the local rejection control."""
    from agent import settings

    monkeypatch.chdir(tmp_path)

    def forbidden(*args, **kwargs):
        pytest.fail("rejection tried to load live configuration")

    monkeypatch.setattr(settings, "Settings", forbidden)
    args = argparse.Namespace(gateway_command="review", decision="reject", reviewer="operator")
    assert await execute_gateway(args) == 0
    assert json.loads(capsys.readouterr().out) == {"state": "rejected"}


@pytest.mark.asyncio
async def test_invalid_case_never_sends(tmp_path):
    """A supplied case name cannot introduce a new prompt or tool."""
    import httpx2

    from agent.gateway.config import route_policy
    from agent.gateway.models import GatewayError
    from agent.gateway.probes import probe
    from agent.gateway.review import ReviewStore
    from agent.model_config import gateway_model
    from tests.gateway_support import configuration

    settings = configuration()

    async def fail(request):
        pytest.fail("invalid case dispatched")

    model = gateway_model(
        settings,
        route_policy(settings),
        inner=httpx2.MockTransport(fail),
        store=ReviewStore(tmp_path),
    )
    try:
        with pytest.raises(GatewayError):
            await probe(settings, model, "custom-prompt")
    finally:
        await model._agent_gateway.aclose()
    assert not (tmp_path / ".local").exists()

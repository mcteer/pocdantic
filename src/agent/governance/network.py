"""Whole-call provider bounds, including slow streaming and private JSON parsing.

HTTPX's I/O timeout resets between chunks. Governance adds a total deadline so a peer
cannot prolong one call by sending a byte just before each read timeout. Response size,
redirect and compression checks remain in the shared trusted adapter.
"""

import asyncio

from agent.response.providers.common import request as bounded_request

from .models import GovernanceError

BUDGET = 10


async def request(http, method, url, *, headers=None, body=None):
    """Return bounded private status/body/digest or a closed failure, never upstream text."""
    try:
        async with asyncio.timeout(BUDGET):
            return await bounded_request(http, method, url, headers=headers, body=body)
    except asyncio.CancelledError:
        raise
    except Exception:
        raise GovernanceError("effect_uncertain") from None

"""Offline tests for the sentinel MCP tools.

The tools delegate all reasoning to the client's LLM via MCP sampling, so we
drive them through FastMCP's in-memory ``Client`` with a mocked
``sampling_handler`` that returns canned text. No network or live model is used.
"""

import pytest
from fastmcp import Client
from mcp.shared.exceptions import McpError
from mcp.types import ErrorData

from sentinel.server import (
    ANALYSIS_SYSTEM_PROMPT,
    DISCOVERY_SYSTEM_PROMPT,
    SAMPLING_SPEC_URL,
    mcp,
)

DISCOVERY_TEXT = "- filesystem: reads and writes local files\n- http: sends outbound requests"
ANALYSIS_TEXT = "RISK-001 (High): filesystem + http form a data-exfiltration path."


def make_handler(discovery=DISCOVERY_TEXT, analysis=ANALYSIS_TEXT):
    """Build a sampling handler that returns canned text and records its calls.

    The handler picks its response from the system prompt so it works for both
    the single-step ``discover`` flow and the two-step ``assess`` flow.
    """
    calls = []

    async def handler(messages, params, ctx):
        calls.append(params.systemPrompt)
        if params.systemPrompt == ANALYSIS_SYSTEM_PROMPT:
            return analysis
        return discovery

    handler.calls = calls
    return handler


def _handler_raising(exc: Exception):
    async def handler(messages, params, ctx):
        raise exc

    return handler


async def test_assess_happy_path():
    handler = make_handler()
    async with Client(mcp, sampling_handler=handler) as client:
        result = await client.call_tool("assess", {})

    assert result.data == ANALYSIS_TEXT
    # assess runs discovery then analysis: two sampling round-trips.
    assert len(handler.calls) == 2
    assert handler.calls[0] == DISCOVERY_SYSTEM_PROMPT
    assert handler.calls[1] == ANALYSIS_SYSTEM_PROMPT


async def test_discover_happy_path():
    handler = make_handler()
    async with Client(mcp, sampling_handler=handler) as client:
        result = await client.call_tool("discover", {})

    assert result.data == DISCOVERY_TEXT
    # discover is a single sampling round-trip.
    assert len(handler.calls) == 1
    assert handler.calls[0] == DISCOVERY_SYSTEM_PROMPT


async def test_assess_empty_discovery_fallback():
    handler = make_handler(discovery="   ")
    async with Client(mcp, sampling_handler=handler) as client:
        result = await client.call_tool("assess", {})

    assert result.data == (
        "Could not discover any MCP tools. The client may not support sampling."
    )
    # Falls back after discovery; analysis is never attempted.
    assert len(handler.calls) == 1


async def test_discover_empty_fallback():
    handler = make_handler(discovery="")
    async with Client(mcp, sampling_handler=handler) as client:
        result = await client.call_tool("discover", {})

    assert result.data == "Could not discover any MCP tools."


async def test_tools_registered():
    async with Client(mcp) as client:
        tools = await client.list_tools()

    names = {tool.name for tool in tools}
    assert {"assess", "discover"} <= names


@pytest.mark.parametrize("tool", ["assess", "discover"])
async def test_sampling_failure_returns_friendly_message(tool):
    # A handler that raises surfaces to ctx.sample as an McpError inside the tool.
    handler = _handler_raising(
        McpError(ErrorData(code=-32603, message="sampling not supported"))
    )
    async with Client(mcp, sampling_handler=handler) as client:
        result = await client.call_tool(tool, {})

    assert "Sentinel requires an MCP client that supports sampling" in result.data
    assert SAMPLING_SPEC_URL in result.data


@pytest.mark.parametrize("tool", ["assess", "discover"])
async def test_unsupported_sampling_returns_friendly_message(tool):
    # No sampling_handler at all: ctx.sample raises "Client does not support sampling".
    async with Client(mcp) as client:
        result = await client.call_tool(tool, {})

    assert "Sentinel requires an MCP client that supports sampling" in result.data
    assert SAMPLING_SPEC_URL in result.data

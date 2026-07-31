"""Offline tests for the sentinel MCP tool.

``assess`` is a pure rule engine over a caller-supplied inventory, so every test
drives the real tool through FastMCP's in-memory ``Client`` and asserts exact
values. No model, no sampling, no network.
"""

from itertools import permutations

import pytest
from fastmcp import Client
from fastmcp.exceptions import ToolError

from sentinel.server import LIMITATIONS, NO_FINDINGS_SUMMARY, mcp


async def assess(inventory):
    """Call the real ``assess`` tool and return its structured result."""
    async with Client(mcp) as client:
        result = await client.call_tool("assess", {"tool_inventory": inventory})
    return result.structured_content


async def test_only_assess_is_registered_and_takes_a_structured_inventory():
    async with Client(mcp) as client:
        tools = await client.list_tools()

    assert [tool.name for tool in tools] == ["assess"]

    schema = tools[0].inputSchema
    assert schema["required"] == ["tool_inventory"]
    # No injected Context parameter, and nothing else to pass.
    assert list(schema["properties"]) == ["tool_inventory"]

    entry = schema["properties"]["tool_inventory"]["items"]
    assert entry["required"] == ["name"]
    assert entry["properties"]["capabilities"]["items"]["enum"] == [
        "sensitive-read",
        "outbound-write",
        "untrusted-ingest",
        "privileged-action",
    ]


async def test_unknown_capability_fails_validation():
    with pytest.raises(ToolError) as excinfo:
        await assess([{"name": "mystery", "capabilities": ["root-access"]}])

    assert "root-access" in str(excinfo.value)


async def test_unknown_entry_field_fails_validation():
    with pytest.raises(ToolError):
        await assess([{"name": "db", "capabilities": [], "severity": "critical"}])


async def test_sensitive_read_with_outbound_write_reports_exfiltration():
    result = await assess(
        [
            {"name": "db", "capabilities": ["sensitive-read"]},
            {"name": "http", "capabilities": ["outbound-write"]},
        ]
    )

    assert result == {
        "findings": [
            {
                "id": "RISK-001",
                "category": "data-exfiltration",
                "severity": "high",
                "tools": ["db", "http"],
                "description": (
                    "'db' reads sensitive data and 'http' sends data outside the "
                    "session. Together they form an exfiltration path: anything the "
                    "first tool reads can leave through the second without further "
                    "approval."
                ),
                "recommendation": (
                    "Confirm 'db' and 'http' genuinely need to be enabled together. "
                    "If they do, scope 'db' to the narrowest data it needs and "
                    "require explicit approval for 'http' calls."
                ),
            }
        ],
        "summary": (
            "1 finding(s): 1 data-exfiltration pairing(s) and 0 prompt-injection "
            "pairing(s)."
        ),
        "limitations": LIMITATIONS,
    }


async def test_untrusted_ingest_with_privileged_action_reports_injection():
    result = await assess(
        [
            {"name": "fetch", "capabilities": ["untrusted-ingest"]},
            {"name": "shell", "capabilities": ["privileged-action"]},
        ]
    )

    assert result == {
        "findings": [
            {
                "id": "RISK-001",
                "category": "prompt-injection",
                "severity": "high",
                "tools": ["fetch", "shell"],
                "description": (
                    "'fetch' ingests content controlled by someone else and 'shell' "
                    "takes privileged actions. Instructions hidden in what the first "
                    "tool fetches can steer the model into calling the second."
                ),
                "recommendation": (
                    "Treat everything 'fetch' returns as untrusted data rather than "
                    "instructions, and require explicit approval for 'shell' calls "
                    "that follow it."
                ),
            }
        ],
        "summary": (
            "1 finding(s): 0 data-exfiltration pairing(s) and 1 prompt-injection "
            "pairing(s)."
        ),
        "limitations": LIMITATIONS,
    }


async def test_single_tool_carrying_both_sides_of_a_pairing_is_reported():
    result = await assess(
        [
            {
                "name": "mail",
                "capabilities": [
                    "sensitive-read",
                    "outbound-write",
                    "untrusted-ingest",
                    "privileged-action",
                ],
            }
        ]
    )

    assert result["findings"] == [
        {
            "id": "RISK-001",
            "category": "data-exfiltration",
            "severity": "high",
            "tools": ["mail"],
            "description": (
                "'mail' both reads sensitive data and sends data outside the "
                "session, so one call chain within this single tool is enough to "
                "exfiltrate what it reads."
            ),
            "recommendation": (
                "Scope 'mail' to the narrowest data it needs, and require explicit "
                "approval before it sends anything outbound."
            ),
        },
        {
            "id": "RISK-002",
            "category": "prompt-injection",
            "severity": "high",
            "tools": ["mail"],
            "description": (
                "'mail' both ingests untrusted content and takes privileged "
                "actions, so content it pulls in can steer its own later calls."
            ),
            "recommendation": (
                "Treat everything 'mail' returns as untrusted data rather than "
                "instructions, and require explicit approval before it acts on that "
                "content."
            ),
        },
    ]
    assert result["summary"] == (
        "2 finding(s): 1 data-exfiltration pairing(s) and 1 prompt-injection "
        "pairing(s)."
    )


@pytest.mark.parametrize(
    "inventory",
    [
        pytest.param([], id="empty"),
        pytest.param(
            [{"name": "notes", "capabilities": []}],
            id="untagged-tool",
        ),
        pytest.param(
            [
                {"name": "db", "capabilities": ["sensitive-read"]},
                {"name": "fetch", "capabilities": ["untrusted-ingest"]},
            ],
            id="only-source-halves",
        ),
        pytest.param(
            [
                {"name": "http", "capabilities": ["outbound-write"]},
                {"name": "shell", "capabilities": ["privileged-action"]},
            ],
            id="only-sink-halves",
        ),
        pytest.param(
            [
                {"name": "db", "capabilities": ["sensitive-read"]},
                {"name": "shell", "capabilities": ["privileged-action"]},
            ],
            id="mismatched-halves",
        ),
    ],
)
async def test_incomplete_pairings_return_a_stable_no_findings_result(inventory):
    assert await assess(inventory) == {
        "findings": [],
        "summary": NO_FINDINGS_SUMMARY,
        "limitations": LIMITATIONS,
    }


INVENTORY = [
    {"name": "db", "capabilities": ["sensitive-read"]},
    {"name": "fetch", "capabilities": ["untrusted-ingest", "sensitive-read"]},
    {"name": "http", "capabilities": ["outbound-write"]},
    {"name": "shell", "capabilities": ["privileged-action", "outbound-write"]},
]


async def test_findings_do_not_depend_on_inventory_order():
    expected = await assess(INVENTORY)

    # Four tools => 24 orderings; every one must produce byte-identical output.
    for ordering in permutations(INVENTORY):
        assert await assess(list(ordering)) == expected

    assert [(f["id"], f["category"], f["tools"]) for f in expected["findings"]] == [
        ("RISK-001", "data-exfiltration", ["db", "http"]),
        ("RISK-002", "data-exfiltration", ["db", "shell"]),
        ("RISK-003", "data-exfiltration", ["fetch", "http"]),
        ("RISK-004", "data-exfiltration", ["fetch", "shell"]),
        ("RISK-005", "prompt-injection", ["fetch", "shell"]),
    ]


async def test_duplicate_capabilities_and_entries_do_not_duplicate_findings():
    baseline = await assess(
        [
            {"name": "db", "capabilities": ["sensitive-read"]},
            {"name": "http", "capabilities": ["outbound-write"]},
        ]
    )

    noisy = await assess(
        [
            {"name": "db", "capabilities": ["sensitive-read", "sensitive-read"]},
            {"name": "db", "capabilities": ["sensitive-read"]},
            {"name": "http", "capabilities": ["outbound-write", "outbound-write"]},
        ]
    )

    assert noisy == baseline


async def test_capability_ordering_within_a_tool_is_irrelevant():
    forward = await assess([{"name": "mail", "capabilities": ["sensitive-read", "outbound-write"]}])
    reverse = await assess([{"name": "mail", "capabilities": ["outbound-write", "sensitive-read"]}])

    assert forward == reverse


async def test_result_documents_the_self_report_limitation():
    result = await assess([])

    assert "self-report" in result["limitations"]
    assert "not a clean bill of health" in result["limitations"]
    assert "in-session advisor" in result["limitations"]

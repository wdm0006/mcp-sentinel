"""Offline tests for the sentinel MCP tool.

``assess`` is a pure rule engine over a caller-supplied inventory, so every test
drives the real tool through FastMCP's in-memory ``Client`` and asserts exact
values. No model, no sampling, no network.
"""

import json
import re
import tomllib
from itertools import permutations
from pathlib import Path

import pytest
from fastmcp import Client
from fastmcp.exceptions import ToolError

from sentinel.server import (
    CAPABILITY_DESCRIPTIONS,
    EMPTY_INVENTORY_SUMMARY,
    EXFILTRATION_CATEGORY,
    EXFILTRATION_SEVERITY,
    INJECTION_CATEGORY,
    INJECTION_SEVERITY,
    LIMITATIONS,
    NO_FINDINGS_SUMMARY,
    UNTAGGED_INVENTORY_SUMMARY,
    Capability,
    mcp,
)


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


async def test_every_capability_meaning_reaches_the_calling_model():
    async with Client(mcp) as client:
        tools = await client.list_tools()

    entry = tools[0].inputSchema["properties"]["tool_inventory"]["items"]
    field_description = entry["properties"]["capabilities"]["description"]

    for capability in Capability:
        meaning = CAPABILITY_DESCRIPTIONS[capability]
        # The schema the model is handed must carry the meaning, not just the value.
        assert capability.value in field_description
        assert meaning in field_description
        # And so must the tool description it reads before tagging anything.
        assert capability.value in tools[0].description
        assert meaning in tools[0].description


async def test_every_assessment_field_description_reaches_the_calling_model():
    async with Client(mcp) as client:
        tools = await client.list_tools()

    schema = tools[0].outputSchema
    assessment_fields = schema["properties"]
    for field in ("findings", "summary", "limitations"):
        assert assessment_fields[field]["description"]

    limitations_description = assessment_fields["limitations"]["description"]
    assert "relayed to the user together with the findings" in limitations_description

    finding_schema = assessment_fields["findings"]["items"]
    if "$ref" in finding_schema:
        finding_schema = schema["$defs"][finding_schema["$ref"].rsplit("/", 1)[-1]]
    finding_fields = finding_schema["properties"]
    for field in ("id", "category", "severity", "tools", "description", "recommendation"):
        assert finding_fields[field]["description"]

    category_description = finding_fields["category"]["description"]
    assert EXFILTRATION_CATEGORY in category_description
    assert INJECTION_CATEGORY in category_description

    severity_description = finding_fields["severity"]["description"]
    assert EXFILTRATION_SEVERITY in severity_description
    assert INJECTION_SEVERITY in severity_description
    assert "fixed" in severity_description.lower()


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
                    "Sensitive-read tools 'db' can pass what they read to outbound-write "
                    "tools 'http' without further approval."
                ),
                "recommendation": (
                    "Confirm the sensitive-read tools 'db' and outbound-write tools "
                    "'http' genuinely need to be enabled together. Scope each reader to "
                    "the narrowest data it "
                    "needs and require explicit approval for outbound calls."
                ),
            }
        ],
        "summary": (
            "1 finding(s): 1 data-exfiltration risk(s) and 0 prompt-injection risk(s)."
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
                    "Untrusted-ingest tools 'fetch' can expose privileged-action "
                    "tools 'shell' to hidden instructions that steer later calls."
                ),
                "recommendation": (
                    "Treat everything returned by 'fetch' as untrusted data rather "
                    "than instructions, and require explicit approval for calls to "
                    "'shell' that follow it."
                ),
            }
        ],
        "summary": (
            "1 finding(s): 0 data-exfiltration risk(s) and 1 prompt-injection risk(s)."
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
        "2 finding(s): 1 data-exfiltration risk(s) and 1 prompt-injection risk(s)."
    )


@pytest.mark.parametrize(
    "inventory",
    [
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


async def test_empty_inventory_says_nothing_was_submitted():
    """An empty inventory is a caller failure, not a clean result."""
    result = await assess([])

    assert result == {
        "findings": [],
        "summary": EMPTY_INVENTORY_SUMMARY,
        "limitations": LIMITATIONS,
    }
    # The exact string is what the assistant relays, so it must not read as an all-clear.
    assert "No risky capability pairing found" not in result["summary"]


async def test_inventory_with_no_tagged_capability_says_nothing_was_tagged():
    """Tools listed but never tagged means the analysis never ran."""
    result = await assess(
        [
            {"name": "notes", "capabilities": []},
            {"name": "calc", "capabilities": []},
        ]
    )

    assert result == {
        "findings": [],
        "summary": UNTAGGED_INVENTORY_SUMMARY,
        "limitations": LIMITATIONS,
    }
    assert "No risky capability pairing found" not in result["summary"]
    # And distinct from the empty-inventory case, which is a different caller failure.
    assert result["summary"] != EMPTY_INVENTORY_SUMMARY


async def test_one_tagged_tool_among_untagged_ones_uses_the_pairing_summary():
    """A single tagged tool means the pairings really were evaluated and came up short."""
    result = await assess(
        [
            {"name": "notes", "capabilities": []},
            {"name": "db", "capabilities": ["sensitive-read"]},
        ]
    )

    assert result["findings"] == []
    assert result["summary"] == NO_FINDINGS_SUMMARY


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
        ("RISK-001", "data-exfiltration", ["db", "fetch", "http", "shell"]),
        ("RISK-002", "prompt-injection", ["fetch", "shell"]),
    ]


async def test_rule_groups_multiple_sources_and_sinks_into_one_finding():
    result = await assess(
        [
            {"name": "vault", "capabilities": ["sensitive-read"]},
            {"name": "db", "capabilities": ["sensitive-read"]},
            {"name": "slack", "capabilities": ["outbound-write"]},
            {"name": "http", "capabilities": ["outbound-write"]},
        ]
    )

    assert result["findings"] == [
        {
            "id": "RISK-001",
            "category": "data-exfiltration",
            "severity": "high",
            "tools": ["db", "http", "slack", "vault"],
            "description": (
                "Sensitive-read tools 'db' and 'vault' can pass what they read to "
                "outbound-write tools 'http' and 'slack' without further approval."
            ),
            "recommendation": (
                "Confirm the sensitive-read tools 'db' and 'vault' and outbound-write "
                "tools 'http' and 'slack' genuinely need to be enabled together. Scope "
                "each reader to the narrowest data it needs and require explicit "
                "approval for outbound calls."
            ),
        }
    ]


async def test_self_path_is_called_out_inside_a_grouped_rule_finding():
    result = await assess(
        [
            {"name": "mail", "capabilities": ["sensitive-read", "outbound-write"]},
            {"name": "vault", "capabilities": ["sensitive-read"]},
            {"name": "http", "capabilities": ["outbound-write"]},
        ]
    )

    assert result["findings"] == [
        {
            "id": "RISK-001",
            "category": "data-exfiltration",
            "severity": "high",
            "tools": ["http", "mail", "vault"],
            "description": (
                "Sensitive-read tools 'mail' and 'vault' can pass what they read to "
                "outbound-write tools 'http' and 'mail' without further approval. Any tool "
                "appearing in both roles ('mail') can form one call chain within that "
                "single tool."
            ),
            "recommendation": (
                "Confirm the sensitive-read tools 'mail' and 'vault' and outbound-write "
                "tools 'http' and 'mail' genuinely need to be enabled together. Scope "
                "each reader to the narrowest data it needs and require explicit "
                "approval for outbound calls."
            ),
        }
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


REPO_ROOT = Path(__file__).resolve().parents[1]


async def test_readme_example_matches_assess_output_exactly():
    readme = (REPO_ROOT / "README.md").read_text()
    call = re.search(r"### Example call\n\n```json\n(.*?)\n```", readme, re.DOTALL)
    documented = re.search(r"### Example result\n\n```json\n(.*?)\n```", readme, re.DOTALL)

    assert call is not None
    assert documented is not None
    payload = json.loads(call.group(1))
    assert await assess(payload["tool_inventory"]) == json.loads(documented.group(1))


def _executable_run_by(args):
    """The executable ``uvx`` runs: the token after ``--from <ref>``, or the bare argument."""
    if args[:1] == ["--from"]:
        args = args[2:]
    return args[0] if args else None


def _readme_uvx_executables(readme):
    """Every executable name a ``uvx`` invocation in the README resolves to."""
    executables = []
    for language, body in re.findall(r"```(\w*)\n(.*?)```", readme, re.DOTALL):
        if language == "json":
            document = json.loads(body)
            for server in document.get("mcpServers", {}).values():
                if server.get("command") == "uvx":
                    executables.append(_executable_run_by(server.get("args", [])))
        else:
            for line in body.splitlines():
                tokens = line.split()
                if tokens[:1] == ["uvx"]:
                    executables.append(_executable_run_by(tokens[1:]))
    return executables


def test_readme_uvx_commands_name_a_declared_console_script():
    """The launch commands must resolve to an executable the package actually ships."""
    readme = (REPO_ROOT / "README.md").read_text()
    pyproject = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text())
    scripts = sorted(pyproject["project"]["scripts"])

    executables = _readme_uvx_executables(readme)

    assert executables, "the README should document at least one uvx launch command"
    for executable in executables:
        assert executable in scripts, (
            f"README runs `uvx ... {executable}`, but [project.scripts] declares {scripts}"
        )

"""
Sentinel - MCP security advisor for the tool surface of an agent session.

A single-file MCP server with one deterministic tool. The calling model passes
in the tools it can reach, tagged with capability categories, and Sentinel
reports the capability pairings that create risk: sensitive reads next to
outbound writes, untrusted ingestion next to privileged actions.

No sampling, no model provider, no API key, no persistence.
"""

from enum import Enum

from fastmcp import FastMCP
from pydantic import BaseModel, ConfigDict, Field

mcp = FastMCP(
    "sentinel",
    instructions=(
        "Sentinel analyzes the security posture of an MCP tool surface. "
        "Call the assess tool with the tools you can reach, each tagged with "
        "its capability categories, to get deterministic findings about risky "
        "capability pairings."
    ),
)


class Capability(str, Enum):
    """The capability categories Sentinel reasons about.

    Deliberately narrow: these four are the ones that pair into the two flows
    Sentinel checks. Anything outside this set is rejected by validation
    rather than silently ignored.
    """

    SENSITIVE_READ = "sensitive-read"
    OUTBOUND_WRITE = "outbound-write"
    UNTRUSTED_INGEST = "untrusted-ingest"
    PRIVILEGED_ACTION = "privileged-action"


CAPABILITY_DESCRIPTIONS = {
    Capability.SENSITIVE_READ: (
        "reads data the session should not leak (files, databases, mail, secrets)"
    ),
    Capability.OUTBOUND_WRITE: (
        "sends data outside the session (HTTP requests, email, chat, uploads)"
    ),
    Capability.UNTRUSTED_INGEST: (
        "pulls in content controlled by someone else (web pages, inboxes, issue "
        "trackers, shared files)"
    ),
    Capability.PRIVILEGED_ACTION: (
        "takes actions with consequences (code execution, writes, deployments, "
        "permission changes)"
    ),
}


class ToolEntry(BaseModel):
    """One tool in the session, with the capability categories it carries."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(description="The tool's name as the client exposes it.")
    capabilities: list[Capability] = Field(
        default_factory=list,
        description=(
            "Capability categories this tool carries. Allowed values: "
            "sensitive-read, outbound-write, untrusted-ingest, privileged-action."
        ),
    )


class Finding(BaseModel):
    """A single capability-pairing finding."""

    id: str
    category: str
    severity: str
    tools: list[str]
    description: str
    recommendation: str


class Assessment(BaseModel):
    """The full result of one assess call."""

    findings: list[Finding]
    summary: str
    limitations: str


EXFILTRATION_CATEGORY = "data-exfiltration"
INJECTION_CATEGORY = "prompt-injection"

EXFILTRATION_SEVERITY = "high"
INJECTION_SEVERITY = "high"

NO_FINDINGS_SUMMARY = (
    "No risky capability pairing found. Sentinel checks two pairings only: "
    "sensitive-read with outbound-write, and untrusted-ingest with "
    "privileged-action. Neither is complete in this inventory."
)

LIMITATIONS = (
    "Sentinel analyzes only the inventory it was given. That inventory is a "
    "self-report from the calling model, so a tool it omits or mis-tags is "
    "invisible here, and a clean result is not a clean bill of health. Sentinel "
    "is an in-session advisor: it does not enumerate tools itself, read "
    "configuration files, scan source, emit SARIF, or run in CI, and it never "
    "changes permissions or blocks a call."
)


def _summary(findings: list[Finding]) -> str:
    if not findings:
        return NO_FINDINGS_SUMMARY
    exfiltration = sum(1 for f in findings if f.category == EXFILTRATION_CATEGORY)
    injection = len(findings) - exfiltration
    return (
        f"{len(findings)} finding(s): {exfiltration} data-exfiltration pairing(s) "
        f"and {injection} prompt-injection pairing(s)."
    )


def _names_with(inventory: list[ToolEntry], capability: Capability) -> list[str]:
    """Sorted, de-duplicated tool names carrying a capability."""
    return sorted({entry.name for entry in inventory if capability in entry.capabilities})


def _exfiltration_finding(reader: str, writer: str) -> tuple[str, str, list[str]]:
    if reader == writer:
        return (
            f"'{reader}' both reads sensitive data and sends data outside the "
            "session, so one call chain within this single tool is enough to "
            "exfiltrate what it reads.",
            f"Scope '{reader}' to the narrowest data it needs, and require explicit "
            "approval before it sends anything outbound.",
            [reader],
        )
    return (
        f"'{reader}' reads sensitive data and '{writer}' sends data outside the "
        "session. Together they form an exfiltration path: anything the first "
        "tool reads can leave through the second without further approval.",
        f"Confirm '{reader}' and '{writer}' genuinely need to be enabled together. "
        f"If they do, scope '{reader}' to the narrowest data it needs and require "
        f"explicit approval for '{writer}' calls.",
        [reader, writer],
    )


def _injection_finding(ingest: str, action: str) -> tuple[str, str, list[str]]:
    if ingest == action:
        return (
            f"'{ingest}' both ingests untrusted content and takes privileged "
            "actions, so content it pulls in can steer its own later calls.",
            f"Treat everything '{ingest}' returns as untrusted data rather than "
            "instructions, and require explicit approval before it acts on that "
            "content.",
            [ingest],
        )
    return (
        f"'{ingest}' ingests content controlled by someone else and '{action}' "
        "takes privileged actions. Instructions hidden in what the first tool "
        "fetches can steer the model into calling the second.",
        f"Treat everything '{ingest}' returns as untrusted data rather than "
        f"instructions, and require explicit approval for '{action}' calls that "
        f"follow it.",
        [ingest, action],
    )


def _analyze(inventory: list[ToolEntry]) -> Assessment:
    """Apply the capability-pairing rules. Pure, total, and order-independent."""
    findings: list[Finding] = []

    pairings = (
        (
            EXFILTRATION_CATEGORY,
            EXFILTRATION_SEVERITY,
            _exfiltration_finding,
            _names_with(inventory, Capability.SENSITIVE_READ),
            _names_with(inventory, Capability.OUTBOUND_WRITE),
        ),
        (
            INJECTION_CATEGORY,
            INJECTION_SEVERITY,
            _injection_finding,
            _names_with(inventory, Capability.UNTRUSTED_INGEST),
            _names_with(inventory, Capability.PRIVILEGED_ACTION),
        ),
    )

    for category, severity, build, sources, sinks in pairings:
        for source in sources:
            for sink in sinks:
                description, recommendation, tools = build(source, sink)
                findings.append(
                    Finding(
                        id=f"RISK-{len(findings) + 1:03d}",
                        category=category,
                        severity=severity,
                        tools=tools,
                        description=description,
                        recommendation=recommendation,
                    )
                )

    return Assessment(findings=findings, summary=_summary(findings), limitations=LIMITATIONS)


@mcp.tool
def assess(tool_inventory: list[ToolEntry]) -> Assessment:
    """Assess an MCP tool surface for risky capability pairings.

    Pass every tool available in this session, tagging each with the capability
    categories it carries:

    - `sensitive-read` - reads data the session should not leak.
    - `outbound-write` - sends data outside the session.
    - `untrusted-ingest` - pulls in content controlled by someone else.
    - `privileged-action` - takes actions with consequences.

    A tool may carry several categories, or none. Sentinel reports two
    pairings: `sensitive-read` with `outbound-write` (data exfiltration) and
    `untrusted-ingest` with `privileged-action` (prompt injection into a
    privileged call). A single tool holding both sides of a pairing is reported
    too. The result is deterministic and depends only on the inventory's
    content, not its order.
    """
    return _analyze(tool_inventory)


def main():
    mcp.run()


if __name__ == "__main__":
    main()

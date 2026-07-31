# Sentinel

MCP server that analyzes the security posture of your MCP tool setup.

Sentinel exposes one deterministic tool, `assess`. The calling model already knows which
tools it can invoke, so it passes them in directly — each tagged with capability
categories — and Sentinel reports the pairings that create risk. No sampling, no model
provider, no API key, no persistence: the same inventory always produces the same
findings.

## How it works

1. You ask your assistant to assess its MCP tool setup
2. The assistant calls `assess`, passing its tools tagged with capability categories
3. Sentinel applies its rules and returns findings with fixed severities and recommendations

## Install

```bash
# Run directly with uvx
uvx sentinel-security-advisor

# Or install from source
git clone https://github.com/wdm0006/mcp-sentinel
cd mcp-sentinel
uv sync
uv run sentinel
```

## MCP client config

```json
{
  "mcpServers": {
    "sentinel": {
      "command": "uvx",
      "args": ["sentinel-security-advisor"]
    }
  }
}
```

## The `assess` tool

`assess` takes one required argument, `tool_inventory`: a list of entries, each with a
`name` and a list of `capabilities`.

| Capability | Meaning |
| --- | --- |
| `sensitive-read` | Reads data the session should not leak (files, databases, mail, secrets) |
| `outbound-write` | Sends data outside the session (HTTP requests, email, chat, uploads) |
| `untrusted-ingest` | Pulls in content controlled by someone else (web pages, inboxes, issue trackers, shared files) |
| `privileged-action` | Takes actions with consequences (code execution, writes, deployments, permission changes) |

A tool may carry several categories, or none. These four values are the only ones
accepted — anything else fails schema validation rather than being silently ignored.

### Example call

```json
{
  "tool_inventory": [
    { "name": "postgres", "capabilities": ["sensitive-read"] },
    { "name": "slack", "capabilities": ["outbound-write", "untrusted-ingest"] },
    { "name": "bash", "capabilities": ["privileged-action"] }
  ]
}
```

### Example result

```json
{
  "findings": [
    {
      "id": "RISK-001",
      "category": "data-exfiltration",
      "severity": "high",
      "tools": ["postgres", "slack"],
      "description": "'postgres' reads sensitive data and 'slack' sends data outside the session. ...",
      "recommendation": "Confirm 'postgres' and 'slack' genuinely need to be enabled together. ..."
    },
    {
      "id": "RISK-002",
      "category": "prompt-injection",
      "severity": "high",
      "tools": ["slack", "bash"],
      "description": "'slack' ingests content controlled by someone else and 'bash' takes privileged actions. ...",
      "recommendation": "Treat everything 'slack' returns as untrusted data rather than instructions. ..."
    }
  ],
  "summary": "2 finding(s): 1 data-exfiltration pairing(s) and 1 prompt-injection pairing(s).",
  "limitations": "..."
}
```

## Rules

Sentinel checks two capability pairings, deliberately and only these:

- `sensitive-read` × `outbound-write` — a data-exfiltration path
- `untrusted-ingest` × `privileged-action` — untrusted content steering a privileged call

A single tool carrying both sides of a pairing is reported too. Findings come back in a
stable order (exfiltration pairings first, then injection pairings, each sorted by tool
name) with fixed severities, descriptions, and recommendations. Inventory order and
duplicate entries or capabilities do not change the output.

## Limitations

**The inventory is a self-report.** Sentinel does not enumerate your tools; it analyzes
exactly what the calling model passes in. A tool the model omits or mis-tags is invisible
here, so a result with no findings is not a clean bill of health.

**The rule set is narrow by design.** Sentinel reports two pairings. It says nothing
about over-broad scopes, missing authentication, lateral movement, or anything else.

**Sentinel is an in-session advisor, not a scanner.** It does not read MCP configuration
files, scan source code, emit SARIF, or run in CI — mature tools already cover that
ground. It reports; it never changes permissions, blocks a call, or remediates anything.

## Requirements

- Python 3.12+
- Any MCP client (no sampling support required)

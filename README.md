# Sentinel

MCP server that analyzes the security posture of your MCP tool setup.

You give Sentinel an inventory of the MCP tools available in your session, and it analyzes the combination for security risks like data exfiltration paths, prompt injection vectors, and overly permissive access.

## How it works

1. You ask your AI model to assess your security posture
2. Your model lists the MCP tools it has access to and passes that list to Sentinel's `assess` tool
3. Sentinel analyzes that tool set for security risks server-side, using the Anthropic API
4. You get back a risk assessment with specific findings and recommendations

The `sentinel_audit` prompt spells out the inventory format if you want to drive step 2 explicitly.

> **Why the tool list is an argument.** Sentinel used to ask the client's own LLM to enumerate its tools via [MCP sampling](https://modelcontextprotocol.io/specification/2026-07-28/deprecated). Sampling is deprecated as of the [2026-07-28 specification](https://modelcontextprotocol.io/specification/2026-07-28/changelog), which recommends passing this kind of context as ordinary tool parameters instead. Your agent can already see its own tool list, so it supplies it directly.

## Install

```bash
# Run directly from GitHub (no install needed)
uvx --from git+https://github.com/wdm0006/mcp-sentinel sentinel

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
      "args": ["--from", "git+https://github.com/wdm0006/mcp-sentinel", "sentinel"],
      "env": {
        "ANTHROPIC_API_KEY": "sk-ant-..."
      }
    }
  }
}
```

## Tools

### `assess(tool_inventory)`

Runs a security analysis over the tool inventory you pass in, covering:

- Data exfiltration paths
- Prompt injection vectors
- Overly broad access
- Missing authentication
- Lateral movement potential

The inventory is treated as untrusted data, not instructions: it is delimited and escaped, and the analyst prompt is told to report any embedded instructions as a finding rather than follow them.

## Prompts

### `sentinel_audit`

Returns the instructions for enumerating your tools in the format `assess` expects, then calling it.

## Configuration

| Variable | Required | Default | Purpose |
| --- | --- | --- | --- |
| `ANTHROPIC_API_KEY` | yes | — | Used to run the analysis |
| `SENTINEL_MODEL` | no | `claude-opus-5` | Model used for the analysis |

## Requirements

- Python 3.12+
- An Anthropic API key

# Sentinel

MCP server that analyzes the security posture of your MCP tool setup.

Sentinel uses [MCP sampling](https://spec.modelcontextprotocol.io/specification/client/sampling/) to ask the client LLM to describe its available tools, then analyzes the combination for security risks like data exfiltration paths, prompt injection vectors, and overly permissive access.

## How it works

1. You ask your AI model to assess your security posture
2. Sentinel uses sampling to ask the client LLM: "what tools do you have?"
3. The LLM describes all its connected MCP tools and their capabilities
4. Sentinel samples again, asking the LLM to analyze that tool set for security risks
5. You get back a risk assessment with specific findings and recommendations

No API keys needed — Sentinel uses the client's own LLM via sampling.

## Install

```bash
# Run directly with uvx
uvx sentinel-security-advisor

# Or install from source
git clone https://github.com/your-org/sentinel-security-advisor
cd sentinel-security-advisor
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

## Tools

### `assess`

Runs a full security analysis. Discovers all connected MCP tools via sampling, then analyzes them for risks including:

- Data exfiltration paths
- Prompt injection vectors
- Overly broad access
- Missing authentication
- Lateral movement potential

### `discover`

Lists all MCP tools the client model has access to. Useful for understanding your tool surface before running a full assessment.

## Requirements

- Python 3.12+
- An MCP client that supports [sampling](https://spec.modelcontextprotocol.io/specification/client/sampling/)

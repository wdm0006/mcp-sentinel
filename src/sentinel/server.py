"""
Sentinel - MCP security advisor that uses sampling to analyze your tool setup.

A single-file MCP server that asks the client LLM to describe its available
tools, then analyzes the configuration for security risks like data
exfiltration paths, prompt injection vectors, and overly permissive access.
"""

from fastmcp import FastMCP, Context

SAMPLING_SPEC_URL = "https://modelcontextprotocol.io/specification/client/sampling"

mcp = FastMCP(
    "sentinel",
    instructions=(
        "Sentinel analyzes the security posture of your MCP tool setup. "
        "Call the assess tool to get a security risk analysis of all "
        "your currently connected MCP tools."
    ),
)

DISCOVERY_SYSTEM_PROMPT = """\
You are cataloging MCP tools. List every MCP tool you have access to \
(excluding any sentinel tools). For each tool provide:
- Tool name
- What it can read or access
- What actions it can take (send messages, write files, query databases, \
execute code, etc.)
- What authentication or permissions it requires, if known

Be thorough. Include every tool.\
"""

ANALYSIS_SYSTEM_PROMPT = """\
You are a security analyst specializing in AI tool chain security. \
Analyze the provided tool inventory for concrete security risks. \
Be specific and actionable. Focus on practical risks, not theoretical ones. \
If the tool set is genuinely low-risk, say so — do not invent problems.\
"""

ANALYSIS_USER_PROMPT = """\
Here are the MCP tools available in a single AI assistant session:

{tools}

Analyze this tool configuration for security risks. Consider:

1. **Data exfiltration paths** — Can a tool that reads sensitive data \
(database, files, email) combined with a tool that sends data externally \
(email, HTTP, messaging) create an exfiltration path?
2. **Prompt injection vectors** — Can a tool that ingests untrusted content \
(web fetch, file read, message receive) feed into a tool that takes \
privileged actions (code execution, database writes, sending messages)?
3. **Overly broad access** — Does any tool have more access than it \
likely needs (full filesystem, admin database access, wildcard permissions)?
4. **Missing authentication** — Are any tools accessing sensitive \
resources without authentication?
5. **Lateral movement** — Could compromising one tool's access lead to \
escalated access through another?

For each risk found, provide:
- **Risk ID** (RISK-001, RISK-002, etc.)
- **Severity** (Critical / High / Medium / Low)
- **Tools involved**
- **Description** of the concrete risk
- **Recommendation** to mitigate it

End with a brief overall assessment.\
"""


def _sampling_error_message(exc: Exception) -> str:
    """Build a clear, actionable message for a failed/unsupported sampling call."""
    return (
        "Sentinel requires an MCP client that supports sampling, and this "
        f"client returned an error: {exc}. See {SAMPLING_SPEC_URL} for details."
    )


async def _discover_tools(ctx: Context) -> str:
    """Ask the client LLM to enumerate its connected MCP tools via sampling."""
    ctx.info("Discovering connected MCP tools...")
    discovery = await ctx.sample(
        messages="List all MCP tools you currently have access to, with their capabilities.",
        system_prompt=DISCOVERY_SYSTEM_PROMPT,
        max_tokens=8192,
    )
    return discovery.text


@mcp.tool
async def assess(ctx: Context) -> str:
    """Analyze the security posture of your MCP tool setup.

    Uses sampling to discover all connected MCP tools, then analyzes
    the combination for security risks like data exfiltration paths,
    prompt injection vectors, and overly permissive access.
    """
    # Step 1: Ask the client LLM to describe its available tools
    try:
        tool_inventory = await _discover_tools(ctx)
    except Exception as exc:
        return _sampling_error_message(exc)

    if not tool_inventory or not tool_inventory.strip():
        return "Could not discover any MCP tools. The client may not support sampling."

    # Step 2: Analyze the tool inventory for security risks
    ctx.info("Analyzing tool configuration for security risks...")
    try:
        analysis = await ctx.sample(
            messages=ANALYSIS_USER_PROMPT.format(tools=tool_inventory),
            system_prompt=ANALYSIS_SYSTEM_PROMPT,
            max_tokens=8192,
        )
    except Exception as exc:
        return _sampling_error_message(exc)

    return analysis.text or "Analysis produced no output."


@mcp.tool
async def discover(ctx: Context) -> str:
    """List all MCP tools the client model has access to.

    Uses sampling to ask the client LLM to enumerate its available tools
    and their capabilities. Useful for understanding your current tool
    surface before running a full security assessment.
    """
    try:
        tool_inventory = await _discover_tools(ctx)
    except Exception as exc:
        return _sampling_error_message(exc)

    if not tool_inventory or not tool_inventory.strip():
        return "Could not discover any MCP tools."

    return tool_inventory


def main():
    mcp.run()


if __name__ == "__main__":
    main()

---
name: local-dev
description: Bring wdm0006/mcp-sentinel to a working local dev environment and verify the assess tool end-to-end
---

# Local dev — Sentinel MCP server

## What this repo needs

- Python 3.12+ (system Python 3.13.14 works fine).
- uv — not preinstalled in a fresh sandbox; `pip install uv` worked here. Network is
  required for the first `uv sync`.
- Nothing else: no DB, no Redis, no Docker Compose, no API keys, no env vars, no ports.

## Steps (verified 2026-09-06)

1. `uv sync` — creates `.venv` and installs runtime + dev deps (~15s cold).
2. Smoke-start the server: `uv run sentinel < /dev/null`. Expect the FastMCP banner,
   `Starting MCP server 'sentinel' with transport 'stdio'`, then a clean exit 0.
   stdio is the only transport — do not look for a port or health endpoint.
3. `uv run pytest` — 23 offline tests, ~4s.
4. `uv run --with ruff ruff check .` — lint, must be clean.
5. End-to-end primary flow: launch `.venv/bin/sentinel` as a subprocess via fastmcp
   `Client(StdioTransport(...))`; `list_tools()` must expose exactly `assess`; call it
   with the README example inventory and diff the structured result against the
   README's documented example result.

## Gotchas

- `uv sync` writes `uv.lock`, which this repo neither gitignores nor commits — leave
  it out of setup PRs.
- fastmcp 4.x raises `FastMCPDeprecationWarning` for `Tool.inputSchema`/`outputSchema`
  reads in tests — pre-existing warnings, not failures.
- Tests assert README examples byte-for-byte: wording changes to README and to
  finding/summary text must land together.
- CI also tests the dependency floor (`uv sync --resolution lowest-direct`) and the
  built wheel; run `uv build` if you touch packaging.

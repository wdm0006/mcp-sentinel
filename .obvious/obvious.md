# Sentinel — wdm0006/mcp-sentinel

MCP server that analyzes the security posture of an MCP tool setup. One deterministic
tool, `assess`: the calling model passes in the tools it can reach, each tagged with
capability categories, and Sentinel reports the risky pairings (`sensitive-read` ×
`outbound-write` → data exfiltration; `untrusted-ingest` × `privileged-action` →
prompt injection). No sampling, no model provider, no API key, no persistence, no
external services.

## Stack

| Component | Detail |
| --- | --- |
| Language | Python 3.12+ (CI matrix: 3.12, 3.13) |
| Package manager | uv (`uv sync`, `uv run`) |
| Build backend | hatchling |
| Runtime deps | fastmcp>=2.14.6 (resolved: 4.0.3), pydantic>=2.0.0 |
| Dev deps | pytest>=8.0.0, pytest-asyncio>=0.24.0 |
| Lint | ruff, line-length 100, rules E+F |
| App type | MCP server on stdio transport — no port, no HTTP listener |
| External services | None (no DB, no Redis, no Docker, no env vars, no secrets) |

## Commands

| Task | Command |
| --- | --- |
| Install deps | `uv sync` |
| Run the server (canonical dev command) | `uv run sentinel` |
| Run as a module | `uv run python -m sentinel` |
| Tests | `uv run pytest` |
| Lint | `uv run --with ruff ruff check .` |
| Build wheel | `uv build` |
| Dependency-floor check (as CI) | `uv sync --resolution lowest-direct && UV_NO_SYNC=1 uv run pytest` |

`uv run sentinel` speaks MCP over stdio: there is no port to curl. It starts, prints
the FastMCP banner, and exits 0 when stdin reaches EOF — that is the normal shutdown
and the same smoke test CI runs on the built wheel.

uv is not preinstalled in a fresh sandbox; `pip install uv` works (needs network for
the first `uv sync`).

## Codebase map

See `codebase-map.md`.

## Local Verification Summary

Onboarding run 2026-09-06, sandbox `cmp_E5gFFHrq`:

- `uv sync` — installed runtime + dev deps into `.venv` (Python 3.13.14, uv 0.12.10).
- `uv run --with ruff ruff check .` — all checks passed, 0 issues.
- `uv run pytest` — 23 passed, 2 warnings in 3.68s (pre-existing FastMCP deprecation
  notices for `inputSchema`/`outputSchema` in tests; not failures).
- `uv run sentinel < /dev/null` — server started on stdio transport and exited 0.
- Primary user flow (end-to-end): a real MCP client session over stdio against a live
  `.venv/bin/sentinel` subprocess (fastmcp `Client` + `StdioTransport`):
  - `list_tools` exposed exactly one tool, `assess`.
  - Calling `assess` with the README example inventory returned findings RISK-001
    (data-exfiltration, high, tools postgres+slack) and RISK-002 (prompt-injection,
    high, tools bash+slack), byte-identical to the README's documented example result.
  - An untagged inventory returned no findings with the "nothing was tagged" summary.

dev_stack_healthy: true

## Sandbox snapshot

- Snapshot ID (E2B template): `ph3zgj6xfsg5e4428mo2:default`
- Built at: 2026-09-06T20:22:05.366Z
- Contents: repo checkout on `main` + uv 0.12.10 + synced `.venv` (Python 3.13.14,
  fastmcp 4.0.3), dev stack verified healthy before capture.

## Repo policy

Default branch `main`; all merge methods enabled on GitHub (squash preferred).
See `config.yml`.

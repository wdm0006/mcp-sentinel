# Codebase map — wdm0006/mcp-sentinel

Folder-level overview, depth capped at 2.

| Path | Kind | Purpose |
| --- | --- | --- |
| `src/sentinel/` | package | The entire server; no other app code exists |
| `src/sentinel/server.py` | module | FastMCP app, `Capability` enum, `ToolEntry`/`Finding`/`Assessment` models, the two pairing rules, the `assess` tool, `main()` entry point |
| `src/sentinel/__main__.py` | module | `python -m sentinel` shim that calls `sentinel.server:main` |
| `src/sentinel/__init__.py` | module | Empty package marker |
| `tests/test_server.py` | tests | 23 offline tests driving the real `assess` tool through FastMCP's in-memory `Client`; includes README consistency checks (example output and uvx launch commands) |
| `.github/workflows/ci.yml` | CI | uv jobs: ruff + pytest on Python 3.12/3.13, dependency-floor pytest (`--resolution lowest-direct`), built-wheel install + import + console-script smoke test |
| `pyproject.toml` | manifest | hatchling build, deps, console script `sentinel`, pytest (asyncio auto) and ruff config |
| `README.md` | docs | Usage, MCP client config, capability glossary, example call/result — asserted byte-for-byte by tests |
| `LICENSE` | legal | MIT |

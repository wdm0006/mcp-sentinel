# Mutation-testing waiver register

Every mutation-testing campaign on this repository must end in one of two states
for each surviving mutant:

1. **Killed by a named, committed test** — the test is added to the suite and
   named in the campaign evidence; or
2. **Entered in this register** with a classification and a one-line rationale.

A survivor that is neither killed nor waived blocks the campaign from counting
as complete. Waivers are reviewed like code: removing one requires either a
killing test or a re-justification.

## Running a campaign

```bash
uv run mutmut run       # configuration in [tool.mutmut] (pyproject.toml)
uv run mutmut results   # per-mutant outcomes
uv run mutmut show <id> # diff of a surviving mutant
```

## Classification taxonomy

| Class | Meaning |
| --- | --- |
| `equivalent` | The mutant is semantically identical to the original; no test can kill it. |
| `output-invisible` | The mutated behavior is not observable through the public surface the tests exercise (e.g. diagnostics only reachable under a debugger). |
| `test-cost` | A killing test is possible but would pin incidental detail (e.g. exact log prose beyond the operator contract), making future maintenance worse than the risk it retires. |

## Register

**Current waivers: none.**

### Campaign 2026-09-07 — `src/sentinel/server.py` (mutmut 3.7.0)

- Result: **97/97 mutants killed**, 0 survived, 0 timeout, 0 suspicious, 0 skipped.
- Suite at campaign time: 27 tests, ~0.8 s.
- The first campaign pass left 16 survivors; all were killed by named tests
  rather than waived:
  - `test_capability_glossary_renders_the_schema_text_exactly` — pins the
    glossary renderer that produces the schema text the calling model reads
    (5 survivors; the renderer runs at import time, so no constant-based test
    could see a mutation of it).
  - `test_three_sources_are_listed_comma_separated_with_a_final_and` — a
    three-source case with an exact description byte-assert; the two-name
    tests could not distinguish `[:-1]` slicing or final-element index
    mutations (3 survivors).
  - `test_main_runs_the_stdio_server_and_logs_startup` and
    `test_main_logs_the_interrupt_before_reraising` — exact
    `LogRecord.getMessage()` list assertions on the operator-facing stdio
    startup/shutdown logs (8 survivors, including `logger.info(None)`
    crash variants).
- Negative result worth keeping: substring assertions (`msg in caplog.text`)
  cannot kill `XX…XX` wrapper mutants — the exact-record form above is the
  minimum assertion strength for log-contract tests in this repository.

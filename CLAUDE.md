# agent-audit — project contract

Read this before you change anything. Project facts here win over general habits.

## What this project is

A CLI that scans a lockfile for known-vulnerable versions of agent-payment SDKs (x402 and
related), **including vulnerabilities that have no published advisory**, which `npm audit`
therefore reports as clean. It is a security tool. Correctness beats features.

## The gate

Run all three before you report a sub-task done. They must all pass.

```bash
npm run typecheck     # tsc --noEmit, must be silent
npm test              # vitest, all tests must pass
npm run build         # tsc, must emit dist/
```

Only **one** heavy job at a time across all agents. RAM is tight.

## The rules that are not negotiable

### 1. Never invent a version range

Every advisory fact must come from `research/x402-verified-facts.md`. If a fact is not in
that file with a source, **it does not go into an advisory**. Do not guess a lower bound
because it looks reasonable. A false finding in a security tool destroys its credibility.

If you need a fact that is not in the research file, stop and report it. Do not research it
yourself and do not assume.

### 2. Every advisory declares its provenance

- `source: "advisory"` — mirrored from a published GHSA/OSV record. Ranges are upstream's.
- `source: "derived"` — reconstructed. **Must** carry a `provenance` field explaining how
  the range was established, and an honest `confidence`.

A test enforces this. Do not weaken that test.

### 3. Never weaken a test to make it pass

Fix the cause. Do not delete an assertion, loosen a matcher or skip a case. If a test is
genuinely wrong, say so in your report and explain why — do not silently change it.

### 4. File ownership is exclusive

Three developers share one checkout with no worktrees. Edit **only** the files your
sub-task lists. If your change seems to need a file you do not own, stop and report it.
Do not edit it "quickly".

### 5. YAGNI

Build only what the acceptance criteria need. No flag, option, config key, helper or
abstraction without a caller today. Delete code your change makes dead. No new runtime
dependency — the only ones are `semver` and `yaml`.

## Layout

| Path | Holds |
|---|---|
| `src/types.ts` | All shared types. Changing it affects every other file. |
| `src/db.ts` | Loads and validates advisories from disk |
| `src/lockfiles.ts` | Parsers for npm, pnpm, yarn, bun lockfiles |
| `src/match.ts` | OSV range evaluation and filtering |
| `src/report.ts` | Text and JSON output |
| `src/cli.ts` | Argument parsing and exit codes |
| `advisories/*.json` | The database, one OSV document per file |
| `research/` | Verification records. The source of truth for advisory facts. |
| `test/` | Tests and fixtures |
| `docs/` | The website (static, no build step) |

## Style

- TypeScript, ESM, `strict` with `noUncheckedIndexedAccess`. Relative imports end in `.js`.
- Node 20+. No transpile target below ES2022.
- Comments explain **why**, not what. Do not narrate the code.
- Error messages are for a developer under time pressure. Say what is wrong and what to do.

## Tools available

`graphify` and `headroom` are present. `wt`, `graft` and the code graph are **not**. Write
`graph skipped: tool not available` in your tool log — this is an accepted reason, not a miss.

## Reporting

End every report with the tool log line, for example:

```
tools: graph 0 / graft 0 / graphify 1 / headroom 0 / grep 3 / read 4  (graph skipped: tool not available)
```

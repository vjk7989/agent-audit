# Todo: agent-audit v0.1.0 -> v0.2.0

Base commit: `fadd8bd` (v0.1.0, 24 tests passing). Target: v0.2.0.
Gate: `npm run typecheck && npm test && npm run build`
States: `[ ]` pending, `[~]` in progress, `[r]` ready for test, `[x]` done (commit hash), `[!]` blocked (reason).

## Ordering

T1,T2,T3 parallel -> GATE 1 -> T5,T4,T6 -> T7 -> GATE 2 -> T8 -> GATE 3 -> T9,T10 -> FINAL GATE

## Assignment

| ID | Title | Dev | Size |
|---|---|---|---|
| T1 | Chain type, chain filter in matcher, no-fix contract | D1 | M |
| T2 | Chain tags and EVM notes on existing advisories | D2 | S |
| T3 | GHSA-5cgh-j82v-jvrj entry, EVM fixture, data invariants | D3 | M |
| T4 | No-fix, mitigation and chain in report output | D2 | M |
| T5 | `--chain` flag | D1 | S |
| T6 | Static landing page | D3 | L |
| T7 | Credible layout and compact summary renderer | D2 | M |
| T8 | `--summary` flag and library export | D1 | S |
| T9 | Replace site terminal panels with real v0.2 output | D3 | S |
| T10 | README and version 0.2.0 | D1 | M |

Points (S=1, M=2, L=3): D1 = 2+1+1+2 = 6, D2 = 1+2+2 = 5, D3 = 2+3+1 = 6.

## File ownership (disjoint; no worktrees)

- D1: `src/types.ts`, `src/match.ts`, `src/index.ts`, `src/cli.ts`, `test/chain.test.ts`, `README.md`, `package.json`, `package-lock.json`
- D2: `advisories/AAUD-2026-000{1,2,3}.json`, `advisories/GHSA-qr2g-p6q7-w82m.json`, `src/report.ts`, `test/report.test.ts`
- D3: `advisories/GHSA-5cgh-j82v-jvrj.json`, `test/fixtures/evm-agent/*`, `test/evm-advisory.test.ts`, `docs/*`
- Owned by nobody, must not be edited: `test/agent-audit.test.ts`, `src/db.ts`, `src/lockfiles.ts`, `advisories/AAUD-2026-0004.json`, `advisories/GHSA-3j63-5h8p-gf7c.json`, the four existing fixtures, `tsconfig.json`, `vitest.config.ts`, `CLAUDE.md`, `research/*`.

## Sub-tasks

- [~] T1 · agent-audit · Chain type, chain filter in matcher, no-fix contract
  files: src/types.ts, src/match.ts, test/chain.test.ts          size: M      dev: D1
  AC: (planner to fill; see ADR-1, ADR-2, ADR-3)
  verify: npm run typecheck && npm test
  deps: none        tools: graphify; graph skipped: tool not available
  worktree: main

- [~] T2 · agent-audit · Chain tags and EVM notes on existing advisories
  files: advisories/AAUD-2026-000{1,2,3}.json, advisories/GHSA-qr2g-p6q7-w82m.json          size: S      dev: D2
  AC: (planner to fill; see ADR-1, ADR-5)
  verify: npm test
  deps: none        tools: graphify; graph skipped: tool not available
  worktree: main

- [~] T3 · agent-audit · GHSA-5cgh-j82v-jvrj entry, EVM fixture, data invariants
  files: advisories/GHSA-5cgh-j82v-jvrj.json, test/fixtures/evm-agent/*, test/evm-advisory.test.ts          size: M      dev: D3
  AC: (planner to fill; see ADR-3, ADR-4, ADR-6)
  verify: npm test
  deps: none        tools: graphify; graph skipped: tool not available
  worktree: main

- [ ] T4 · agent-audit · No-fix, mitigation and chain in report output
  files: src/report.ts, test/report.test.ts          size: M      dev: D2
  AC: (planner to fill; see ADR-3, ADR-7)
  verify: npm run typecheck && npm test
  deps: T1, T2, T3 (GATE 1)        tools: graphify; graph skipped: tool not available
  worktree: main

- [ ] T5 · agent-audit · `--chain` flag
  files: src/cli.ts          size: S      dev: D1
  AC: (planner to fill; see ADR-2, ADR-9)
  verify: npm run build && node dist/cli.js (cli.ts runs main() on import; not unit-testable)
  deps: T1 (GATE 1)        tools: graphify; graph skipped: tool not available
  worktree: main

- [ ] T6 · agent-audit · Static landing page
  files: docs/*          size: L      dev: D3
  AC: (planner to fill; see ADR-11)
  verify: (planner to fill; grep check on docs/ content)
  deps: GATE 1        tools: graphify; graph skipped: tool not available
  worktree: main

- [ ] T7 · agent-audit · Credible layout and compact summary renderer
  files: src/report.ts, test/report.test.ts          size: M      dev: D2
  AC: (planner to fill)
  verify: npm run typecheck && npm test
  deps: T4        tools: graphify; graph skipped: tool not available
  worktree: main

- [ ] T8 · agent-audit · `--summary` flag and library export
  files: src/cli.ts, src/index.ts          size: S      dev: D1
  AC: (planner to fill; see ADR-7, ADR-8)
  verify: npm run build && node dist/cli.js
  deps: T7 (GATE 2)        tools: graphify; graph skipped: tool not available
  worktree: main

- [ ] T9 · agent-audit · Replace site terminal panels with real v0.2 output
  files: docs/*          size: S      dev: D3
  AC: (planner to fill; see ADR-11)
  verify: (planner to fill)
  deps: T8 (GATE 3)        tools: graphify; graph skipped: tool not available
  worktree: main

- [ ] T10 · agent-audit · README and version 0.2.0
  files: README.md, package.json, package-lock.json          size: M      dev: D1
  AC: (planner to fill)
  verify: npm run typecheck && npm test && npm run build
  deps: T8 (GATE 3)        tools: graphify; graph skipped: tool not available
  worktree: main

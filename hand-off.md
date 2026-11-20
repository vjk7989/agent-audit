# Hand-off 2026-11-20

**State: v0.2.0 complete and committed. Working tree clean. Nothing pushed, nothing published.**

Base was `fadd8bd` (v0.1.0, 24 tests). Head is `7c84235` (v0.2.0, 135 tests). Fifteen commits.

## What v0.2.0 added

- A chain dimension (`evm` / `solana`) on advisories, with a `--chain` filter that **fails open**: an advisory is hidden only when it positively names other chains, so a chain-agnostic entry can never be filtered away (ADR-2).
- `GHSA-5cgh-j82v-jvrj`, an **unpatched** EVM advisory. `@x402/evm` 2.12.0–2.31.0, and 2.31.0 is the current latest release, so a fully up-to-date install is affected. It is absent from OSV and returns 404 from GitHub's global advisory API.
- "No fix available" handling end to end: a `Mitigate:` line in the report, `noFixCount` in JSON, `no fix` in `--summary`.
- `--summary`, an aligned 80-column layout, a static landing page in `docs/`.

## Gate

```
npm run typecheck     # now covers test/ as well as src/
npm test
npm run build
```

Verified twice at head: once by the orchestrator, once independently by the Haiku test
runner from a clean start. Both green, no differences.

## Next step

Nothing is in flight. The build work is finished. What remains is release and grant work,
and all of it needs the user's decision:

1. Push to a remote. There is **no GitHub repository yet**, which is why `docs/index.html`
   carries no outbound links — there is an HTML comment marking where they go.
2. Publish to npm as `agent-audit`. The name is free; `agentaudit` was taken.
3. Submit the four derived advisories upstream to the GitHub Advisory Database. This is the
   strongest grant evidence available and benefits the ecosystem regardless of this tool.
4. Grant applications. See `../INDIA-GRANT-PLAN.md` (outside this repo, deliberately).

## Gotchas for whoever picks this up

- **`src/cli.ts` runs `main()` on import**, so it cannot be unit-tested in-process. CLI
  behaviour is verified by building and spawning `node dist/cli.js`.
- **Never invent a version range.** Every advisory fact must trace to
  `research/x402-verified-facts.md` with a source. See `CLAUDE.md` rule 1.
- **`tsconfig.json` excludes `test/`** because it drives the build. `tsconfig.test.json`
  exists purely so the test suite is typechecked too. Run `npm run typecheck`, not bare
  `tsc -p tsconfig.json` — the latter will not see test files, and that gap once hid two
  tests that passed for the wrong reason.
- **Re-verify before any release.** `research/x402-verified-facts.md` §6 lists what to
  re-check: whether `@x402/evm` has shipped a release after 2.31.0, and whether
  GHSA-5cgh has reached OSV. If it has, flip `npm_audit_detects` to `true`.
- The known limitation on prerelease lower bounds is documented in the README. It follows
  the OSV spec, so it was recorded rather than changed.

## Resources and tools (this session)

```
cpu 16 logical | ram free 2.6/15.4 GB | developers 3 | heavy jobs at once 1
```

Present: `graphify`, `headroom`. Missing: `wt` (fallback: disjoint file ownership per
developer, which held for the whole run with no collisions), `graft`, code graph
(`graph skipped: tool not available` is an accepted tool-log reason).

## Steward

Developer misses 0, explorer 0, test-writer 0.

Two defects were caught by agents rather than by the gate, and both were reported rather
than quietly fixed — the process working as intended:

- The test writer found that `fixedVersionFor` returned a fix from a range that had not
  matched, which would have advised a **downgrade** and destroyed the no-fix signal. It
  refused to fix it, as briefed.
- D1 found that the resulting arity change broke a frozen test, and refused to edit that
  test. The orchestrator reviewed the intent and made the change, which revealed two
  further tests that had been passing vacuously.

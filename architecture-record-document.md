# Architecture decision records (append-only; supersede, never rewrite)

## ADR-1: Chain field shape  (2026-11-20, status: accepted)
Context: Entries need a chain scope. Inferring chain from package name fails for `@x402/core`, `@x402/fetch` and `@x402/extensions`, which are used on every chain. The existing `roles` field already uses an optional array.
Decision: Chain is `database_specific.chains?: ("evm"|"solana")[]`. Missing or empty means chain-agnostic. This mirrors the `roles` convention.
Consequences: No name heuristics. Entries must be tagged explicitly. Untagged entries are always shown.

## ADR-2: Chain filter fails open  (2026-11-20, status: accepted)
Context: A scanner that hides a real issue is worse than one that over-reports.
Decision: `--chain evm` shows EVM entries plus chain-agnostic entries. An entry is hidden only when it positively names other chains and not the requested one.
Consequences: Some agnostic entries appear for users on one chain. Users never miss an entry through a missing tag.

## ADR-3: "No patch available" representation  (2026-11-20, status: accepted)
Context: GHSA-5cgh-j82v-jvrj has no fixed release. OSV expresses this as a range with `last_affected` and no `fixed` event.
Decision: The only signal is `Finding.fixedIn === undefined`. There is no `patched: false` flag that could drift out of sync with the range. Orchestrator decision: mirror the published range verbatim. An open-ended `introduced` would be inventing data, which the project's provenance rule forbids.
Consequences: If upstream ships 2.32.0 without a fix, the tool reports clean until `last_affected` is bumped. Mitigated by recording in the entry that 2.31.0 was the latest release on 20 Nov 2026, and by the re-check list in `research/x402-verified-facts.md` section 6.

## ADR-4: `mitigation` optional in type, required by data test  (2026-11-20, status: accepted)
Context: Entries without a fix need guidance for the user, but entries with a fix do not.
Decision: `mitigation` is optional in the type but required by a data test whenever no fix exists. `src/db.ts` gets no runtime schema validation, matching the existing "requires provenance" test style.
Consequences: Invariants live in tests (`test/evm-advisory.test.ts`), not in the loader. A malformed entry is caught in CI, not at runtime.

## ADR-5: AAUD-2026-0002 stays chain-agnostic  (2026-11-20, status: accepted)
Context: The issue is likely EVM-related, but an `@x402/evm` user also installs `@x402/core`, so they are already flagged.
Decision: `AAUD-2026-0002` stays chain-agnostic at confidence "high". The EVM inference goes in `provenance`. No new entry, and `@x402/evm` is not added to its affected list.
Consequences: Marking it Solana-only would hide a likely-real issue from Ethereum users, so it is not done. EVM-specific wording lives only in provenance text.

## ADR-6: GHSA-5cgh combination of source flags  (2026-11-20, status: accepted)
Context: Earlier entries were either advisory-backed and detected by npm audit, or unadvised.
Decision: `GHSA-5cgh-j82v-jvrj` is `source: "advisory"`, `has_upstream_advisory: true`, `npm_audit_detects: false`. It is the first entry with that combination.
Consequences: "Hidden" means "npm audit cannot see it", not "no advisory exists". Docs and README wording must follow this meaning.

## ADR-7: JSON output changes are additive only  (2026-11-20, status: accepted)
Context: Consumers parse `--json` output from v0.1.0.
Decision: New keys only: `chains`, `mitigation`, `noFixCount`, `chain`. No key is renamed or removed.
Consequences: v0.1.0 consumers keep working. Any later removal needs a superseding ADR.

## ADR-8: `--summary` and `--json` are mutually exclusive  (2026-11-20, status: accepted)
Context: Both select an output format. Letting one silently win hides a user mistake.
Decision: Passing both exits with code 2 and an error message.
Consequences: Scripts that pass both fail loudly. Behaviour is verified via `npm run build` then `node dist/cli.js`.

## ADR-9: CLI chain values  (2026-11-20, status: accepted)
Context: The package is `@x402/evm` and covers Base and other EVM chains, so "ethereum" would mislead.
Decision: CLI chain values are `evm` and `solana`. No `ethereum` alias.
Consequences: Users typing `ethereum` get an invalid-value error. An alias can be added later by a new ADR.

## ADR-10: Parallel work without worktrees  (2026-11-20, status: accepted)
Context: `wt` is not available, and three developers write in one tree at the same time.
Decision: Isolation is disjoint file ownership (see `todo.md`), a frozen legacy test file (`test/agent-audit.test.ts`), and one new test file per developer.
Consequences: No two writers share a file. A task needing a file owned by another developer must be routed to its owner. One heavy job (build, full tests) runs at a time.

## ADR-11: Site is plain HTML and CSS  (2026-11-20, status: accepted)
Context: The landing page must stay credible and cheap to maintain.
Decision: Plain HTML and CSS, no JavaScript, no external assets. Terminal panels are pasted from real CLI output (T9).
Consequences: The page cannot drift into marketing fiction. Panels must be refreshed whenever output format changes.

## ADR-12: `fixedVersionFor` is version-aware  (2026-11-20, status: accepted)

**Context.** The function scanned every range of every affected entry for the package name
and returned the first `fixed` event found, without checking which range matched the
installed version. With the ordinary OSV shape of one range per major line, a 2.20.0
install against ranges `[1.0.0 .. fixed 1.5.0]` and `[2.0.0 .. last_affected 2.31.0]`
produced `fixedIn: "1.5.0"` — advice to downgrade, which fixes nothing. It also destroyed
the no-fix signal that ADR-3 depends on, since `fixedIn === undefined` is its only marker.

**Decision.** Take the installed version as a required third argument, filter on the npm
ecosystem as `advisoryHits` already did, locate the matching range with
`isAffectedByRange`, and return that range's `fixed` event or `undefined`. No optional
parameter and no compatibility overload, so the broken path is unreachable.

**Consequences.** A breaking signature change to an exported function, accepted because
nothing is published and the old behaviour was wrong. Supersedes nothing; it corrects an
implementation defect rather than a decision. Found by the edge-case test pass, which
reported it rather than fixing it.

## ADR-13: the test suite is typechecked  (2026-11-20, status: accepted)

**Context.** `tsconfig.json` excludes `test/` because it drives the build with
`rootDir: src`. So no typecheck ever saw test call sites. When ADR-12 changed an arity,
three call sites broke; one failed loudly, but **two kept passing** because they asserted
`undefined` and a malformed call also returns `undefined`. They were green and meaningless.

**Decision.** Add `tsconfig.test.json`, a `noEmit` config covering `src` and `test`, and
run it from `npm run typecheck` alongside the build config.

**Consequences.** Typecheck is slower by roughly three seconds. In exchange, a signature
change can no longer leave a test passing for the wrong reason. Anyone running bare
`tsc -p tsconfig.json` still misses test files, so the npm script is the supported entry
point and the hand-off says so.

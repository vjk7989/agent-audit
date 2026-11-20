# x402 security facts — verification record

**Compiled:** 20 Nov 2026
**Purpose:** the single source of truth for every advisory entry in `advisories/`.

This file exists so that no one has to re-research these facts, and so that no one
invents a version range. **If a fact is not in this file with a source, it does not go
into an advisory.**

Each item below states its verification level:

| Level | Meaning |
|---|---|
| **VERBATIM** | Quoted directly from the primary source, read in full |
| **REPORTED** | Stated by a named secondary source (e.g. a news article) |
| **INFERRED** | A conclusion drawn from evidence; the source does not state it |
| **UNVERIFIED** | Believed but not confirmed — **must not ship** |

---

## 1. Published GitHub advisories

### GHSA-5cgh-j82v-jvrj — EVM, UNPATCHED ⚠️

**VERBATIM** from `github.com/x402-foundation/x402/security/advisories/GHSA-5cgh-j82v-jvrj`:

- Title: "batch-settlement: voucher verifiers accept signatures x402BatchSettlement cannot recover (high-s, v = 0/1)"
- Published 18 Nov 2026 by erikreppel. Reporter: erkancamli.
- Severity Moderate. CVSS 3.1 **5.4** — `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:L`. **CWE-347.** "No known CVE."

Affected packages **exactly as published**:

| Ecosystem | Package | Affected | Patched |
|---|---|---|---|
| npm | `@x402/evm` | `>= 2.12.0, <= 2.31.0` | **None** |
| gomod | `github.com/x402-foundation/x402/go/v2` | `>= 2.11.0, <= 2.31.0` | **None** |
| pip | `x402` | `>= 2.11.0, <= 2.28.0` | **None** |

Mechanism: the TypeScript, Go and Python batch-settlement voucher verifiers accept ECDSA
voucher signatures that the on-chain `x402BatchSettlement` contract rejects. The contract
rejects `s > n/2` (`ECDSAInvalidSignatureS`) and `v` not in {27, 28} (`ECDSAInvalidSignature`).
Impact: the voucher verifies, the resource is served, and the later claim reverts. The
advisory notes "Current usage of the scheme is low." ERC-1271 payers are unaffected.

**Three facts make this the flagship entry:**
1. **No patch exists.** The current release 2.31.0 is affected.
2. **It is absent from OSV.** Queried `api.osv.dev` on 20 Nov 2026 → no record.
3. **GitHub's own global advisory API returns 404** for this ID. It is a repository-level
   advisory that never propagated. `npm audit` cannot see it by any route.

> **Note:** `@x402/core` is NOT listed. The npm entry is `@x402/evm` only.

**Open question:** whether any release after 2.31.0 exists and fixes it. Re-check before release.

### GHSA-qr2g-p6q7-w82m — Solana

**VERBATIM** from `api.github.com/advisories/GHSA-qr2g-p6q7-w82m`. HIGH, published 2026-03-07.
Alias `GO-2026-4647`.

| Ecosystem | Package | Affected | Patched |
|---|---|---|---|
| npm | `@x402/svm` | `< 2.6.0` | 2.6.0 |
| pip | `x402` | `< 2.3.0` | 2.3.0 |
| gomod | coinbase/x402/go | `< 2.5.0` | 2.5.0 |

In OSV. `npm audit` **does** detect this.

### GHSA-3j63-5h8p-gf7c — legacy v1 packages

**VERBATIM** from OSV. HIGH, published 2025-08-20. Affects `x402`, `x402-next`,
`x402-express`, `x402-hono` all `< 0.5.2`. Chain attribution: **not stated**.

In OSV. `npm audit` **does** detect this.

---

## 2. The V12 research — three critical findings, NO advisories

Source: `v12.sh/blog/x402`, "25 Vulnerabilities in the x402 Protocol", by Renwa, 22 Oct 2026.
Severity split **VERBATIM**: 3 critical + 13 high reported 12 Aug 2026; 9 medium/low
submitted 9 Sep 2026. The three criticals were fixed by 20 Aug 2026.

**Only the 3 criticals are described. The other 22 findings are not enumerated.**

### C1 — Solana payment bypass → `AAUD-2026-0001`

**VERBATIM (mechanism):** the TypeScript Solana facilitators for the v1 and v2 `exact`
schemes parsed instruction[2] as `TransferChecked` without enforcing the instruction type.
`ApproveChecked` has the same layout, differing only in the first byte (`0c` vs `0d`). The
delegate field was read as the payment destination. V12: "a complete payment bypass."
Validation was a local test; "the test did not submit a live transaction."

**Chain: SOLANA ONLY.** The blog names "TypeScript Solana facilitators".
**REPORTED (range):** affects `@x402/svm` 2.0.0–2.22.0, fixed 2.23.0 — The Hacker News, 23 Oct 2026.

### C2 — no default spending limit → `AAUD-2026-0002`

**VERBATIM:** the default client "selected the first supported payment option without
applying a spending policy." A hostile server could request the full balance. The HTTP
decoding path parsed requirements without the schema validator. V12 notes "schema
validation alone would not fix the spending issue."

**Chain: INFERRED to include EVM.** The blog does not name a chain. Its exploit mechanism
describes a signed transfer, which is an EIP-3009/EVM mechanism. The `@x402/evm` 2.23.0
changelog entry adding `spendControls` is consistent. **Mark as inferred in the data.**
**REPORTED (range):** `@x402/fetch`, `@x402/axios` fixed 2.23.0, "pulls in matching
`@x402/core`" — The Hacker News.

⚠️ `spendControls: false` disables the fix. A lockfile cannot detect that.

### C3 — SIWx origin binding → `AAUD-2026-0003`

**VERBATIM:** the client copied `domain`, `uri` and related fields from the 402 response
into the signed message without checking them against the contacted host. The blog states
"On Ethereum, it builds a Sign-In with Ethereum message" and "the real SIWE library
produced a validly formatted message."

**Chain: EVM EXPLICITLY NAMED.** The client wrapper is chain-agnostic, so treat as affecting
both, with Ethereum confirmed.
**REPORTED (range):** `@x402/extensions` fixed 2.23.0 — The Hacker News.

---

## 3. `@x402/evm` CHANGELOG — silent security fixes

Source: `raw.githubusercontent.com/x402-foundation/x402/main/typescript/packages/mechanisms/evm/CHANGELOG.md`
Read **in full, verbatim** (49,959 chars, two chunks, no truncation).

> **CRITICAL CONSTRAINT — VERBATIM finding:** "The changelog never uses the terms
> 'vulnerability' or 'vulnerable' for a package version range." **No entry states which
> versions were affected.** Only the fix version is known.
>
> Therefore every advisory derived from this changelog has an **unknown lower bound** and
> must be `confidence: "medium"` at best. Over-reporting is the accepted trade-off; say so
> in the entry.

| Fixed in | VERBATIM text | Ships? |
|---|---|---|
| **2.14.0** | "Fixed ERC-6492 factory call injection vulnerability in EVM exact settlement (v1 and v2) and simplified the configuration API." | ✅ Yes — the only entry that says "vulnerability" |
| **2.19.0** | "Fix an unauthenticated path-traversal and pre-verification channel-mutation issue in the batch-settlement server scheme." | ✅ Yes — untrusted `channelId` reached the file-storage path builder |
| **2.15.0** | "Fixed a bug where EVM facilitator verify accepted payments whose asset address was an EOA." | ✅ Yes |
| **2.7.0** | "Closed fail-open verification paths, aligned Permit2 amount check to exact match, and added `signerForNetwork` to the extensions package." | ⚠️ Marginal — mixed feature/fix entry |
| **2.29.0** | "Reject non-canonical (high-s) EOA signatures in exact-scheme EIP-3009 verify (v1 and v2)" + "Normalize the EIP-3009 signature `v` to 27 or 28 before calling `transferWithAuthorization`" | ℹ️ Context only — this is the EIP-3009 half of the GHSA-5cgh class, already fixed |
| **2.23.0** | "add client `spendControls`: by default only recognized pegged assets are allowed with a `$1` USD cap" | ℹ️ Context — confirms C2 reached EVM |

Corrections to an earlier summary that proved wrong: the term "EOA-asset" is not verbatim
(actual: "asset address was an EOA"); the EIP-2612 recovery-byte normalisation is under
**2.31.0**, not 2.29.0.

---

## 4. Chain attribution summary

| Advisory | Solana | EVM | Basis |
|---|:---:|:---:|---|
| `AAUD-2026-0001` | ✅ | ❌ | Blog names Solana facilitators |
| `AAUD-2026-0002` | ✅ | ✅* | *EVM inferred, not stated |
| `AAUD-2026-0003` | ✅ | ✅ | Blog explicitly names Ethereum |
| `AAUD-2026-0004` | ? | ? | Chain not established — treat as agnostic |
| `GHSA-5cgh-j82v-jvrj` | ❌ | ✅ | ECDSA + on-chain contract, EVM by construction |
| `GHSA-qr2g-p6q7-w82m` | ✅ | ❌ | `@x402/svm` |
| `GHSA-3j63-5h8p-gf7c` | ? | ? | Not stated |

**Design consequence:** chain must be a tri-state — `solana`, `evm`, or unknown/agnostic.
A two-value boolean would force a false claim on three of the seven entries.

---

## 5. Must NOT ship

- Any range for the 22 undescribed V12 findings. Nothing is public about them.
- Any lower bound for a changelog-derived entry. It is not published.
- `GHSA-5cgh` ranges for Go or pip while the tool is npm-only.

## 6. Re-check before release

1. ~~Does a release after `@x402/evm` 2.31.0 exist, and does it patch GHSA-5cgh?~~
   **CHECKED 20 Nov 2026 — NO.** `registry.npmjs.org/@x402/evm` reports `latest = 2.31.0`,
   published 2026-11-12. No later version exists. The advisory's upper bound (`<= 2.31.0`)
   therefore covers **the current release**, and `patched: None` still holds.
2. ~~Has GHSA-5cgh reached OSV yet?~~
   **CHECKED 20 Nov 2026 — NO.** `api.osv.dev` returns **no advisories at all** for
   `@x402/evm`. Keep `npm_audit_detects: false`.
3. Ask V12 for the 13 high findings. That would roughly quadruple the database.

### The headline fact

> Install `@x402/evm` today with default settings. You get 2.31.0. You get a **published,
> unpatched** vulnerability with a CVSS of 5.4. `npm audit` reports your project clean,
> because the advisory never reached any database that `npm audit` reads.

Re-verify both checks immediately before any public release or grant submission. If a
2.32.0 appears and patches it, the entry needs a `fixed` event and the website copy changes.

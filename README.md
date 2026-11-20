# agent-audit

**`npm audit` for agentic payment SDKs.**

Finds known-vulnerable versions of x402 and related agent-payment packages in your lockfile — including the vulnerabilities that have **no published advisory**, which `npm audit` therefore reports as clean.

```
$ npm audit
found 0 vulnerabilities

$ npx agent-audit
5 findings (4 critical, 1 high)
5 of these are invisible to npm audit.
```

Both commands, same project, same moment.

---

## Why this exists

In October 2026 the security firm V12 published [research on x402](https://v12.sh/blog/x402) reporting **25 vulnerabilities — 3 critical and 13 high**, disclosed on 12 August 2026 and fixed by 20 August. The three criticals were:

1. **Solana payment bypass.** The TypeScript Solana facilitator parsed instruction[2] as `TransferChecked` without checking the instruction discriminator. `ApproveChecked` has an identical layout and differs only in its first byte (`0x0c` vs `0x0d`), and its *delegate* field was read as the payment destination. **An approval moving zero tokens was accepted as payment** — the resource was delivered, nothing was paid.
2. **No default spending limit.** The default client took the first payment option a server offered, with no budget. A hostile API could request the agent wallet's entire balance.
3. **SIWx origin binding.** The client signed Sign-In-With-X messages without checking the named domain matched the host contacted, allowing session takeover by relay.

All three were fixed in `2.23.0`. **None of them received a security advisory.**

### The gap, verified

Queried against [OSV.dev](https://osv.dev) on 20 Nov 2026:

```
@x402/svm        1 advisory: GHSA-qr2g-p6q7-w82m → fixed in 2.6.0 (March 2026)
@x402/core       NO ADVISORIES
@x402/fetch      NO ADVISORIES
@x402/axios      NO ADVISORIES
@x402/extensions NO ADVISORIES
```

The only `@x402/svm` advisory covers a **different, earlier** issue fixed in `2.6.0`. The August criticals — fixed in `2.23.0` — have no record. The two client-side criticals live in `@x402/fetch` and `@x402/extensions`, which have **zero advisories between them**.

So an application running `@x402/svm@2.22.0` today has a complete payment bypass, and every standard supply-chain tool reports it clean.

There is a second case. `GHSA-5cgh-j82v-jvrj` is listed on the x402 repository's own advisories page (published 18 Nov 2026) but returns **404 from GitHub's global advisory API** and **nothing from OSV** — a repository-level advisory that never propagated to the databases `npm audit` reads.

This is not a criticism of the x402 maintainers, who ship fixes quickly. It is a gap in how security information reaches the people running the code.

---

## Install

```bash
npx agent-audit
```

Or add it to a project:

```bash
npm install --save-dev agent-audit
```

Requires Node 20+.

## Usage

```bash
agent-audit                          # scan the current directory
agent-audit ./my-agent               # scan a specific project
agent-audit --role client            # only issues affecting payment clients
agent-audit --min-severity critical  # only the worst
agent-audit --only-hidden            # only what npm audit cannot see
agent-audit --json                   # machine-readable output
```

Supports `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock` (classic and Berry) and `bun.lock`.

### Exit codes

| Code | Meaning |
|---|---|
| `0` | No findings, or `--exit-zero` |
| `1` | Findings reported |
| `2` | Error |

So it drops into CI as-is:

```yaml
- run: npx agent-audit --min-severity high
```

### Roles

x402 vulnerabilities rarely affect everyone. A facilitator bug does not threaten a client, and a client bug does not threaten a resource server. Pass `--role` to cut the noise:

| Role | You are |
|---|---|
| `client` | An agent or app that *pays* for resources |
| `facilitator` | A service that verifies and settles payments |
| `resource-server` | An API that *charges* for access |

---

## What it covers today

| ID | Severity | Packages | Fixed in | In npm audit? |
|---|---|---|---|---|
| `AAUD-2026-0001` | CRITICAL | `@x402/svm` | 2.23.0 | ❌ No |
| `AAUD-2026-0002` | CRITICAL | `@x402/fetch`, `@x402/axios`, `@x402/core` | 2.23.0 | ❌ No |
| `AAUD-2026-0003` | CRITICAL | `@x402/extensions` | 2.23.0 | ❌ No |
| `AAUD-2026-0004` | HIGH | `@x402/core` | 2.27.0 | ❌ No |
| `GHSA-qr2g-p6q7-w82m` | HIGH | `@x402/svm` | 2.6.0 | ✅ Yes |
| `GHSA-3j63-5h8p-gf7c` | HIGH | `x402`, `x402-next`, `x402-express`, `x402-hono` | 0.5.2 | ✅ Yes |

Published advisories are mirrored too, so one command gives the whole picture.

---

## The provenance rule

A security tool that invents findings is worse than no tool. Every entry declares where its facts came from, and the report shows it.

**`source: "advisory"`** — mirrored from a published GHSA/OSV record. Ranges are upstream's.

**`source: "derived"`** — reconstructed from published research, changelogs or commit history because no advisory exists. These entries **must** carry a `provenance` field explaining exactly how the affected range was established, and a `confidence` rating:

- **high** — the affected range is stated explicitly in a named public source
- **medium** — the fix version is known but a bound is inferred
- **low** — not shipped; tracked in the issue tracker until verified

`AAUD-2026-0004` is `medium`: the fix version (`2.27.0`) is reported, but the lower bound is an assumption, so it may over-report. The CLI prints the confidence on any entry that is not `high`, and a test enforces that every derived entry documents its provenance.

`GHSA-5cgh-j82v-jvrj` is deliberately **not** shipped. It is real, but its affected package and version range could not be verified from any machine-readable source, and guessed ranges in a security scanner cause real harm.

---

## Advisory format

Entries live in [`advisories/`](./advisories) as [OSV](https://ossf.github.io/osv-schema/) documents, so they can be contributed upstream to the GitHub Advisory Database without reshaping. Everything specific to this tool sits under `database_specific`:

```jsonc
{
  "id": "AAUD-2026-0001",
  "summary": "x402 Solana facilitator accepts a token approval as a completed payment",
  "affected": [{
    "package": { "ecosystem": "npm", "name": "@x402/svm" },
    "ranges": [{ "type": "SEMVER", "events": [{ "introduced": "2.0.0" }, { "fixed": "2.23.0" }] }]
  }],
  "database_specific": {
    "severity": "CRITICAL",
    "source": "derived",
    "confidence": "high",
    "has_upstream_advisory": false,
    "npm_audit_detects": false,
    "roles": ["facilitator", "resource-server"],
    "impact_summary": "A payer can take the paid resource without transferring any tokens.",
    "provenance": "..."
  }
}
```

**The goal is for this database to become unnecessary.** Entries should be submitted upstream; when one is accepted, its `source` flips to `advisory` and `npm audit` starts catching it.

---

## Use as a library

```ts
import { audit } from "agent-audit";

const result = audit("./my-agent", { role: "client" });

for (const finding of result.invisibleToNpmAudit) {
  console.log(finding.advisory.id, finding.package.name, "→", finding.fixedIn);
}
```

---

## Limitations

Stated plainly, because a security tool should not oversell itself:

- **npm only.** The same vulnerabilities affect the Python and Go x402 SDKs. Not yet covered.
- **Version matching, not code analysis.** If you have patched a vulnerability yourself without upgrading, this will still flag you. If you call a vulnerable API in a way that is not exploitable, it will still flag you.
- **`spendControls: false` is undetectable here.** `AAUD-2026-0002` is only *mitigated* by upgrading if you leave the new defaults on. A lockfile cannot show that. For source-level checks, [x402guard](https://github.com/dario933/x402guard) is complementary.
- **The database is small and hand-curated.** It covers what has been published about x402. V12's 13 high and 9 medium/low findings are not described publicly, so they are not here.
- **Not affiliated** with the x402 Foundation, Coinbase, V12 or the Solana Foundation.

## Related work

- [x402guard](https://github.com/dario933/x402guard) — static pattern scanner for your own integration code
- [settle-scanner](https://github.com/TheDocter-dev/settle-scanner) — active probing of live x402 merchant endpoints
- [OSV.dev](https://osv.dev) / [GitHub Advisory Database](https://github.com/advisories) — the upstream databases this tool supplements

These check different things. agent-audit is the only one that scans lockfiles against an advisory database.

## Contributing

New advisory entries are very welcome, especially with better provenance than guesswork. Open a PR adding a JSON file to `advisories/`. The test suite enforces the schema and the provenance rule.

```bash
npm install
npm test
npm run build
```

## License

MIT

import { afterAll, describe, expect, it } from "vitest";
import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { loadAdvisories } from "../src/db.js";
import { findLockfile, scanLockfile } from "../src/lockfiles.js";
import { fixedVersionFor, isAffectedByRange, matchAdvisories } from "../src/match.js";
import { renderJson, renderSummary, renderText } from "../src/report.js";
import { audit } from "../src/index.js";
import type {
  Advisory,
  AgentAuditSpecific,
  Chain,
  Finding,
  InstalledPackage,
  OsvAffected,
  OsvRange,
  ScanResult,
  ScanTarget,
} from "../src/types.js";

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, "..");
const fixture = (name: string) => resolve(here, "fixtures", name);

/** A minimal advisory. Everything the tests care about is overridable. */
function advisory(
  id: string,
  spec: Partial<AgentAuditSpecific> = {},
  affected: OsvAffected[] = [
    {
      package: { ecosystem: "npm", name: "pkg" },
      ranges: [{ type: "SEMVER", events: [{ introduced: "0" }] }],
    },
  ],
): Advisory {
  return {
    schema_version: "1.6.0",
    id,
    modified: "2026-01-01T00:00:00Z",
    published: "2026-01-01T00:00:00Z",
    summary: `${id} summary`,
    details: `${id} details`,
    affected,
    database_specific: {
      severity: "HIGH",
      source: "advisory",
      confidence: "high",
      has_upstream_advisory: true,
      npm_audit_detects: false,
      impact_summary: `${id} impact`,
      ...spec,
    },
  };
}

function target(packages: InstalledPackage[]): ScanTarget {
  return { lockfile: "package-lock.json", path: "/tmp/package-lock.json", packages };
}

const one = (version: string, name = "pkg"): ScanTarget => target([{ name, version }]);

const ids = (r: ScanResult) => r.findings.map((f) => f.advisory.id);

/** A ScanResult built straight from findings, for the renderers. */
function resultOf(findings: Finding[], chain?: Chain): ScanResult {
  return {
    target: target([]),
    findings,
    invisibleToNpmAudit: findings.filter((f) => !f.advisory.database_specific.npm_audit_detects),
    advisoriesLoaded: 7,
    packagesScanned: 3,
    ...(chain ? { chain } : {}),
  };
}

const tempDirs: string[] = [];
function tempProject(lock: unknown, prefix = "agent-audit-"): string {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  tempDirs.push(dir);
  writeFileSync(join(dir, "package-lock.json"), JSON.stringify(lock), "utf8");
  return dir;
}

afterAll(() => {
  for (const dir of tempDirs) rmSync(dir, { recursive: true, force: true });
});

// ---------------------------------------------------------------------------
// AC 2 — a `last_affected` range with no `fixed` event
// ---------------------------------------------------------------------------

describe("last_affected range boundaries", () => {
  const range: OsvRange = {
    type: "SEMVER",
    events: [{ introduced: "2.12.0" }, { last_affected: "2.31.0" }],
  };

  // A miss here is a vulnerable install reported as clean, so both sides of
  // each boundary are pinned.
  it.each([
    ["2.11.9", false, "one patch below introduced"],
    ["2.12.0", true, "exactly at introduced"],
    ["2.12.1", true, "one patch above introduced"],
    ["2.30.9", true, "one patch below last_affected"],
    ["2.31.0", true, "exactly at last_affected"],
    ["2.31.1", false, "one patch above last_affected"],
    ["3.0.0", false, "a major above last_affected"],
    ["1.0.0", false, "a major below introduced"],
  ])("%s is affected=%s (%s)", (version, affected) => {
    expect(isAffectedByRange(version as string, range)).toBe(affected);
  });

  it("still flags a prerelease of the last affected version", () => {
    // 2.31.0-beta.1 precedes 2.31.0, so it carries the vulnerable code.
    expect(isAffectedByRange("2.31.0-beta.1", range)).toBe(true);
    expect(isAffectedByRange("2.31.0-rc.10", range)).toBe(true);
    expect(isAffectedByRange("2.13.0-0", range)).toBe(true);
    expect(isAffectedByRange("2.12.1-beta.1", range)).toBe(true);
  });

  it("does not let build metadata hide a hit", () => {
    expect(isAffectedByRange("2.31.0+build.5", range)).toBe(true);
    expect(isAffectedByRange("2.20.0+20261120", range)).toBe(true);
  });

  it("treats a prerelease of the fixed version as still affected", () => {
    const fixedRange: OsvRange = {
      type: "SEMVER",
      events: [{ introduced: "2.0.0" }, { fixed: "2.23.0" }],
    };
    // A beta of the fix is not the fix.
    expect(isAffectedByRange("2.23.0-beta.1", fixedRange)).toBe(true);
    expect(isAffectedByRange("2.23.0", fixedRange)).toBe(false);
  });

  it("reports no fix for every version inside the window", () => {
    const db = [
      advisory("NOFIX", { mitigation: "Reject non-canonical signatures" }, [
        { package: { ecosystem: "npm", name: "pkg" }, ranges: [range] },
      ]),
    ];
    for (const version of ["2.12.0", "2.20.0", "2.31.0", "2.31.0-beta.1"]) {
      const found = matchAdvisories(one(version), db).findings;
      expect(found, version).toHaveLength(1);
      expect(found[0]?.fixedIn, version).toBeUndefined();
      expect("fixedIn" in found[0]!, version).toBe(false);
    }
  });

  it("ignores a range type it does not understand", () => {
    const ecosystem: OsvRange = {
      type: "ECOSYSTEM",
      events: [{ introduced: "2.12.0" }, { last_affected: "2.31.0" }],
    };
    expect(isAffectedByRange("2.20.0", ecosystem)).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// AC 1 — the chain filter must fail open
// ---------------------------------------------------------------------------

describe("chain filter fails open", () => {
  const db = [
    advisory("EVM_ONLY", { chains: ["evm"] }),
    advisory("SOLANA_ONLY", { chains: ["solana"] }),
    advisory("BOTH", { chains: ["evm", "solana"] }),
    advisory("EMPTY", { chains: [] }),
    advisory("ABSENT"),
  ];

  it("shows everything when no chain is requested", () => {
    expect(ids(matchAdvisories(one("1.0.0"), db)).sort()).toEqual([
      "ABSENT",
      "BOTH",
      "EMPTY",
      "EVM_ONLY",
      "SOLANA_ONLY",
    ]);
  });

  it.each(["evm", "solana"] as const)(
    "never hides a chain-agnostic advisory under --chain %s",
    (chain) => {
      const got = ids(matchAdvisories(one("1.0.0"), db, { chain }));
      expect(got).toContain("EMPTY"); // chains: []
      expect(got).toContain("ABSENT"); // no chains key at all
      expect(got).toContain("BOTH"); // names both chains
    },
  );

  it("hides only an advisory that positively names another chain", () => {
    expect(ids(matchAdvisories(one("1.0.0"), db, { chain: "evm" })).sort()).toEqual([
      "ABSENT",
      "BOTH",
      "EMPTY",
      "EVM_ONLY",
    ]);
    expect(ids(matchAdvisories(one("1.0.0"), db, { chain: "solana" })).sort()).toEqual([
      "ABSENT",
      "BOTH",
      "EMPTY",
      "SOLANA_ONLY",
    ]);
  });

  it("loses no advisory across the two chains", () => {
    const union = new Set([
      ...ids(matchAdvisories(one("1.0.0"), db, { chain: "evm" })),
      ...ids(matchAdvisories(one("1.0.0"), db, { chain: "solana" })),
    ]);
    expect([...union].sort()).toEqual(ids(matchAdvisories(one("1.0.0"), db)).sort());
  });

  it("does not change the scan counters or the echoed chain", () => {
    const filtered = matchAdvisories(one("1.0.0"), db, { chain: "evm" });
    const unfiltered = matchAdvisories(one("1.0.0"), db);
    expect(filtered.advisoriesLoaded).toBe(unfiltered.advisoriesLoaded);
    expect(filtered.packagesScanned).toBe(unfiltered.packagesScanned);
    expect(filtered.chain).toBe("evm");
    expect(unfiltered.chain).toBeUndefined();
  });

  it("keeps invisibleToNpmAudit a subset of the filtered findings", () => {
    const db2 = [
      advisory("HIDDEN", { chains: ["solana"] }),
      advisory("SEEN", { chains: ["evm"], npm_audit_detects: true }),
    ];
    const r = matchAdvisories(one("1.0.0"), db2, { chain: "evm" });
    expect(ids(r)).toEqual(["SEEN"]);
    expect(r.invisibleToNpmAudit).toHaveLength(0);
  });

  it("combines with the role filter without either one widening the other", () => {
    const db3 = [
      advisory("EVM_CLIENT", { chains: ["evm"], roles: ["client"] }),
      advisory("SOLANA_CLIENT", { chains: ["solana"], roles: ["client"] }),
      advisory("AGNOSTIC_FACILITATOR", { roles: ["facilitator"] }),
    ];
    expect(ids(matchAdvisories(one("1.0.0"), db3, { chain: "evm", role: "client" }))).toEqual([
      "EVM_CLIENT",
    ]);
  });
});

describe("chain filter against the bundled database", () => {
  // Assertions are invariants, not counts, so a growing database cannot break them.
  const vulnerable = fixture("vulnerable-agent");
  const key = (f: Finding) => `${f.advisory.id}::${f.package.name}@${f.package.version}`;

  const all = audit(vulnerable);
  const evm = audit(vulnerable, { chain: "evm" });
  const solana = audit(vulnerable, { chain: "solana" });

  it("finds something to filter", () => {
    expect(all.findings.length).toBeGreaterThan(0);
  });

  it("only ever narrows the unfiltered result", () => {
    const allKeys = new Set(all.findings.map(key));
    for (const f of [...evm.findings, ...solana.findings]) {
      expect(allKeys.has(key(f)), key(f)).toBe(true);
    }
  });

  it("shows every chain-agnostic finding under both chains", () => {
    const evmKeys = new Set(evm.findings.map(key));
    const solanaKeys = new Set(solana.findings.map(key));
    const agnostic = all.findings.filter(
      (f) => (f.advisory.database_specific.chains ?? []).length === 0,
    );
    expect(agnostic.length, "the database should carry chain-agnostic entries").toBeGreaterThan(0);
    for (const f of agnostic) {
      expect(evmKeys.has(key(f)), `${key(f)} must survive --chain evm`).toBe(true);
      expect(solanaKeys.has(key(f)), `${key(f)} must survive --chain solana`).toBe(true);
    }
  });

  it("loses no finding across the two chains", () => {
    const union = new Set([...evm.findings.map(key), ...solana.findings.map(key)]);
    expect([...union].sort()).toEqual(all.findings.map(key).sort());
  });

  it("keeps every surviving finding relevant to the requested chain", () => {
    for (const [chain, r] of [
      ["evm", evm],
      ["solana", solana],
    ] as const) {
      for (const f of r.findings) {
        const chains = f.advisory.database_specific.chains ?? [];
        expect(chains.length === 0 || chains.includes(chain), key(f)).toBe(true);
      }
    }
  });
});

// ---------------------------------------------------------------------------
// Empty and degenerate input
// ---------------------------------------------------------------------------

describe("degenerate input", () => {
  it("scans a lockfile that declares no packages", () => {
    const dir = tempProject({
      name: "empty",
      lockfileVersion: 3,
      packages: { "": { name: "empty" } },
    });
    const scanned = scanLockfile(dir);
    expect(scanned.packages).toHaveLength(0);

    const r = matchAdvisories(scanned, loadAdvisories());
    expect(r.findings).toHaveLength(0);
    expect(r.packagesScanned).toBe(0);
    expect(r.advisoriesLoaded).toBeGreaterThan(0);
    expect(renderText(r)).toContain("No known vulnerable agent-payment SDK versions found");
    expect(JSON.parse(renderJson(r)).packagesScanned).toBe(0);
  });

  it("matches nothing when the advisory has an empty ranges array", () => {
    const db = [
      advisory("NO_RANGES", {}, [{ package: { ecosystem: "npm", name: "pkg" }, ranges: [] }]),
    ];
    expect(matchAdvisories(one("2.0.0"), db).findings).toHaveLength(0);
  });

  it("matches nothing when a range has no events", () => {
    const db = [
      advisory("NO_EVENTS", {}, [
        { package: { ecosystem: "npm", name: "pkg" }, ranges: [{ type: "SEMVER", events: [] }] },
      ]),
    ];
    expect(matchAdvisories(one("2.0.0"), db).findings).toHaveLength(0);
  });

  it("matches nothing when the affected entry has neither ranges nor versions", () => {
    const db = [advisory("BARE", {}, [{ package: { ecosystem: "npm", name: "pkg" } }])];
    expect(matchAdvisories(one("2.0.0"), db).findings).toHaveLength(0);
  });

  it("ignores an affected entry from another ecosystem", () => {
    const db = [
      advisory("PYPI", {}, [
        {
          package: { ecosystem: "PyPI", name: "pkg" },
          ranges: [{ type: "SEMVER", events: [{ introduced: "0" }] }],
        },
      ]),
    ];
    expect(matchAdvisories(one("2.0.0"), db).findings).toHaveLength(0);
  });

  it("still matches the npm entry of a mixed-ecosystem advisory", () => {
    const db = [
      advisory("MIXED", {}, [
        {
          package: { ecosystem: "PyPI", name: "pkg" },
          ranges: [{ type: "SEMVER", events: [{ introduced: "0" }] }],
        },
        {
          package: { ecosystem: "npm", name: "pkg" },
          ranges: [
            { type: "SEMVER", events: [{ introduced: "1.0.0" }, { last_affected: "2.0.0" }] },
          ],
        },
      ]),
    ];
    const found = matchAdvisories(one("2.0.0"), db).findings;
    expect(found).toHaveLength(1);
    expect(found[0]?.fixedIn).toBeUndefined();
  });

  it("matches an exact version list with no ranges", () => {
    const db = [
      advisory("EXACT", {}, [
        { package: { ecosystem: "npm", name: "pkg" }, versions: ["2.0.0", "2.1.0"] },
      ]),
    ];
    expect(ids(matchAdvisories(one("2.0.0"), db))).toEqual(["EXACT"]);
    expect(matchAdvisories(one("2.2.0"), db).findings).toHaveLength(0);
  });

  it("does not throw or false-positive on a non-semver lockfile version", () => {
    const db = [advisory("ANY")]; // introduced: 0, so it would match any real version
    for (const version of ["workspace:*", "latest", "file:../local", ""]) {
      expect(() => matchAdvisories(one(version), db), version).not.toThrow();
      expect(matchAdvisories(one(version), db).findings, version).toHaveLength(0);
    }
  });

  it("renders an empty result through every renderer", () => {
    const empty = resultOf([]);
    expect(() => renderText(empty)).not.toThrow();
    expect(renderSummary(empty).split("\n")).toHaveLength(1);
    expect(JSON.parse(renderJson(empty)).findings).toEqual([]);
  });

  it("handles an empty advisory database", () => {
    const r = matchAdvisories(one("2.0.0"), []);
    expect(r.findings).toHaveLength(0);
    expect(r.advisoriesLoaded).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// AC 2 — "No fix available" in the text report
// ---------------------------------------------------------------------------

describe("no-fix reporting", () => {
  const noFix = (mitigation?: string): Finding => ({
    advisory: advisory("NOFIX", mitigation ? { mitigation } : {}),
    package: { name: "@x402/evm", version: "2.31.0" },
  });

  it("never glues the mitigation onto the Fix line", () => {
    const text = renderText(resultOf([noFix("Reject non-canonical ECDSA signatures.")]));
    const lines = text.split("\n");
    const fixLine = lines.find((l) => l.includes("No fix available"));
    expect(fixLine).toBeDefined();
    expect(fixLine).toContain("No fix available — mitigation required");
    expect(fixLine).not.toContain("Reject non-canonical");
    expect(lines.some((l) => l.trimStart().startsWith("Mitigate:"))).toBe(true);
    expect(text).toContain("Reject non-canonical ECDSA signatures.");
  });

  it("prints no upgrade advice when there is no fix", () => {
    const text = renderText(resultOf([noFix("do this instead")]));
    expect(text).not.toContain("upgrade @x402/evm to");
    expect(text).toContain("1 with no fix");
  });

  it("still prints the no-fix line when the advisory carries no mitigation", () => {
    const text = renderText(resultOf([noFix()]));
    expect(text).toContain("No fix available — mitigation required");
    expect(text).not.toContain("Mitigate:");
    expect(text).toContain("1 with no fix");
  });

  it("omits the no-fix tally when every finding has a fix", () => {
    const fixed: Finding = {
      advisory: advisory("FIXED"),
      package: { name: "@x402/core", version: "2.22.0" },
      fixedIn: "2.23.0",
    };
    const text = renderText(resultOf([fixed]));
    expect(text).toContain("upgrade @x402/core to >=2.23.0");
    expect(text).not.toContain("No fix available");
    expect(text).not.toContain("with no fix");
  });

  it("wraps a mitigation that holds one very long unbreakable token", () => {
    const url = `https://example.invalid/${"a".repeat(120)}`;
    const text = renderText(resultOf([noFix(`See ${url} for details.`)]));
    const mitigateLine = text.split("\n").find((l) => l.trimStart().startsWith("Mitigate:"));
    expect(mitigateLine).toBeDefined();
    expect(mitigateLine).not.toContain("No fix available");
    expect(text).toContain(url);
  });

  it("counts mixed fixed and unfixed findings separately", () => {
    const mixed = resultOf([
      noFix("mitigate me"),
      { advisory: advisory("B"), package: { name: "b", version: "1.0.0" }, fixedIn: "2.0.0" },
      { advisory: advisory("C"), package: { name: "c", version: "1.0.0" } },
    ]);
    expect(renderText(mixed)).toContain("2 with no fix");
    expect(JSON.parse(renderJson(mixed)).noFixCount).toBe(2);
  });

  it("reports the real @x402/evm no-fix advisory with no fixedIn", () => {
    const result = audit(fixture("evm-agent"));
    const noFixFindings = result.findings.filter((f) => f.fixedIn === undefined);
    expect(noFixFindings.length).toBeGreaterThan(0);
    const text = renderText(result);
    expect(text).toContain("No fix available — mitigation required");
    for (const f of noFixFindings) {
      const mitigation = f.advisory.database_specific.mitigation;
      expect(mitigation, `${f.advisory.id} needs a mitigation`).toBeTruthy();
      // The first words of the mitigation must appear on their own line.
      const firstWords = mitigation!.split(/\s+/).slice(0, 3).join(" ");
      const line = text.split("\n").find((l) => l.includes(firstWords));
      expect(line, firstWords).toBeDefined();
      expect(line).not.toContain("No fix available");
    }
  });
});

describe("fixedVersionFor", () => {
  it("returns undefined for a range that only has last_affected", () => {
    const a = advisory("NOFIX", {}, [
      {
        package: { ecosystem: "npm", name: "pkg" },
        ranges: [
          { type: "SEMVER", events: [{ introduced: "2.12.0" }, { last_affected: "2.31.0" }] },
        ],
      },
    ]);
    expect(fixedVersionFor(a, "pkg")).toBeUndefined();
  });

  it("returns undefined for a package the advisory does not name", () => {
    expect(fixedVersionFor(advisory("A"), "not-this-one")).toBeUndefined();
  });

  it("reads the fix from the entry for the requested package only", () => {
    const a = advisory("TWO", {}, [
      {
        package: { ecosystem: "npm", name: "alpha" },
        ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "1.1.0" }] }],
      },
      {
        package: { ecosystem: "npm", name: "beta" },
        ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "2.2.0" }] }],
      },
    ]);
    expect(fixedVersionFor(a, "alpha")).toBe("1.1.0");
    expect(fixedVersionFor(a, "beta")).toBe("2.2.0");
  });
});

// ---------------------------------------------------------------------------
// AC 4 — renderSummary
// ---------------------------------------------------------------------------

describe("renderSummary shape", () => {
  const lines = (r: ScanResult) => renderSummary(r).split("\n");

  it("is exactly one header line when there are no findings", () => {
    const out = lines(resultOf([]));
    expect(out).toHaveLength(1);
    expect(out[0]).toContain("0 findings");
    expect(out[0]).toContain("0 with no fix");
    expect(renderSummary(resultOf([])).endsWith("\n")).toBe(false);
  });

  it("is header plus one line for a single finding", () => {
    const out = lines(
      resultOf([
        { advisory: advisory("A"), package: { name: "p", version: "1.0.0" }, fixedIn: "2.0.0" },
      ]),
    );
    expect(out).toHaveLength(2);
    expect(out[0]).toContain("1 finding ");
    expect(out[0]).not.toContain("1 findings");
    expect(out[1]).toContain("fix >=2.0.0");
    expect(out[1]).not.toContain("no fix");
  });

  it("marks a finding with no fix", () => {
    const out = lines(
      resultOf([{ advisory: advisory("A"), package: { name: "p", version: "1.0.0" } }]),
    );
    expect(out).toHaveLength(2);
    expect(out[1]).toContain("no fix");
    expect(out[1]).not.toContain("fix >=");
    expect(out[0]).toContain("1 with no fix");
  });

  it("keeps exactly one line per finding however many there are", () => {
    for (const count of [1, 2, 5, 20]) {
      const findings = Array.from({ length: count }, (_, i) => ({
        advisory: advisory(`A${i}`),
        package: { name: `p${i}`, version: "1.0.0" },
      }));
      expect(lines(resultOf(findings)), `${count} findings`).toHaveLength(count + 1);
    }
  });

  it("never spills the multi-line advisory details into the summary", () => {
    const wordy = advisory("WORDY", { mitigation: "line one\nline two" });
    wordy.summary = "a summary\nwith a newline";
    wordy.details = "details\nover\nlines";
    const out = lines(resultOf([{ advisory: wordy, package: { name: "p", version: "1.0.0" } }]));
    expect(out).toHaveLength(2);
    expect(out[1]).toContain("WORDY");
    expect(out[1]).not.toContain("with a newline");
  });

  it("names the lockfile and both tallies in the header", () => {
    const r = resultOf([
      {
        advisory: advisory("A", { npm_audit_detects: true }),
        package: { name: "p", version: "1.0.0" },
        fixedIn: "2.0.0",
      },
      { advisory: advisory("B"), package: { name: "q", version: "1.0.0" } },
    ]);
    const header = lines(r)[0]!;
    expect(header.startsWith("agent-audit · package-lock.json · ")).toBe(true);
    expect(header).toContain("2 findings");
    expect(header).toContain("1 invisible to npm audit");
    expect(header).toContain("1 with no fix");
  });

  it("marks hidden findings and leaves visible ones unmarked", () => {
    const r = resultOf([
      { advisory: advisory("HIDDEN"), package: { name: "p", version: "1.0.0" } },
      {
        advisory: advisory("SEEN", { npm_audit_detects: true }),
        package: { name: "q", version: "1.0.0" },
      },
    ]);
    const out = lines(r);
    expect(out[1]).toContain("hidden");
    expect(out[2]).not.toContain("hidden");
  });
});

// ---------------------------------------------------------------------------
// Ordering
// ---------------------------------------------------------------------------

describe("finding order", () => {
  it("sorts severity high to low", () => {
    const db = [
      advisory("LOW_ONE", { severity: "LOW" }),
      advisory("CRIT", { severity: "CRITICAL" }),
      advisory("MOD", { severity: "MODERATE" }),
      advisory("HIGH_ONE", { severity: "HIGH" }),
    ];
    expect(ids(matchAdvisories(one("1.0.0"), db))).toEqual(["CRIT", "HIGH_ONE", "MOD", "LOW_ONE"]);
  });

  it("puts the findings npm audit misses first within one severity", () => {
    const db = [
      advisory("SEEN", { severity: "HIGH", npm_audit_detects: true }),
      advisory("HIDDEN", { severity: "HIGH", npm_audit_detects: false }),
    ];
    expect(ids(matchAdvisories(one("1.0.0"), db))).toEqual(["HIDDEN", "SEEN"]);
    // Declaration order must not decide it.
    expect(ids(matchAdvisories(one("1.0.0"), [...db].reverse()))).toEqual(["HIDDEN", "SEEN"]);
  });

  it("does not let hidden-first override severity", () => {
    const db = [
      advisory("HIDDEN_LOW", { severity: "LOW", npm_audit_detects: false }),
      advisory("SEEN_CRIT", { severity: "CRITICAL", npm_audit_detects: true }),
    ];
    expect(ids(matchAdvisories(one("1.0.0"), db))).toEqual(["SEEN_CRIT", "HIDDEN_LOW"]);
  });

  it("falls back to package name within one severity and visibility", () => {
    const db = [
      advisory("ZETA", { severity: "HIGH" }, [
        {
          package: { ecosystem: "npm", name: "zeta" },
          ranges: [{ type: "SEMVER", events: [{ introduced: "0" }] }],
        },
      ]),
      advisory("ALPHA", { severity: "HIGH" }, [
        {
          package: { ecosystem: "npm", name: "alpha" },
          ranges: [{ type: "SEMVER", events: [{ introduced: "0" }] }],
        },
      ]),
    ];
    const scan = target([
      { name: "zeta", version: "1.0.0" },
      { name: "alpha", version: "1.0.0" },
    ]);
    expect(matchAdvisories(scan, db).findings.map((f) => f.package.name)).toEqual(["alpha", "zeta"]);
  });

  it("deduplicates the same advisory reaching the same package twice", () => {
    const scan = target([
      { name: "pkg", version: "1.0.0", path: "node_modules/pkg" },
      { name: "pkg", version: "1.0.0", path: "node_modules/a/node_modules/pkg" },
    ]);
    const r = matchAdvisories(scan, [advisory("DUP")]);
    expect(r.findings).toHaveLength(1);
    expect(r.packagesScanned).toBe(2);
  });

  it("keeps distinct versions of one package apart", () => {
    const scan = target([
      { name: "pkg", version: "1.0.0" },
      { name: "pkg", version: "1.1.0" },
    ]);
    expect(matchAdvisories(scan, [advisory("DUP")]).findings).toHaveLength(2);
  });
});

// ---------------------------------------------------------------------------
// AC 5 — JSON output is additive
// ---------------------------------------------------------------------------

describe("JSON back-compatibility with v0.1", () => {
  const V01_TOP = [
    "lockfile",
    "lockfilePath",
    "packagesScanned",
    "advisoriesLoaded",
    "findingCount",
    "invisibleToNpmAuditCount",
    "findings",
  ];
  const V01_FINDING = [
    "id",
    "package",
    "version",
    "severity",
    "summary",
    "impact",
    "fixedIn",
    "source",
    "confidence",
    "npmAuditDetects",
    "hasUpstreamAdvisory",
    "roles",
    "references",
  ];

  const sample = (): ScanResult => {
    const a = advisory("AAUD-2026-9999", {
      severity: "CRITICAL",
      source: "derived",
      confidence: "medium",
      has_upstream_advisory: false,
      npm_audit_detects: false,
      roles: ["client"],
      chains: ["solana"],
      mitigation: "pin the dependency",
    });
    a.references = [{ type: "ADVISORY", url: "https://example.invalid/a" }];
    return resultOf(
      [
        { advisory: a, package: { name: "@x402/svm", version: "2.22.0" } },
        {
          advisory: advisory("B", { npm_audit_detects: true }),
          package: { name: "@x402/core", version: "2.22.0" },
          fixedIn: "2.23.0",
        },
      ],
      "solana",
    );
  };

  it("keeps every v0.1 top-level key", () => {
    const json = JSON.parse(renderJson(sample()));
    for (const k of V01_TOP) expect(Object.keys(json), k).toContain(k);
  });

  it("keeps every v0.1 per-finding key", () => {
    const json = JSON.parse(renderJson(sample()));
    for (const f of json.findings) {
      for (const k of V01_FINDING) expect(Object.keys(f), k).toContain(k);
    }
  });

  it("adds only chain and noFixCount at the top level", () => {
    const json = JSON.parse(renderJson(sample()));
    expect(Object.keys(json).sort()).toEqual([...V01_TOP, "chain", "noFixCount"].sort());
  });

  it("adds only chains and mitigation per finding", () => {
    const json = JSON.parse(renderJson(sample()));
    expect(Object.keys(json.findings[0]).sort()).toEqual(
      [...V01_FINDING, "chains", "mitigation"].sort(),
    );
  });

  it("keeps the old keys meaning what they meant", () => {
    const r = sample();
    const json = JSON.parse(renderJson(r));
    expect(json.lockfile).toBe(r.target.lockfile);
    expect(json.lockfilePath).toBe(r.target.path);
    expect(json.packagesScanned).toBe(r.packagesScanned);
    expect(json.advisoriesLoaded).toBe(r.advisoriesLoaded);
    expect(json.findingCount).toBe(r.findings.length);
    expect(json.invisibleToNpmAuditCount).toBe(r.invisibleToNpmAudit.length);
    expect(json.findings).toHaveLength(r.findings.length);

    const first = json.findings[0];
    expect(first.id).toBe("AAUD-2026-9999");
    expect(first.package).toBe("@x402/svm");
    expect(first.version).toBe("2.22.0");
    expect(first.severity).toBe("CRITICAL");
    expect(first.source).toBe("derived");
    expect(first.confidence).toBe("medium");
    expect(first.npmAuditDetects).toBe(false);
    expect(first.hasUpstreamAdvisory).toBe(false);
    expect(first.roles).toEqual(["client"]);
    expect(first.references).toEqual(["https://example.invalid/a"]);
    expect(first.fixedIn).toBeNull();
    expect(json.findings[1].fixedIn).toBe("2.23.0");
  });

  it("uses null, not a missing key, for an absent chain or mitigation", () => {
    const json = JSON.parse(
      renderJson(resultOf([{ advisory: advisory("A"), package: { name: "p", version: "1.0.0" } }])),
    );
    expect(json.chain).toBeNull();
    expect("chain" in json).toBe(true);
    expect(json.findings[0].mitigation).toBeNull();
    expect(json.findings[0].chains).toEqual([]);
    expect(json.findings[0].roles).toEqual([]);
    expect(json.noFixCount).toBe(1);
  });

  it("emits parseable JSON for the real database", () => {
    const json = JSON.parse(renderJson(audit(fixture("vulnerable-agent"))));
    expect(json.findingCount).toBe(json.findings.length);
    expect(json.noFixCount).toBe(
      json.findings.filter((f: { fixedIn: string | null }) => f.fixedIn === null).length,
    );
    for (const f of json.findings) expect(Array.isArray(f.chains)).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Paths
// ---------------------------------------------------------------------------

describe("path handling", () => {
  const dir = () =>
    tempProject(
      {
        name: "p",
        lockfileVersion: 3,
        packages: {
          "": { name: "p" },
          "node_modules/@x402/evm": { version: "2.20.0" },
        },
      },
      "agent audit ", // a space, like "Program Files"
    );

  it("accepts a direct path to the lockfile", () => {
    const file = join(dir(), "package-lock.json");
    expect(findLockfile(file)).toEqual({ path: file, kind: "package-lock.json" });
    expect(scanLockfile(file).packages).toHaveLength(1);
  });

  it("accepts a directory whose name contains a space", () => {
    const d = dir();
    expect(d).toContain(" ");
    expect(scanLockfile(d).packages[0]?.name).toBe("@x402/evm");
  });

  it("accepts a directory path with a trailing separator", () => {
    const scanned = scanLockfile(dir() + sep);
    expect(scanned.packages).toHaveLength(1);
  });

  it("reports the lockfile path verbatim, separators and all", () => {
    const d = dir();
    const scanned = scanLockfile(d);
    expect(scanned.path).toBe(join(d, "package-lock.json"));
    const json = JSON.parse(renderJson(matchAdvisories(scanned, loadAdvisories())));
    expect(json.lockfilePath).toBe(scanned.path);
  });

  it.runIf(process.platform === "win32")("accepts a backslash path on Windows", () => {
    const d = dir().split("/").join("\\");
    expect(scanLockfile(d).packages).toHaveLength(1);
    expect(scanLockfile(`${d}\\package-lock.json`).packages).toHaveLength(1);
  });

  it.runIf(process.platform === "win32")("accepts a forward-slash path on Windows", () => {
    const d = dir().split("\\").join("/");
    expect(scanLockfile(d).packages).toHaveLength(1);
  });

  it("strips nested node_modules prefixes to the bare package name", () => {
    const d = tempProject({
      name: "p",
      lockfileVersion: 3,
      packages: {
        "": { name: "p" },
        "node_modules/a/node_modules/@x402/evm": { version: "2.20.0" },
      },
    });
    expect(scanLockfile(d).packages[0]?.name).toBe("@x402/evm");
  });

  it("errors with the path it looked in when no lockfile exists", () => {
    const missing = join(tmpdir(), "agent-audit-no-such-dir-29381");
    expect(() => scanLockfile(missing)).toThrow(/No lockfile found/);
  });
});

// ---------------------------------------------------------------------------
// AC 3 — CLI flags
// ---------------------------------------------------------------------------

const viteNode = resolve(root, "node_modules", "vite-node", "vite-node.mjs");
const cliEntry = resolve(root, "src", "cli.ts");
const cliAvailable = existsSync(viteNode) && existsSync(cliEntry);

function runCli(args: string[]): { status: number; stdout: string; stderr: string } {
  const r = spawnSync(process.execPath, [viteNode, cliEntry, "--", ...args], {
    cwd: root,
    encoding: "utf8",
    env: { ...process.env, NO_COLOR: "1" },
  });
  return { status: r.status ?? -1, stdout: r.stdout ?? "", stderr: r.stderr ?? "" };
}

describe.runIf(cliAvailable)("CLI flags", () => {
  it(
    "exits 2 when --summary and --json are combined",
    () => {
      const r = runCli(["--summary", "--json"]);
      expect(r.status).toBe(2);
      expect(r.stderr).toContain("--summary and --json cannot be combined");
      expect(r.stdout).toBe("");
    },
    60_000,
  );

  it(
    "exits 2 whichever order the two flags are given in",
    () => {
      expect(runCli(["--json", "--summary"]).status).toBe(2);
    },
    60_000,
  );

  it(
    "rejects a chain it does not know",
    () => {
      const r = runCli(["--chain", "bitcoin"]);
      expect(r.status).toBe(2);
      expect(r.stderr).toContain("--chain must be one of: evm, solana");
    },
    60_000,
  );

  it(
    "rejects --chain with no value",
    () => {
      expect(runCli([fixture("vulnerable-agent"), "--chain"]).status).toBe(2);
    },
    60_000,
  );

  it(
    "accepts both known chains",
    () => {
      for (const chain of ["evm", "solana"]) {
        const r = runCli([fixture("patched-agent"), "--chain", chain]);
        expect(r.status, chain).toBe(0);
        expect(r.stdout, chain).toContain("No known vulnerable");
      }
    },
    60_000,
  );

  it(
    "prints one summary line per finding and exits 1",
    () => {
      const r = runCli([fixture("vulnerable-agent"), "--summary"]);
      expect(r.status).toBe(1);
      const lines = r.stdout.replace(/\n$/, "").split("\n");
      const count = Number(/· (\d+) finding/.exec(lines[0] ?? "")?.[1]);
      expect(count).toBeGreaterThan(0);
      expect(lines).toHaveLength(count + 1);
    },
    60_000,
  );

  it(
    "prints only the header line for a clean project under --summary",
    () => {
      const r = runCli([fixture("patched-agent"), "--summary"]);
      expect(r.status).toBe(0);
      expect(r.stdout.replace(/\n$/, "").split("\n")).toHaveLength(1);
      expect(r.stdout).toContain("0 findings");
    },
    60_000,
  );

  it(
    "emits valid JSON carrying the new keys under --chain",
    () => {
      const r = runCli([fixture("vulnerable-agent"), "--chain", "evm", "--json"]);
      const json = JSON.parse(r.stdout);
      expect(json.chain).toBe("evm");
      expect(typeof json.noFixCount).toBe("number");
      expect(json.findingCount).toBe(json.findings.length);
    },
    60_000,
  );
});

import { describe, expect, it } from "vitest";
import { matchAdvisories } from "../src/match.js";
import type { Advisory, Chain, ScanTarget } from "../src/types.js";

function adv(id: string, chains?: Chain[], events: Record<string, string>[] = [{ introduced: "0" }]): Advisory {
  return {
    schema_version: "1.6.0",
    id,
    modified: "2026-01-01T00:00:00Z",
    published: "2026-01-01T00:00:00Z",
    summary: id,
    details: id,
    affected: [
      { package: { ecosystem: "npm", name: "pkg" }, ranges: [{ type: "SEMVER", events }] },
    ],
    database_specific: {
      severity: "HIGH",
      source: "advisory",
      confidence: "high",
      has_upstream_advisory: true,
      npm_audit_detects: false,
      impact_summary: id,
      ...(chains ? { chains } : {}),
    },
  };
}

function target(version: string): ScanTarget {
  return {
    lockfile: "package-lock.json",
    path: "package-lock.json",
    packages: [{ name: "pkg", version }],
  };
}

const ids = (r: { findings: { advisory: Advisory }[] }) => r.findings.map((f) => f.advisory.id);

describe("chain filter", () => {
  const advisories = [adv("EVM", ["evm"]), adv("NONE"), adv("EMPTY", [])];

  it("hides an EVM-only advisory under solana", () => {
    expect(ids(matchAdvisories(target("1.0.0"), advisories, { chain: "solana" })).sort()).toEqual([
      "EMPTY",
      "NONE",
    ]);
  });

  it("shows chain-agnostic advisories under both chains", () => {
    for (const chain of ["evm", "solana"] as const) {
      const got = ids(matchAdvisories(target("1.0.0"), advisories, { chain }));
      expect(got).toContain("NONE");
      expect(got).toContain("EMPTY");
    }
    expect(ids(matchAdvisories(target("1.0.0"), advisories, { chain: "evm" }))).toContain("EVM");
  });

  it("does not filter without a chain option", () => {
    const result = matchAdvisories(target("1.0.0"), advisories);
    expect(ids(result).sort()).toEqual(["EMPTY", "EVM", "NONE"]);
    expect(result.chain).toBeUndefined();
  });

  it("echoes the chain option", () => {
    expect(matchAdvisories(target("1.0.0"), advisories, { chain: "solana" }).chain).toBe("solana");
  });
});

describe("last_affected range with no fix", () => {
  const range = [adv("NOFIX", undefined, [{ introduced: "2.12.0" }, { last_affected: "2.31.0" }])];

  it.each([
    ["2.12.0", true],
    ["2.31.0", true],
    ["2.11.9", false],
    ["2.31.1", false],
  ])("version %s matches=%s", (version, hit) => {
    expect(matchAdvisories(target(version), range).findings.length).toBe(hit ? 1 : 0);
  });

  it("leaves fixedIn undefined", () => {
    const [finding] = matchAdvisories(target("2.20.0"), range).findings;
    expect(finding).toBeDefined();
    expect(finding?.fixedIn).toBeUndefined();
  });
});

import { describe, expect, it } from "vitest";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { loadAdvisories } from "../src/db.js";
import { scanLockfile } from "../src/lockfiles.js";
import { isAffectedByRange, matchAdvisories } from "../src/match.js";
import { audit } from "../src/index.js";
import type { OsvRange } from "../src/types.js";

const here = dirname(fileURLToPath(import.meta.url));
const fixture = (name: string) => resolve(here, "fixtures", name);

describe("advisory database", () => {
  const advisories = loadAdvisories();

  it("loads every bundled advisory", () => {
    expect(advisories.length).toBeGreaterThanOrEqual(6);
  });

  it("gives every advisory a unique id", () => {
    const ids = advisories.map((a) => a.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it("requires provenance on derived entries", () => {
    for (const a of advisories) {
      if (a.database_specific.source === "derived") {
        expect(a.database_specific.provenance, `${a.id} must document provenance`).toBeTruthy();
      }
    }
  });

  it("marks derived entries as invisible to npm audit", () => {
    for (const a of advisories) {
      if (a.database_specific.source === "derived") {
        expect(a.database_specific.npm_audit_detects, `${a.id}`).toBe(false);
        expect(a.database_specific.has_upstream_advisory, `${a.id}`).toBe(false);
      }
    }
  });

  it("only targets npm packages for now", () => {
    for (const a of advisories) {
      for (const affected of a.affected) {
        expect(affected.package.ecosystem).toBe("npm");
      }
    }
  });
});

describe("OSV range evaluation", () => {
  const range: OsvRange = {
    type: "SEMVER",
    events: [{ introduced: "2.0.0" }, { fixed: "2.23.0" }],
  };

  it("includes the introduced boundary", () => {
    expect(isAffectedByRange("2.0.0", range)).toBe(true);
  });

  it("excludes the fixed boundary", () => {
    expect(isAffectedByRange("2.23.0", range)).toBe(false);
  });

  it("flags a version inside the window", () => {
    expect(isAffectedByRange("2.22.0", range)).toBe(true);
  });

  it("ignores versions below the window", () => {
    expect(isAffectedByRange("1.9.9", range)).toBe(false);
  });

  it("ignores versions above the fix", () => {
    expect(isAffectedByRange("2.31.0", range)).toBe(false);
  });

  it("handles an open-ended introduced:0 range", () => {
    const open: OsvRange = { type: "SEMVER", events: [{ introduced: "0" }, { fixed: "2.6.0" }] };
    expect(isAffectedByRange("0.1.0", open)).toBe(true);
    expect(isAffectedByRange("2.5.9", open)).toBe(true);
    expect(isAffectedByRange("2.6.0", open)).toBe(false);
  });
});

describe("lockfile parsing", () => {
  it("parses a v3 package-lock.json", () => {
    const target = scanLockfile(fixture("vulnerable-agent"));
    expect(target.lockfile).toBe("package-lock.json");
    const names = target.packages.map((p) => p.name);
    expect(names).toContain("@x402/svm");
    expect(names).toContain("@solana/kit");
    expect(names).not.toContain("");
    const svm = target.packages.find((p) => p.name === "@x402/svm");
    expect(svm?.version).toBe("2.22.0");
  });

  it("parses a pnpm-lock.yaml", () => {
    const target = scanLockfile(fixture("pnpm-agent"));
    expect(target.lockfile).toBe("pnpm-lock.yaml");
    const svm = target.packages.find((p) => p.name === "@x402/svm");
    expect(svm?.version).toBe("2.22.0");
    const kit = target.packages.find((p) => p.name === "@solana/kit");
    expect(kit?.version).toBe("8.6.0");
  });

  it("parses a classic yarn.lock", () => {
    const target = scanLockfile(fixture("yarn-agent"));
    expect(target.lockfile).toBe("yarn.lock");
    const svm = target.packages.find((p) => p.name === "@x402/svm");
    expect(svm?.version).toBe("2.22.0");
    const semverPkg = target.packages.find((p) => p.name === "semver");
    expect(semverPkg?.version).toBe("7.6.3");
  });

  it("errors clearly when no lockfile exists", () => {
    expect(() => scanLockfile(fixture("does-not-exist"))).toThrow(/No lockfile found/);
  });
});

describe("end to end", () => {
  it("finds the three critical derived issues in a vulnerable project", () => {
    const result = audit(fixture("vulnerable-agent"));
    const ids = result.findings.map((f) => f.advisory.id);

    expect(ids).toContain("AAUD-2026-0001"); // Solana payment bypass
    expect(ids).toContain("AAUD-2026-0002"); // no spend limit
    expect(ids).toContain("AAUD-2026-0003"); // SIWx origin binding
    expect(ids).toContain("AAUD-2026-0004"); // @x402/core < 2.27.0
  });

  it("reports findings npm audit cannot see", () => {
    const result = audit(fixture("vulnerable-agent"));
    expect(result.invisibleToNpmAudit.length).toBeGreaterThan(0);
    for (const finding of result.invisibleToNpmAudit) {
      expect(finding.advisory.database_specific.npm_audit_detects).toBe(false);
    }
  });

  it("sorts critical findings first", () => {
    const result = audit(fixture("vulnerable-agent"));
    expect(result.findings[0]?.advisory.database_specific.severity).toBe("CRITICAL");
  });

  it("names a fix version for every finding", () => {
    const result = audit(fixture("vulnerable-agent"));
    for (const finding of result.findings) {
      expect(finding.fixedIn, `${finding.advisory.id}`).toBeTruthy();
    }
  });

  it("reports nothing for a fully patched project", () => {
    const result = audit(fixture("patched-agent"));
    expect(result.findings).toHaveLength(0);
    expect(result.invisibleToNpmAudit).toHaveLength(0);
  });

  it("filters by role", () => {
    const result = audit(fixture("vulnerable-agent"), { role: "client" });
    for (const finding of result.findings) {
      const roles = finding.advisory.database_specific.roles ?? [];
      expect(roles.length === 0 || roles.includes("client")).toBe(true);
    }
    // The Solana facilitator bypass is not a client issue.
    expect(result.findings.map((f) => f.advisory.id)).not.toContain("AAUD-2026-0001");
  });

  it("filters by minimum severity", () => {
    const result = audit(fixture("vulnerable-agent"), { minSeverity: "CRITICAL" });
    for (const finding of result.findings) {
      expect(finding.advisory.database_specific.severity).toBe("CRITICAL");
    }
  });

  it("does not deduplicate distinct advisories on the same package", () => {
    const result = audit(fixture("vulnerable-agent"));
    const coreFindings = result.findings.filter((f) => f.package.name === "@x402/core");
    // @x402/core 2.22.0 is hit by both AAUD-2026-0002 and AAUD-2026-0004.
    expect(coreFindings.length).toBe(2);
  });
});

describe("matching is pure", () => {
  it("returns the same result for the same input", () => {
    const advisories = loadAdvisories();
    const target = scanLockfile(fixture("vulnerable-agent"));
    const a = matchAdvisories(target, advisories);
    const b = matchAdvisories(target, advisories);
    expect(a.findings.map((f) => f.advisory.id)).toEqual(b.findings.map((f) => f.advisory.id));
  });
});

import { describe, expect, it } from "vitest";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { loadAdvisories } from "../src/db.js";
import { audit } from "../src/index.js";

const here = dirname(fileURLToPath(import.meta.url));
const fixture = (name: string) => resolve(here, "fixtures", name);

describe("GHSA-5cgh-j82v-jvrj (@x402/evm, no patched version)", () => {
  it("flags a fully up-to-date evm-agent, with no fix to offer", () => {
    const result = audit(fixture("evm-agent"));
    expect(result.findings).toHaveLength(1);
    const finding = result.findings[0]!;
    expect(finding.advisory.id).toBe("GHSA-5cgh-j82v-jvrj");
    expect(finding.fixedIn).toBeUndefined();
    expect(result.invisibleToNpmAudit.map((f) => f.advisory.id)).toContain("GHSA-5cgh-j82v-jvrj");
  });

  it("still reports 0 findings for patched-agent", () => {
    expect(audit(fixture("patched-agent")).findings).toHaveLength(0);
  });
});

describe("advisory database invariants", () => {
  const advisories = loadAdvisories();

  it("keeps chains within evm and solana", () => {
    for (const a of advisories) {
      const chains = (a.database_specific as { chains?: string[] }).chains;
      if (chains) {
        for (const c of chains) expect(["evm", "solana"], `${a.id}`).toContain(c);
      }
    }
  });

  it("requires a mitigation when no range has a fixed event", () => {
    for (const a of advisories) {
      const hasFix = a.affected.some((aff) =>
        (aff.ranges ?? []).some((r) => r.events.some((e) => "fixed" in e)),
      );
      if (!hasFix) {
        expect(a.database_specific.mitigation, `${a.id} has no fix and needs a mitigation`).toBeTruthy();
      }
    }
  });
});

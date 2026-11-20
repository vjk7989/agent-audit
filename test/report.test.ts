import { describe, expect, it } from "vitest";
import { renderJson, renderSummary, renderText } from "../src/report.js";
import type { Chain, Finding, ScanResult } from "../src/types.js";

function finding(over: {
  id?: string;
  fixedIn?: string;
  chains?: Chain[];
  mitigation?: string;
}): Finding {
  return {
    package: { name: "@x402/core", version: "2.0.0" },
    ...(over.fixedIn ? { fixedIn: over.fixedIn } : {}),
    advisory: {
      schema_version: "1.6.0",
      id: over.id ?? "AAUD-TEST-1",
      summary: "test summary",
      database_specific: {
        severity: "HIGH",
        source: "derived",
        confidence: "high",
        has_upstream_advisory: false,
        npm_audit_detects: false,
        impact_summary: "test impact",
        ...(over.chains ? { chains: over.chains } : {}),
        ...(over.mitigation ? { mitigation: over.mitigation } : {}),
      },
    },
  } as Finding;
}

function result(findings: Finding[], chain?: Chain): ScanResult {
  return {
    target: { lockfile: "package-lock.json", path: "/tmp/package-lock.json" },
    findings,
    invisibleToNpmAudit: findings,
    advisoriesLoaded: 5,
    packagesScanned: 10,
    ...(chain ? { chain } : {}),
  } as ScanResult;
}

describe("renderText", () => {
  it("prints the no-fix line with mitigation", () => {
    const out = renderText(result([finding({ mitigation: "Disable the flag" })]));
    expect(out).toContain("Fix:      No fix available — mitigation required");
    expect(out).toContain("Mitigate: Disable the flag");
    expect(out).not.toMatch(/required: Disable/);
    expect(out).toContain("1 with no fix");
  });

  it("prints the upgrade line and no no-fix footer when fixed", () => {
    const out = renderText(result([finding({ fixedIn: "2.3.0" })]));
    expect(out).toContain("upgrade @x402/core to >=2.3.0");
    expect(out).not.toContain("No fix available");
    expect(out).not.toContain("no fix available");
  });

  it("labels chains", () => {
    expect(renderText(result([finding({ chains: ["evm"] })]))).toContain("Chain:    EVM");
    expect(renderText(result([finding({ chains: ["solana"] })]))).toContain("Chain:    Solana");
    expect(renderText(result([finding({})]))).toContain("Chain:    all chains");
    expect(renderText(result([finding({ chains: [] })]))).toContain("Chain:    all chains");
  });

  it("shows the chain in the header only when filtered", () => {
    expect(renderText(result([finding({})], "solana"))).toContain("· chain: Solana");
    expect(renderText(result([finding({})]))).not.toContain("· chain:");
  });

  it("names the chain on a filtered clean result", () => {
    const out = renderText(result([], "evm"));
    expect(out).toContain("for chain: EVM");
    expect(out).toContain("other chains were not checked");
  });

  it("keeps the plain all-clear when unfiltered", () => {
    const out = renderText(result([]));
    expect(out).toContain("No known vulnerable agent-payment SDK versions found.");
    expect(out).not.toContain("chain");
  });
});

describe("renderJson", () => {
  it("adds chain, noFixCount, chains and mitigation", () => {
    const json = JSON.parse(
      renderJson(
        result(
          [finding({ chains: ["solana"], mitigation: "m" }), finding({ id: "B", fixedIn: "1.0.0" })],
          "solana",
        ),
      ),
    );
    expect(json.chain).toBe("solana");
    expect(json.noFixCount).toBe(1);
    expect(json.findingCount).toBe(2);
    expect(json.findings[0].chains).toEqual(["solana"]);
    expect(json.findings[0].mitigation).toBe("m");
    expect(json.findings[0].fixedIn).toBeNull();
    expect(json.findings[1].chains).toEqual([]);
    expect(json.findings[1].mitigation).toBeNull();
    expect(json.findings[1].fixedIn).toBe("1.0.0");
  });

  it("emits chain null when unfiltered", () => {
    expect(JSON.parse(renderJson(result([]))).chain).toBeNull();
  });
});

describe("layout", () => {
  const long = "word ".repeat(80).trim();
  const out = renderText(
    result([finding({ mitigation: long, chains: ["evm"] }), finding({ id: "B", fixedIn: "1.0.0" })]),
  );

  it("keeps every line within 80 columns", () => {
    for (const line of out.split("\n")) expect(line.length).toBeLessThanOrEqual(80);
  });

  it("puts the id on the title line and uses a footer rule", () => {
    expect(out).toMatch(/1\. HIGH\s+@x402\/core@2\.0\.0 AAUD-TEST-1/);
    expect(out).toContain("─".repeat(60));
    expect(out).toContain("2 findings (2 high)");
    expect(out).toContain("2 invisible to npm audit · 1 with no fix");
  });
});

describe("renderSummary", () => {
  it("writes a header and one line per finding", () => {
    const lines = renderSummary(
      result([finding({}), finding({ id: "B", fixedIn: "1.0.0" })]),
    ).split("\n");
    expect(lines).toHaveLength(3);
    expect(lines[0]).toBe(
      "agent-audit · package-lock.json · 2 findings (2 high) · 2 invisible to npm audit · 1 with no fix",
    );
    expect(lines[1]).toMatch(/HIGH\s+@x402\/core@2\.0\.0\s+AAUD-TEST-1\s+no fix\s+hidden/);
    expect(lines[2]).toContain("fix >=1.0.0");
  });

  it("is a single header line with no findings", () => {
    const out = renderSummary(result([]));
    expect(out.split("\n")).toHaveLength(1);
    expect(out).toContain("0 findings");
  });
});

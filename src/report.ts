import type { Chain, Finding, ScanResult, Severity } from "./types.js";

const useColor =
  process.env["NO_COLOR"] === undefined &&
  process.env["TERM"] !== "dumb" &&
  Boolean(process.stdout.isTTY);

const paint = (code: string) => (s: string) => (useColor ? `\u001b[${code}m${s}\u001b[0m` : s);

const c = {
  bold: paint("1"),
  dim: paint("2"),
  red: paint("31"),
  green: paint("32"),
  yellow: paint("33"),
  blue: paint("34"),
  magenta: paint("35"),
  cyan: paint("36"),
};

const SEVERITY_LABEL: Record<Severity, (s: string) => string> = {
  CRITICAL: c.red,
  HIGH: c.red,
  MODERATE: c.yellow,
  LOW: c.dim,
};

function severityTag(severity: Severity): string {
  return SEVERITY_LABEL[severity](c.bold(severity.padEnd(8)));
}

const CHAIN_LABEL: Record<Chain, string> = { evm: "EVM", solana: "Solana" };

function chainLabel(chains: Chain[] | undefined): string {
  return chains && chains.length > 0 ? chains.map((x) => CHAIN_LABEL[x]).join(", ") : "all chains";
}

const INDENT = "   ";
const LABEL_WIDTH = 10;
const WIDTH = 80;

// Free text can run to several hundred characters, so it wraps under the label column.
function wrap(text: string, width: number): string[] {
  const out: string[] = [];
  let line = "";
  for (const word of text.split(/\s+/).filter(Boolean)) {
    if (line && line.length + 1 + word.length > width) {
      out.push(line);
      line = word;
    } else {
      line = line ? `${line} ${word}` : word;
    }
  }
  if (line) out.push(line);
  return out;
}

function field(label: string, text: string, style: (s: string) => string = (s) => s): string[] {
  const pad = " ".repeat(INDENT.length + LABEL_WIDTH);
  return wrap(text, WIDTH - pad.length).map(
    (l, i) => `${i === 0 ? `${INDENT}${c.dim(`${label}:`.padEnd(LABEL_WIDTH))}` : pad}${style(l)}`,
  );
}

function renderFinding(finding: Finding, index: number): string {
  const { advisory, package: pkg, fixedIn } = finding;
  const spec = advisory.database_specific;
  const lines: string[] = [];

  lines.push(
    `${c.dim(`${index + 1}.`)} ${severityTag(spec.severity)} ${c.bold(`${pkg.name}@${pkg.version}`)} ${c.dim(advisory.id)}`,
  );
  lines.push(...wrap(advisory.summary, WIDTH - INDENT.length).map((l) => `${INDENT}${l}`));
  lines.push(...field("Impact", spec.impact_summary));
  lines.push(...field("Chain", chainLabel(spec.chains)));

  if (fixedIn) {
    lines.push(...field("Fix", `upgrade ${pkg.name} to >=${fixedIn}`, c.green));
  } else {
    lines.push(...field("Fix", "No fix available — mitigation required", c.red));
    if (spec.mitigation) lines.push(...field("Mitigate", spec.mitigation));
  }

  if (!spec.npm_audit_detects) {
    lines.push(
      ...field(
        "Hidden",
        `npm audit does not report this (${
          spec.has_upstream_advisory ? "advisory not propagated" : "no advisory published"
        })`,
        c.magenta,
      ),
    );
  }

  const confidence = spec.confidence === "high" ? "" : ` · confidence: ${spec.confidence}`;
  lines.push(...field("Source", `${spec.source}${confidence}`));

  return lines.join("\n");
}

function severityCounts(findings: Finding[]): string {
  const counts = findings.reduce<Record<string, number>>((acc, f) => {
    const s = f.advisory.database_specific.severity;
    acc[s] = (acc[s] ?? 0) + 1;
    return acc;
  }, {});
  return (["CRITICAL", "HIGH", "MODERATE", "LOW"] as Severity[])
    .filter((s) => counts[s])
    .map((s) => `${counts[s]} ${s.toLowerCase()}`)
    .join(", ");
}

const plural = (n: number) => `${n} finding${n === 1 ? "" : "s"}`;

export function renderSummary(result: ScanResult): string {
  const { findings, invisibleToNpmAudit, target } = result;
  const noFix = findings.filter((f) => !f.fixedIn).length;
  const counts = findings.length > 0 ? ` (${severityCounts(findings)})` : "";
  const out = [
    `agent-audit · ${target.lockfile} · ${plural(findings.length)}${counts} · ${invisibleToNpmAudit.length} invisible to npm audit · ${noFix} with no fix`,
  ];
  for (const f of findings) {
    const spec = f.advisory.database_specific;
    out.push(
      [
        severityTag(spec.severity),
        `${f.package.name}@${f.package.version}`,
        f.advisory.id,
        f.fixedIn ? `fix >=${f.fixedIn}` : "no fix",
        spec.npm_audit_detects ? "" : "hidden",
      ]
        .filter(Boolean)
        .join("  "),
    );
  }
  return out.join("\n");
}

export function renderText(result: ScanResult): string {
  const { findings, invisibleToNpmAudit, target } = result;
  const out: string[] = [];

  out.push("");
  out.push(
    `${c.bold("agent-audit")} ${c.dim(
      `· ${target.lockfile} · ${result.packagesScanned} packages · ${result.advisoriesLoaded} advisories${
        result.chain ? ` · chain: ${CHAIN_LABEL[result.chain]}` : ""
      }`,
    )}`,
  );
  out.push("");

  if (findings.length === 0) {
    out.push(
      result.chain
        ? `${c.green("✓")} No known vulnerable agent-payment SDK versions found for chain: ${CHAIN_LABEL[result.chain]} (chain-agnostic advisories included; other chains were not checked).`
        : `${c.green("✓")} No known vulnerable agent-payment SDK versions found.`,
    );
    out.push("");
    return out.join("\n");
  }

  for (const [i, finding] of findings.entries()) {
    out.push(renderFinding(finding, i));
    out.push("");
  }

  out.push(c.dim("─".repeat(60)));
  out.push(c.bold(`${plural(findings.length)} (${severityCounts(findings)})`));

  const noFixCount = findings.filter((f) => !f.fixedIn).length;
  const tally = [
    invisibleToNpmAudit.length > 0
      ? c.magenta(c.bold(`${invisibleToNpmAudit.length} invisible to npm audit`))
      : "",
    noFixCount > 0 ? c.red(c.bold(`${noFixCount} with no fix`)) : "",
  ].filter(Boolean);
  if (tally.length > 0) out.push(tally.join(c.dim(" · ")));

  out.push("");
  return out.join("\n");
}

export function renderJson(result: ScanResult): string {
  return JSON.stringify(
    {
      lockfile: result.target.lockfile,
      lockfilePath: result.target.path,
      packagesScanned: result.packagesScanned,
      advisoriesLoaded: result.advisoriesLoaded,
      chain: result.chain ?? null,
      findingCount: result.findings.length,
      noFixCount: result.findings.filter((f) => !f.fixedIn).length,
      invisibleToNpmAuditCount: result.invisibleToNpmAudit.length,
      findings: result.findings.map((f) => ({
        id: f.advisory.id,
        package: f.package.name,
        version: f.package.version,
        severity: f.advisory.database_specific.severity,
        summary: f.advisory.summary,
        impact: f.advisory.database_specific.impact_summary,
        fixedIn: f.fixedIn ?? null,
        source: f.advisory.database_specific.source,
        confidence: f.advisory.database_specific.confidence,
        npmAuditDetects: f.advisory.database_specific.npm_audit_detects,
        hasUpstreamAdvisory: f.advisory.database_specific.has_upstream_advisory,
        roles: f.advisory.database_specific.roles ?? [],
        chains: f.advisory.database_specific.chains ?? [],
        mitigation: f.advisory.database_specific.mitigation ?? null,
        references: (f.advisory.references ?? []).map((r) => r.url),
      })),
    },
    null,
    2,
  );
}

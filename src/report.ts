import type { Finding, ScanResult, Severity } from "./types.js";

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

function renderFinding(finding: Finding, index: number): string {
  const { advisory, package: pkg, fixedIn } = finding;
  const spec = advisory.database_specific;
  const lines: string[] = [];

  lines.push(
    `${c.dim(`${index + 1}.`)} ${severityTag(spec.severity)} ${c.bold(`${pkg.name}@${pkg.version}`)}`,
  );
  lines.push(`   ${advisory.summary}`);
  lines.push(`   ${c.dim("Impact:")} ${spec.impact_summary}`);

  if (fixedIn) {
    lines.push(`   ${c.dim("Fix:")}    upgrade ${c.bold(pkg.name)} to ${c.green(`>=${fixedIn}`)}`);
  }

  if (!spec.npm_audit_detects) {
    lines.push(
      `   ${c.magenta("⚠ npm audit does not report this")} ${c.dim(
        spec.has_upstream_advisory ? "(advisory not propagated)" : "(no advisory published)",
      )}`,
    );
  }

  const confidence =
    spec.confidence === "high" ? "" : c.dim(` · confidence: ${spec.confidence}`);
  lines.push(`   ${c.dim(`${advisory.id} · source: ${spec.source}${confidence ? "" : ""}`)}${confidence}`);

  return lines.join("\n");
}

export function renderText(result: ScanResult): string {
  const { findings, invisibleToNpmAudit, target } = result;
  const out: string[] = [];

  out.push("");
  out.push(
    `${c.bold("agent-audit")} ${c.dim(
      `· ${target.lockfile} · ${result.packagesScanned} packages · ${result.advisoriesLoaded} advisories`,
    )}`,
  );
  out.push("");

  if (findings.length === 0) {
    out.push(`${c.green("✓")} No known vulnerable agent-payment SDK versions found.`);
    out.push("");
    return out.join("\n");
  }

  for (const [i, finding] of findings.entries()) {
    out.push(renderFinding(finding, i));
    out.push("");
  }

  const counts = findings.reduce<Record<string, number>>((acc, f) => {
    const s = f.advisory.database_specific.severity;
    acc[s] = (acc[s] ?? 0) + 1;
    return acc;
  }, {});

  const summary = (["CRITICAL", "HIGH", "MODERATE", "LOW"] as Severity[])
    .filter((s) => counts[s])
    .map((s) => `${counts[s]} ${s.toLowerCase()}`)
    .join(", ");

  out.push(c.bold(`${findings.length} finding${findings.length === 1 ? "" : "s"} (${summary})`));

  if (invisibleToNpmAudit.length > 0) {
    out.push(
      c.magenta(
        c.bold(
          `${invisibleToNpmAudit.length} of these ${
            invisibleToNpmAudit.length === 1 ? "is" : "are"
          } invisible to npm audit.`,
        ),
      ),
    );
  }

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
      findingCount: result.findings.length,
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
        references: (f.advisory.references ?? []).map((r) => r.url),
      })),
    },
    null,
    2,
  );
}

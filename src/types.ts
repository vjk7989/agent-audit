/**
 * Types for the agent-audit advisory format.
 *
 * The on-disk format is OSV (https://ossf.github.io/osv-schema/) so entries can be
 * contributed upstream to the GitHub Advisory Database without reshaping. Everything
 * specific to this tool lives under `database_specific`.
 */

/** How a package version range is expressed. We only emit SEMVER. */
export type RangeType = "SEMVER" | "ECOSYSTEM" | "GIT";

export interface OsvEvent {
  introduced?: string;
  fixed?: string;
  last_affected?: string;
  limit?: string;
}

export interface OsvRange {
  type: RangeType;
  events: OsvEvent[];
}

export interface OsvPackage {
  ecosystem: string;
  name: string;
  purl?: string;
}

export interface OsvAffected {
  package: OsvPackage;
  ranges?: OsvRange[];
  versions?: string[];
  database_specific?: Record<string, unknown>;
}

export interface OsvReference {
  type: "ADVISORY" | "ARTICLE" | "FIX" | "PACKAGE" | "REPORT" | "WEB";
  url: string;
}

export interface OsvSeverity {
  type: "CVSS_V3" | "CVSS_V4";
  score: string;
}

export type Severity = "CRITICAL" | "HIGH" | "MODERATE" | "LOW";

/**
 * Where an entry's facts came from. This distinction is the point of the tool, so it
 * is not optional.
 *
 * - `advisory`: mirrored from a published GHSA/OSV record. `npm audit` already finds these.
 * - `derived`:  reconstructed from published security research, changelogs or commit
 *               history because no upstream advisory exists. `npm audit` is blind to these.
 */
export type EntrySource = "advisory" | "derived";

/** How much to trust a derived entry's affected ranges. */
export type Confidence = "high" | "medium" | "low";

/** Which party in an x402 exchange is exposed. Used to suppress irrelevant findings. */
export type Role = "client" | "facilitator" | "resource-server";

export interface AgentAuditSpecific {
  severity: Severity;
  source: EntrySource;
  confidence: Confidence;
  /** True when a GHSA/OSV record exists upstream. */
  has_upstream_advisory: boolean;
  /**
   * Whether `npm audit` detects this today. The headline number in the report is the
   * count of findings where this is false.
   */
  npm_audit_detects: boolean;
  /** Which roles are exposed. Empty/undefined means "all". */
  roles?: Role[];
  /** One line a developer can act on. */
  impact_summary: string;
  /** Free-text note on how the ranges were established. Required for `derived` entries. */
  provenance?: string;
}

export interface Advisory {
  schema_version: string;
  id: string;
  aliases?: string[];
  related?: string[];
  modified: string;
  published: string;
  summary: string;
  details: string;
  severity?: OsvSeverity[];
  affected: OsvAffected[];
  references?: OsvReference[];
  database_specific: AgentAuditSpecific;
}

/** A package at a concrete version, as found in a lockfile. */
export interface InstalledPackage {
  name: string;
  version: string;
  /** Where in the lockfile this came from, for the report. */
  path?: string;
  /** True when the package is a direct dependency of the scanned project. */
  direct?: boolean;
}

export type Lockfile =
  | "package-lock.json"
  | "pnpm-lock.yaml"
  | "yarn.lock"
  | "bun.lock";

export interface ScanTarget {
  lockfile: Lockfile;
  path: string;
  packages: InstalledPackage[];
}

export interface Finding {
  advisory: Advisory;
  package: InstalledPackage;
  /** The first version that fixes this, if the advisory names one. */
  fixedIn?: string;
}

export interface ScanResult {
  target: ScanTarget;
  findings: Finding[];
  /** Findings `npm audit` would not report. The reason this tool exists. */
  invisibleToNpmAudit: Finding[];
  advisoriesLoaded: number;
  packagesScanned: number;
}

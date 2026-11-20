import semver from "semver";
import type {
  Advisory,
  Finding,
  InstalledPackage,
  OsvRange,
  Role,
  ScanResult,
  ScanTarget,
  Severity,
} from "./types.js";

export const SEVERITY_ORDER: Record<Severity, number> = {
  LOW: 0,
  MODERATE: 1,
  HIGH: 2,
  CRITICAL: 3,
};

/** Normalise a lockfile version into something semver can compare. */
function normalise(version: string): string | null {
  if (semver.valid(version)) return version;
  const coerced = semver.coerce(version);
  return coerced ? coerced.version : null;
}

/**
 * Evaluate an OSV SEMVER range against a version.
 *
 * OSV semantics: events are ordered; `introduced` opens an affected interval and
 * `fixed` / `last_affected` closes it. A version is affected if it falls inside an
 * open interval after processing every event in order.
 */
export function isAffectedByRange(version: string, range: OsvRange): boolean {
  if (range.type !== "SEMVER") return false;

  const v = normalise(version);
  if (!v) return false;

  let affected = false;
  for (const event of range.events) {
    if (event.introduced !== undefined) {
      const introduced = event.introduced === "0" ? "0.0.0" : event.introduced;
      const intro = normalise(introduced);
      if (intro && semver.gte(v, intro)) affected = true;
    } else if (event.fixed !== undefined) {
      const fixed = normalise(event.fixed);
      if (fixed && semver.gte(v, fixed)) affected = false;
    } else if (event.last_affected !== undefined) {
      const last = normalise(event.last_affected);
      if (last && semver.gt(v, last)) affected = false;
    }
  }
  return affected;
}

/** The first `fixed` version named for a package in an advisory, if any. */
export function fixedVersionFor(advisory: Advisory, packageName: string): string | undefined {
  for (const affected of advisory.affected) {
    if (affected.package.name !== packageName) continue;
    for (const range of affected.ranges ?? []) {
      for (const event of range.events) {
        if (event.fixed) return event.fixed;
      }
    }
  }
  return undefined;
}

function advisoryHits(advisory: Advisory, pkg: InstalledPackage): boolean {
  for (const affected of advisory.affected) {
    if (affected.package.ecosystem !== "npm") continue;
    if (affected.package.name !== pkg.name) continue;

    if (affected.versions?.includes(pkg.version)) return true;

    for (const range of affected.ranges ?? []) {
      if (isAffectedByRange(pkg.version, range)) return true;
    }
  }
  return false;
}

export interface MatchOptions {
  /** Only report advisories relevant to this role. */
  role?: Role;
  /** Drop findings below this severity. */
  minSeverity?: Severity;
}

export function matchAdvisories(
  target: ScanTarget,
  advisories: Advisory[],
  options: MatchOptions = {},
): ScanResult {
  const findings: Finding[] = [];

  for (const pkg of target.packages) {
    for (const advisory of advisories) {
      if (!advisoryHits(advisory, pkg)) continue;

      const spec = advisory.database_specific;

      if (options.role && spec.roles?.length && !spec.roles.includes(options.role)) {
        continue;
      }
      if (
        options.minSeverity &&
        SEVERITY_ORDER[spec.severity] < SEVERITY_ORDER[options.minSeverity]
      ) {
        continue;
      }

      const fixedIn = fixedVersionFor(advisory, pkg.name);
      findings.push(fixedIn ? { advisory, package: pkg, fixedIn } : { advisory, package: pkg });
    }
  }

  // Deduplicate: the same advisory can hit the same name@version via several lockfile paths.
  const seen = new Set<string>();
  const deduped = findings.filter((f) => {
    const key = `${f.advisory.id}::${f.package.name}@${f.package.version}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });

  deduped.sort((a, b) => {
    const bySeverity =
      SEVERITY_ORDER[b.advisory.database_specific.severity] -
      SEVERITY_ORDER[a.advisory.database_specific.severity];
    if (bySeverity !== 0) return bySeverity;

    // Within a severity, surface the ones npm audit misses first.
    const aHidden = a.advisory.database_specific.npm_audit_detects ? 1 : 0;
    const bHidden = b.advisory.database_specific.npm_audit_detects ? 1 : 0;
    if (aHidden !== bHidden) return aHidden - bHidden;

    return a.package.name.localeCompare(b.package.name);
  });

  return {
    target,
    findings: deduped,
    invisibleToNpmAudit: deduped.filter((f) => !f.advisory.database_specific.npm_audit_detects),
    advisoriesLoaded: advisories.length,
    packagesScanned: target.packages.length,
  };
}

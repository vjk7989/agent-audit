export { loadAdvisories } from "./db.js";
export { findLockfile, scanLockfile } from "./lockfiles.js";
export {
  fixedVersionFor,
  isAffectedByRange,
  matchAdvisories,
  SEVERITY_ORDER,
  type MatchOptions,
} from "./match.js";
export { renderJson, renderText } from "./report.js";
export type {
  Advisory,
  Confidence,
  EntrySource,
  Finding,
  InstalledPackage,
  Lockfile,
  Role,
  ScanResult,
  ScanTarget,
  Severity,
} from "./types.js";

import { loadAdvisories } from "./db.js";
import { scanLockfile } from "./lockfiles.js";
import { matchAdvisories, type MatchOptions } from "./match.js";
import type { ScanResult } from "./types.js";

/** Scan a directory or lockfile path and return the findings. */
export function audit(
  target: string,
  options: MatchOptions & { advisoryDir?: string } = {},
): ScanResult {
  const advisories = loadAdvisories(options.advisoryDir);
  const scanned = scanLockfile(target);
  return matchAdvisories(scanned, advisories, options);
}

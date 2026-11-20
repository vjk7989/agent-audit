import { readdirSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import type { Advisory } from "./types.js";

const here = dirname(fileURLToPath(import.meta.url));

/**
 * Locate the bundled advisories directory.
 *
 * Works both from `dist/` (published package) and from `src/` (vitest, ts-node),
 * so tests and the built CLI load the same data.
 */
function defaultAdvisoryDir(): string {
  const candidates = [
    resolve(here, "..", "advisories"),
    resolve(here, "..", "..", "advisories"),
  ];
  for (const dir of candidates) {
    try {
      readdirSync(dir);
      return dir;
    } catch {
      // try the next one
    }
  }
  throw new Error(
    `Could not locate the advisories directory. Looked in:\n  ${candidates.join("\n  ")}`,
  );
}

function isAdvisory(value: unknown): value is Advisory {
  if (typeof value !== "object" || value === null) return false;
  const a = value as Partial<Advisory>;
  return (
    typeof a.id === "string" &&
    typeof a.summary === "string" &&
    Array.isArray(a.affected) &&
    typeof a.database_specific === "object" &&
    a.database_specific !== null
  );
}

/**
 * Load every advisory from disk.
 *
 * A malformed file is a hard error rather than a silent skip: a security scanner
 * that quietly drops part of its database is worse than one that refuses to run.
 */
export function loadAdvisories(dir?: string): Advisory[] {
  const target = dir ?? defaultAdvisoryDir();
  const files = readdirSync(target)
    .filter((f) => f.endsWith(".json"))
    .sort();

  const advisories: Advisory[] = [];
  for (const file of files) {
    const full = join(target, file);
    let parsed: unknown;
    try {
      parsed = JSON.parse(readFileSync(full, "utf8"));
    } catch (err) {
      throw new Error(`Advisory ${file} is not valid JSON: ${(err as Error).message}`);
    }
    if (!isAdvisory(parsed)) {
      throw new Error(`Advisory ${file} is missing required fields (id, summary, affected, database_specific).`);
    }
    advisories.push(parsed);
  }

  const seen = new Set<string>();
  for (const a of advisories) {
    if (seen.has(a.id)) throw new Error(`Duplicate advisory id: ${a.id}`);
    seen.add(a.id);
  }

  return advisories;
}

import { existsSync, readFileSync } from "node:fs";
import { basename, join } from "node:path";
import { parse as parseYaml } from "yaml";
import type { InstalledPackage, Lockfile, ScanTarget } from "./types.js";

const LOCKFILES: Lockfile[] = [
  "package-lock.json",
  "pnpm-lock.yaml",
  "yarn.lock",
  "bun.lock",
];

/** Find a supported lockfile in `dir`, or accept a direct path to one. */
export function findLockfile(target: string): { path: string; kind: Lockfile } {
  const name = basename(target);
  if ((LOCKFILES as string[]).includes(name) && existsSync(target)) {
    return { path: target, kind: name as Lockfile };
  }

  for (const kind of LOCKFILES) {
    const candidate = join(target, kind);
    if (existsSync(candidate)) return { path: candidate, kind };
  }

  throw new Error(
    `No lockfile found in ${target}.\nSupported: ${LOCKFILES.join(", ")}`,
  );
}

/** Strip a `node_modules/` prefix chain to get the bare package name. */
function nameFromNodeModulesPath(path: string): string | undefined {
  const idx = path.lastIndexOf("node_modules/");
  if (idx === -1) return undefined;
  const name = path.slice(idx + "node_modules/".length);
  return name.length > 0 ? name : undefined;
}

function parsePackageLock(raw: string): InstalledPackage[] {
  const json = JSON.parse(raw) as {
    packages?: Record<string, { version?: string; dev?: boolean }>;
    dependencies?: Record<string, { version?: string; dependencies?: unknown }>;
  };

  const out: InstalledPackage[] = [];

  // lockfileVersion 2 and 3
  if (json.packages) {
    for (const [path, meta] of Object.entries(json.packages)) {
      if (path === "") continue; // the root project itself
      const name = nameFromNodeModulesPath(path);
      if (!name || !meta?.version) continue;
      out.push({ name, version: meta.version, path });
    }
  }

  // lockfileVersion 1 fallback
  if (out.length === 0 && json.dependencies) {
    const walk = (deps: Record<string, any>, prefix: string): void => {
      for (const [name, meta] of Object.entries(deps)) {
        if (meta?.version) {
          out.push({ name, version: meta.version, path: `${prefix}${name}` });
        }
        if (meta?.dependencies) {
          walk(meta.dependencies as Record<string, any>, `${prefix}${name}/node_modules/`);
        }
      }
    };
    walk(json.dependencies, "node_modules/");
  }

  return out;
}

/**
 * pnpm lockfile keys have changed shape across versions:
 *   v9:  '@x402/svm@2.22.0'   and  'semver@7.6.3'
 *   v6:  '/@x402/svm@2.22.0'
 *   v5:  '/@x402/svm/2.22.0'
 * Handle all three.
 */
function parsePnpmKey(key: string): InstalledPackage | undefined {
  let k = key.startsWith("/") ? key.slice(1) : key;

  // Drop peer-dependency suffixes: 'foo@1.0.0(react@18.0.0)'
  const paren = k.indexOf("(");
  if (paren !== -1) k = k.slice(0, paren);

  // v5 style: '@scope/name/1.2.3' or 'name/1.2.3'
  const lastSlash = k.lastIndexOf("/");
  if (lastSlash > 0 && !k.slice(lastSlash + 1).includes("@")) {
    const maybeVersion = k.slice(lastSlash + 1);
    if (/^\d/.test(maybeVersion)) {
      return { name: k.slice(0, lastSlash), version: maybeVersion, path: key };
    }
  }

  // v6/v9 style: '@scope/name@1.2.3' or 'name@1.2.3'
  const at = k.lastIndexOf("@");
  if (at > 0) {
    const name = k.slice(0, at);
    const version = k.slice(at + 1);
    if (/^\d/.test(version)) return { name, version, path: key };
  }

  return undefined;
}

function parsePnpmLock(raw: string): InstalledPackage[] {
  const doc = parseYaml(raw) as {
    packages?: Record<string, unknown>;
    snapshots?: Record<string, unknown>;
  };

  const out: InstalledPackage[] = [];
  const seen = new Set<string>();

  for (const section of [doc?.packages, doc?.snapshots]) {
    if (!section) continue;
    for (const key of Object.keys(section)) {
      const pkg = parsePnpmKey(key);
      if (!pkg) continue;
      const dedupe = `${pkg.name}@${pkg.version}`;
      if (seen.has(dedupe)) continue;
      seen.add(dedupe);
      out.push(pkg);
    }
  }

  return out;
}

/**
 * yarn.lock (classic v1) is a bespoke format. Berry (v2+) is YAML.
 * Detect Berry by its `__metadata:` block and parse accordingly.
 */
function parseYarnLock(raw: string): InstalledPackage[] {
  if (raw.includes("__metadata:")) {
    const doc = parseYaml(raw) as Record<string, { version?: string }>;
    const out: InstalledPackage[] = [];
    const seen = new Set<string>();
    for (const [key, meta] of Object.entries(doc ?? {})) {
      if (key === "__metadata" || !meta?.version) continue;
      // Keys look like: '@x402/svm@npm:^2.22.0, @x402/svm@npm:2.22.0'
      const first = key.split(",")[0]?.trim() ?? "";
      const at = first.lastIndexOf("@");
      if (at <= 0) continue;
      const name = first.slice(0, at);
      const dedupe = `${name}@${meta.version}`;
      if (seen.has(dedupe)) continue;
      seen.add(dedupe);
      out.push({ name, version: meta.version, path: key });
    }
    return out;
  }

  // Classic v1
  const out: InstalledPackage[] = [];
  const seen = new Set<string>();
  const blocks = raw.split(/\n(?=\S)/);
  for (const block of blocks) {
    const header = block.split("\n")[0];
    if (!header || header.startsWith("#")) continue;
    const versionMatch = block.match(/^\s+version\s+"?([^"\s]+)"?/m);
    if (!versionMatch?.[1]) continue;

    const first = header.split(",")[0]?.trim().replace(/:$/, "").replace(/^"|"$/g, "") ?? "";
    const at = first.lastIndexOf("@");
    if (at <= 0) continue;
    const name = first.slice(0, at);
    const version = versionMatch[1];
    const dedupe = `${name}@${version}`;
    if (seen.has(dedupe)) continue;
    seen.add(dedupe);
    out.push({ name, version, path: first });
  }
  return out;
}

function parseBunLock(raw: string): InstalledPackage[] {
  // bun.lock is JSONC-ish: strip trailing commas and comments before parsing.
  const cleaned = raw
    .replace(/\/\*[\s\S]*?\*\//g, "")
    .replace(/(^|[^:])\/\/.*$/gm, "$1")
    .replace(/,(\s*[}\]])/g, "$1");

  const json = JSON.parse(cleaned) as { packages?: Record<string, unknown> };
  const out: InstalledPackage[] = [];
  for (const [name, entry] of Object.entries(json.packages ?? {})) {
    // Entries are arrays whose first element is 'name@version'.
    const spec = Array.isArray(entry) ? entry[0] : entry;
    if (typeof spec !== "string") continue;
    const at = spec.lastIndexOf("@");
    if (at <= 0) continue;
    const version = spec.slice(at + 1);
    if (!/^\d/.test(version)) continue;
    out.push({ name, version, path: name });
  }
  return out;
}

export function scanLockfile(target: string): ScanTarget {
  const { path, kind } = findLockfile(target);
  const raw = readFileSync(path, "utf8");

  let packages: InstalledPackage[];
  try {
    switch (kind) {
      case "package-lock.json":
        packages = parsePackageLock(raw);
        break;
      case "pnpm-lock.yaml":
        packages = parsePnpmLock(raw);
        break;
      case "yarn.lock":
        packages = parseYarnLock(raw);
        break;
      case "bun.lock":
        packages = parseBunLock(raw);
        break;
    }
  } catch (err) {
    throw new Error(`Failed to parse ${path}: ${(err as Error).message}`);
  }

  return { lockfile: kind, path, packages };
}

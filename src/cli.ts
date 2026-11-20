#!/usr/bin/env node
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { loadAdvisories } from "./db.js";
import { scanLockfile } from "./lockfiles.js";
import { matchAdvisories } from "./match.js";
import { renderJson, renderText } from "./report.js";
import type { Chain, Role, ScanResult, Severity } from "./types.js";

const HELP = `
agent-audit — npm audit for agentic payment SDKs

  Scans your lockfile for known-vulnerable versions of x402 and related
  agent-payment packages, including vulnerabilities that have no published
  advisory and that npm audit therefore reports as clean.

Usage
  agent-audit [path] [options]

Arguments
  path                    Directory or lockfile to scan (default: current directory)

Options
  --json                  Emit machine-readable JSON
  --role <role>           Only report issues affecting this role.
                          One of: client, facilitator, resource-server
  --chain <chain>         Only report issues affecting this chain.
                          One of: evm, solana
  --min-severity <level>  Drop findings below this level.
                          One of: low, moderate, high, critical
  --only-hidden           Only report findings npm audit cannot see
  --exit-zero             Always exit 0, even when findings exist
  -h, --help              Show this help
  -v, --version           Show version

Exit codes
  0  no findings (or --exit-zero)
  1  findings reported
  2  error

Examples
  agent-audit
  agent-audit ./my-agent --role client
  agent-audit --only-hidden --json
  agent-audit ./my-agent --chain solana
`;

interface Options {
  path: string;
  json: boolean;
  role?: Role;
  chain?: Chain;
  minSeverity?: Severity;
  onlyHidden: boolean;
  exitZero: boolean;
}

const ROLES: Role[] = ["client", "facilitator", "resource-server"];
const CHAINS: Chain[] = ["evm", "solana"];
const SEVERITIES: Severity[] = ["LOW", "MODERATE", "HIGH", "CRITICAL"];

function fail(message: string): never {
  process.stderr.write(`agent-audit: ${message}\n`);
  process.exit(2);
}

function readVersion(): string {
  try {
    const here = dirname(fileURLToPath(import.meta.url));
    for (const candidate of [
      resolve(here, "..", "package.json"),
      resolve(here, "..", "..", "package.json"),
    ]) {
      try {
        const pkg = JSON.parse(readFileSync(candidate, "utf8")) as { version?: string };
        if (pkg.version) return pkg.version;
      } catch {
        // try the next one
      }
    }
  } catch {
    // fall through
  }
  return "unknown";
}

function parseArgs(argv: string[]): Options {
  const options: Options = {
    path: process.cwd(),
    json: false,
    onlyHidden: false,
    exitZero: false,
  };
  let pathSeen = false;

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    switch (arg) {
      case "-h":
      case "--help":
        process.stdout.write(HELP);
        process.exit(0);
        break;
      case "-v":
      case "--version":
        process.stdout.write(`${readVersion()}\n`);
        process.exit(0);
        break;
      case "--json":
        options.json = true;
        break;
      case "--only-hidden":
        options.onlyHidden = true;
        break;
      case "--exit-zero":
        options.exitZero = true;
        break;
      case "--role": {
        const value = argv[++i];
        if (!value || !ROLES.includes(value as Role)) {
          fail(`--role must be one of: ${ROLES.join(", ")}`);
        }
        options.role = value as Role;
        break;
      }
      case "--chain": {
        const value = argv[++i];
        if (!value || !CHAINS.includes(value as Chain)) {
          fail(`--chain must be one of: ${CHAINS.join(", ")}`);
        }
        options.chain = value as Chain;
        break;
      }
      case "--min-severity": {
        const value = argv[++i]?.toUpperCase();
        if (!value || !SEVERITIES.includes(value as Severity)) {
          fail(`--min-severity must be one of: ${SEVERITIES.map((s) => s.toLowerCase()).join(", ")}`);
        }
        options.minSeverity = value as Severity;
        break;
      }
      default:
        if (arg === undefined) break;
        if (arg.startsWith("-")) fail(`unknown option: ${arg}\nRun agent-audit --help`);
        if (pathSeen) fail(`unexpected extra argument: ${arg}`);
        options.path = resolve(arg);
        pathSeen = true;
    }
  }

  return options;
}

function main(): void {
  const options = parseArgs(process.argv.slice(2));

  let result: ScanResult;
  try {
    const advisories = loadAdvisories();
    const target = scanLockfile(options.path);
    const matchOptions = {
      ...(options.role ? { role: options.role } : {}),
      ...(options.chain ? { chain: options.chain } : {}),
      ...(options.minSeverity ? { minSeverity: options.minSeverity } : {}),
    };
    result = matchAdvisories(target, advisories, matchOptions);
  } catch (err) {
    fail((err as Error).message);
  }

  if (options.onlyHidden) {
    result = {
      ...result,
      findings: result.invisibleToNpmAudit,
    };
  }

  process.stdout.write(options.json ? `${renderJson(result)}\n` : renderText(result));

  if (!options.exitZero && result.findings.length > 0) process.exit(1);
  process.exit(0);
}

main();

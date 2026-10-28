const REGISTRY_URL = "https://registry.npmjs.org";
const OSV_QUERY_URL = "https://api.osv.dev/v1/query";
const UPSTREAM_TIMEOUT_MS = 5_000;
const STALE_AFTER_MS = 2 * 365 * 24 * 60 * 60 * 1000;
const PERFECT_SCORE = 100;

const PENALTY = { typosquat: 60, cve: 25, deprecated: 20, stale: 15 } as const;

const MIN_LOOKALIKE_TARGET_LENGTH = 4;
const SHORT_NAME_MAX_LENGTH = 6;
const MAX_EDITS_SHORT_NAME = 1;
const MAX_EDITS_LONG_NAME = 2;

const POPULAR_PACKAGES = [
  "lodash", "react", "express", "axios", "chalk", "commander", "debug", "moment",
  "request", "async", "uuid", "dotenv", "webpack", "typescript", "eslint", "jest",
  "mocha", "vue", "next", "rxjs", "underscore", "jquery", "yargs", "minimist",
  "glob", "semver", "colors", "bluebird", "body-parser", "cors", "mongoose",
  "redux", "prettier", "babel-core", "core-js", "classnames", "prop-types",
  "fs-extra", "inquirer", "node-fetch", "ws", "socket.io", "cross-env",
  "nodemon", "zod", "vite", "left-pad", "electron", "puppeteer", "sharp",
];

export type SignalKind = keyof typeof PENALTY;

export type Signal = { kind: SignalKind; detail: string; source: string; penalty: number };

export type Verdict = {
  package: string;
  version: string;
  score: number;
  confidence: "high" | "low";
  signals: Signal[];
};

type Manifest = { deprecated?: string };

type RegistryDocument = {
  "dist-tags"?: { latest?: string };
  versions?: Record<string, Manifest>;
  time?: { modified?: string };
};

type OsvResponse = { vulns?: { id: string; summary?: string }[] };

type Fetch = typeof fetch;

export class NotFound extends Error {}

export async function audit(name: string, version?: string, fetchFn: Fetch = fetch): Promise<Verdict> {
  const registryUrl = registryUrlFor(name);
  const document = await fetchRegistryDocument(registryUrl, fetchFn);
  const resolvedVersion = version ?? document["dist-tags"]?.latest;
  const manifest = findManifest(document, resolvedVersion);
  if (!manifest || !resolvedVersion) throw new NotFound(`version ${resolvedVersion} of ${name} not found`);

  const cves = await fetchCveSignals(name, resolvedVersion, fetchFn);
  const signals = [
    ...typosquatSignals(name),
    ...deprecationSignals(manifest, registryUrl),
    ...stalenessSignals(document, registryUrl),
    ...(cves ?? []),
  ];

  return {
    package: name,
    version: resolvedVersion,
    score: scoreOf(signals),
    confidence: cves ? "high" : "low",
    signals,
  };
}

export function typosquatTargetOf(name: string): string | undefined {
  if (POPULAR_PACKAGES.includes(name)) return undefined;
  const unscopedName = name.replace(/^@[^/]+\//, "");
  return POPULAR_PACKAGES.find(
    (target) =>
      target.length >= MIN_LOOKALIKE_TARGET_LENGTH &&
      editDistanceWithSwaps(unscopedName, target) <= maxEditsFor(target),
  );
}

function registryUrlFor(name: string): string {
  return `${REGISTRY_URL}/${name.replace("/", "%2f")}`;
}

async function fetchRegistryDocument(url: string, fetchFn: Fetch): Promise<RegistryDocument> {
  const response = await fetchFn(url, { signal: AbortSignal.timeout(UPSTREAM_TIMEOUT_MS) });
  if (response.status === 404) throw new NotFound(`package not found: ${url}`);
  if (!response.ok) throw new Error(`registry responded ${response.status}`);
  return response.json();
}

function findManifest(document: RegistryDocument, version: string | undefined): Manifest | undefined {
  const versions = document.versions ?? {};
  return version && Object.hasOwn(versions, version) ? versions[version] : undefined;
}

async function fetchCveSignals(name: string, version: string, fetchFn: Fetch): Promise<Signal[] | undefined> {
  try {
    const response = await fetchFn(OSV_QUERY_URL, {
      method: "POST",
      body: JSON.stringify({ package: { name, ecosystem: "npm" }, version }),
      signal: AbortSignal.timeout(UPSTREAM_TIMEOUT_MS),
    });
    if (!response.ok) return undefined;
    const { vulns = [] }: OsvResponse = await response.json();
    return vulns.map((vuln) => ({
      kind: "cve",
      detail: vuln.summary ?? vuln.id,
      source: `https://osv.dev/vulnerability/${vuln.id}`,
      penalty: PENALTY.cve,
    }));
  } catch {
    return undefined;
  }
}

function typosquatSignals(name: string): Signal[] {
  const target = typosquatTargetOf(name);
  if (!target) return [];
  return [{
    kind: "typosquat",
    detail: `name is close to popular package "${target}"`,
    source: `https://www.npmjs.com/package/${target}`,
    penalty: PENALTY.typosquat,
  }];
}

function deprecationSignals(manifest: Manifest, registryUrl: string): Signal[] {
  if (!manifest.deprecated) return [];
  return [{ kind: "deprecated", detail: manifest.deprecated, source: registryUrl, penalty: PENALTY.deprecated }];
}

function stalenessSignals(document: RegistryDocument, registryUrl: string): Signal[] {
  const lastModified = document.time?.modified;
  if (!lastModified || Date.now() - Date.parse(lastModified) <= STALE_AFTER_MS) return [];
  return [{
    kind: "stale",
    detail: `no publish since ${lastModified.slice(0, 10)}`,
    source: registryUrl,
    penalty: PENALTY.stale,
  }];
}

function scoreOf(signals: Signal[]): number {
  const totalPenalty = signals.reduce((sum, signal) => sum + signal.penalty, 0);
  return Math.max(0, PERFECT_SCORE - totalPenalty);
}

function maxEditsFor(target: string): number {
  return target.length > SHORT_NAME_MAX_LENGTH ? MAX_EDITS_LONG_NAME : MAX_EDITS_SHORT_NAME;
}

function editDistanceWithSwaps(a: string, b: string): number {
  let rowBeforePrevious: number[] = [];
  let previousRow = Array.from({ length: b.length + 1 }, (_, j) => j);
  for (let i = 1; i <= a.length; i++) {
    const currentRow = [i];
    for (let j = 1; j <= b.length; j++) {
      const substitutionCost = a[i - 1] === b[j - 1] ? 0 : 1;
      const isAdjacentSwap = i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1];
      currentRow[j] = Math.min(
        previousRow[j] + 1,
        currentRow[j - 1] + 1,
        previousRow[j - 1] + substitutionCost,
        isAdjacentSwap ? rowBeforePrevious[j - 2] + 1 : Infinity,
      );
    }
    rowBeforePrevious = previousRow;
    previousRow = currentRow;
  }
  return previousRow[b.length];
}

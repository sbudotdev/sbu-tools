const REGISTRY = "https://registry.npmjs.org";
const OSV = "https://api.osv.dev/v1/query";
const STALE_MS = 2 * 365 * 24 * 3600 * 1000;

// ponytail: hardcoded top packages, swap for a downloads-ranked list when false negatives show up
const POPULAR = [
  "lodash", "react", "express", "axios", "chalk", "commander", "debug", "moment",
  "request", "async", "uuid", "dotenv", "webpack", "typescript", "eslint", "jest",
  "mocha", "vue", "next", "rxjs", "underscore", "jquery", "yargs", "minimist",
  "glob", "semver", "colors", "bluebird", "body-parser", "cors", "mongoose",
  "redux", "prettier", "babel-core", "core-js", "classnames", "prop-types",
  "fs-extra", "inquirer", "node-fetch", "ws", "socket.io", "cross-env",
  "nodemon", "zod", "vite", "left-pad", "electron", "puppeteer", "sharp",
];

export type Signal = { kind: string; detail: string; source: string; penalty: number };

export type Verdict = {
  package: string;
  version: string;
  score: number;
  confidence: "high" | "medium" | "low";
  signals: Signal[];
};

export class NotFound extends Error {}

type Fetch = typeof fetch;

export async function audit(name: string, version?: string, fetchFn: Fetch = fetch): Promise<Verdict> {
  const regUrl = `${REGISTRY}/${name.replace("/", "%2f")}`;
  const res = await fetchFn(regUrl);
  if (res.status === 404) throw new NotFound(`package ${name} not found`);
  if (!res.ok) throw new Error(`registry ${res.status}`);
  const meta = await res.json();

  const ver = version ?? meta["dist-tags"]?.latest;
  const manifest = meta.versions?.[ver];
  if (!manifest) throw new NotFound(`version ${ver} of ${name} not found`);

  const signals: Signal[] = [];
  let confidence: Verdict["confidence"] = "high";

  const twin = typosquatOf(name);
  if (twin) {
    signals.push({
      kind: "typosquat",
      detail: `name is close to popular package "${twin}"`,
      source: `https://www.npmjs.com/package/${twin}`,
      penalty: 60,
    });
  }

  if (manifest.deprecated) {
    signals.push({ kind: "deprecated", detail: String(manifest.deprecated), source: regUrl, penalty: 20 });
  }

  const lastPublish = Date.parse(meta.time?.modified ?? "");
  if (Date.now() - lastPublish > STALE_MS) {
    signals.push({
      kind: "stale",
      detail: `no publish since ${meta.time.modified.slice(0, 10)}`,
      source: regUrl,
      penalty: 15,
    });
  }

  try {
    const osv = await fetchFn(OSV, {
      method: "POST",
      body: JSON.stringify({ package: { name, ecosystem: "npm" }, version: ver }),
    });
    if (!osv.ok) throw new Error(`osv ${osv.status}`);
    const { vulns = [] } = await osv.json();
    for (const v of vulns) {
      signals.push({
        kind: "cve",
        detail: v.summary ?? v.id,
        source: `https://osv.dev/vulnerability/${v.id}`,
        penalty: 25,
      });
    }
  } catch {
    // OSV down: still answer, but say we could not check
    confidence = "low";
  }

  const score = Math.max(0, 100 - signals.reduce((s, x) => s + x.penalty, 0));
  return { package: name, version: ver, score, confidence, signals };
}

export function typosquatOf(name: string): string | undefined {
  if (POPULAR.includes(name)) return;
  const bare = name.replace(/^@[^/]+\//, "");
  return POPULAR.find((p) => p.length >= 4 && levenshtein(bare, p) <= (p.length > 6 ? 2 : 1));
}

function levenshtein(a: string, b: string): number {
  // optimal string alignment: edits plus adjacent swaps ("lodahs" -> "lodash" = 1)
  let prev2: number[] = [];
  let prev = Array.from({ length: b.length + 1 }, (_, j) => j);
  for (let i = 1; i <= a.length; i++) {
    const cur = [i];
    for (let j = 1; j <= b.length; j++) {
      const swap = i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1] ? prev2[j - 2] + 1 : Infinity;
      cur[j] = Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1), swap);
    }
    prev2 = prev;
    prev = cur;
  }
  return prev[b.length];
}

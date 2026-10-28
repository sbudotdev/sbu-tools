import { test } from "node:test";
import assert from "node:assert/strict";
import { audit, typosquatTargetOf, NotFound } from "../src/audit.ts";

const recent = new Date().toISOString();

function fakeFetch(registryDocument: object | null, vulns: object[] = []): typeof fetch {
  return (async (url: string) => {
    if (url.includes("osv.dev")) return Response.json({ vulns });
    return registryDocument ? Response.json(registryDocument) : new Response("", { status: 404 });
  }) as typeof fetch;
}

const registryDocumentFor = (name: string, version: string) => ({
  name,
  "dist-tags": { latest: version },
  versions: { [version]: { name, version } },
  time: { modified: recent },
});

test("healthy package scores 100", async () => {
  const verdict = await audit("express", undefined, fakeFetch(registryDocumentFor("express", "5.1.0")));
  assert.equal(verdict.version, "5.1.0");
  assert.equal(verdict.score, 100);
  assert.deepEqual(verdict.signals, []);
});

test("package with CVE loses points and links OSV", async () => {
  const fetchFn = fakeFetch(registryDocumentFor("lodash", "4.17.15"), [{ id: "GHSA-29mw-wpgm-hmr9", summary: "ReDoS" }]);
  const verdict = await audit("lodash", "4.17.15", fetchFn);
  assert.equal(verdict.score, 75);
  assert.equal(verdict.signals[0].kind, "cve");
  assert.equal(verdict.signals[0].source, "https://osv.dev/vulnerability/GHSA-29mw-wpgm-hmr9");
});

test("typosquat is flagged", async () => {
  const verdict = await audit("lodahs", undefined, fakeFetch(registryDocumentFor("lodahs", "1.0.0")));
  assert.equal(verdict.signals[0].kind, "typosquat");
  assert.ok(verdict.score <= 40);
});

test("typosquat heuristic", () => {
  assert.equal(typosquatTargetOf("lodahs"), "lodash");
  assert.equal(typosquatTargetOf("expres"), "express");
  assert.equal(typosquatTargetOf("lodash"), undefined);
  assert.equal(typosquatTargetOf("left-pad"), undefined);
  assert.equal(typosquatTargetOf("totally-unrelated"), undefined);
});

test("missing package throws NotFound", async () => {
  await assert.rejects(audit("nope-nope", undefined, fakeFetch(null)), NotFound);
});

test("inherited object keys are not treated as versions", async () => {
  await assert.rejects(audit("express", "constructor", fakeFetch(registryDocumentFor("express", "5.1.0"))), NotFound);
});

test("OSV failure lowers confidence instead of failing", async () => {
  const fetchFn = (async (url: string) =>
    url.includes("osv.dev")
      ? new Response("", { status: 503 })
      : Response.json(registryDocumentFor("express", "5.1.0"))) as typeof fetch;
  const verdict = await audit("express", undefined, fetchFn);
  assert.equal(verdict.confidence, "low");
});

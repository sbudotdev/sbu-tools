import { test } from "node:test";
import assert from "node:assert/strict";
import { audit, typosquatOf, NotFound } from "../src/audit.ts";

const recent = new Date().toISOString();

function fakeFetch(meta: object | null, vulns: object[] = []): typeof fetch {
  return (async (url: string) => {
    if (url.includes("osv.dev")) return Response.json({ vulns });
    return meta ? Response.json(meta) : new Response("", { status: 404 });
  }) as typeof fetch;
}

const pkg = (name: string, ver: string) => ({
  name,
  "dist-tags": { latest: ver },
  versions: { [ver]: { name, version: ver } },
  time: { modified: recent },
});

test("healthy package scores 100", async () => {
  const v = await audit("express", undefined, fakeFetch(pkg("express", "5.1.0")));
  assert.equal(v.version, "5.1.0");
  assert.equal(v.score, 100);
  assert.deepEqual(v.signals, []);
});

test("package with CVE loses points and links OSV", async () => {
  const v = await audit("lodash", "4.17.15", fakeFetch(pkg("lodash", "4.17.15"), [{ id: "GHSA-29mw-wpgm-hmr9", summary: "ReDoS" }]));
  assert.equal(v.score, 75);
  assert.equal(v.signals[0].kind, "cve");
  assert.equal(v.signals[0].source, "https://osv.dev/vulnerability/GHSA-29mw-wpgm-hmr9");
});

test("typosquat is flagged", async () => {
  const v = await audit("lodahs", undefined, fakeFetch(pkg("lodahs", "1.0.0")));
  assert.equal(v.signals[0].kind, "typosquat");
  assert.ok(v.score <= 40);
});

test("typosquat heuristic", () => {
  assert.equal(typosquatOf("lodahs"), "lodash");
  assert.equal(typosquatOf("expres"), "express");
  assert.equal(typosquatOf("lodash"), undefined);
  assert.equal(typosquatOf("left-pad"), undefined);
  assert.equal(typosquatOf("totally-unrelated"), undefined);
});

test("missing package throws NotFound", async () => {
  await assert.rejects(audit("nope-nope", undefined, fakeFetch(null)), NotFound);
});

test("OSV failure lowers confidence instead of failing", async () => {
  const f = (async (url: string) =>
    url.includes("osv.dev") ? new Response("", { status: 503 }) : Response.json(pkg("express", "5.1.0"))) as typeof fetch;
  const v = await audit("express", undefined, f);
  assert.equal(v.confidence, "low");
});

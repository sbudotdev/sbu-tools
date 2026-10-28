import { test } from "node:test";
import assert from "node:assert/strict";

process.env.SELLER_ADDRESS = "0x000000000000000000000000000000000000dEaD";
const { app } = await import("../src/server.ts");

test("invalid input is rejected before the payment step", async (t) => {
  const server = app.listen(0);
  t.after(() => server.close());
  const { port } = server.address() as { port: number };
  const res = await fetch(`http://localhost:${port}/npm-audit`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ package: "../etc/passwd" }),
  });
  assert.equal(res.status, 400);
  assert.equal(res.headers.get("payment-required"), null);
});

test("OpenAPI spec is free and points at the public URL", async (t) => {
  const server = app.listen(0);
  t.after(() => server.close());
  const { port } = server.address() as { port: number };
  const res = await fetch(`http://localhost:${port}/openapi.json`);
  const spec = await res.json();
  assert.equal(res.status, 200);
  assert.equal(spec.openapi, "3.1.0");
  assert.equal(spec.servers[0].url, "https://api.sbu.dev");
  assert.ok(spec.paths["/npm-audit"].post);
});

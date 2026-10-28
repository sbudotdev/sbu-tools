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

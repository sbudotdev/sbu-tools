import express, { type RequestHandler } from "express";
import { createGatewayMiddleware } from "@circle-fin/x402-batching/server";
import { isAddress } from "viem";
import { audit, NotFound } from "./audit.ts";

// npm name rules: lowercase, url-safe, optional scope, max 214 chars
const NAME = /^(@[a-z0-9-~][a-z0-9-._~]*\/)?[a-z0-9-~][a-z0-9-._~]*$/;
const VERSION = /^[0-9A-Za-z.+-]{1,64}$/;

// Testnet unless explicitly overridden: mainnet moves real, irreversible USDC.
const FACILITATOR = process.env.FACILITATOR_URL ?? "https://gateway-api-testnet.circle.com";
const SELLER = process.env.SELLER_ADDRESS ?? "";
if (!isAddress(SELLER)) throw new Error("SELLER_ADDRESS must be a valid EVM address");

const gateway = createGatewayMiddleware({
  sellerAddress: SELLER,
  facilitatorUrl: FACILITATOR,
  description: "npm package security verdict: CVEs, typosquatting, deprecation, staleness",
});

type Payment = { payer: string; amount: string; network: string; transaction?: string };

// Runs before payment so a malformed request never costs the caller anything.
const validate: RequestHandler = (req, res, next) => {
  const { package: name, version } = req.body ?? {};
  if (typeof name !== "string" || name.length > 214 || !NAME.test(name)) {
    res.status(400).json({ error: "invalid package name" });
    return;
  }
  if (version !== undefined && (typeof version !== "string" || !VERSION.test(version))) {
    res.status(400).json({ error: "invalid version" });
    return;
  }
  next();
};

export const app = express();
app.use(express.json({ limit: "1kb" }));
app.use((_req, res, next) => {
  res.setHeader("X-Powered-By", "sbu.dev");
  next();
});

app.get("/health", (_req, res) => {
  res.json({ ok: true, facilitator: FACILITATOR });
});

app.post("/npm-audit", validate, gateway.require("$0.01"), async (req, res) => {
  const { package: name, version } = req.body as { package: string; version?: string };
  const payment = (req as typeof req & { payment?: Payment }).payment;
  // ponytail: stdout is the payment ledger for now, move to SQLite when we need weekly counts
  console.log(JSON.stringify({ event: "paid_call", package: name, ...payment }));
  try {
    res.json(await audit(name, version));
  } catch (e) {
    // ponytail: payment already settled here, upstream failures are not refunded
    if (e instanceof NotFound) return res.status(404).json({ error: e.message });
    console.error(e);
    res.status(502).json({ error: "upstream error" });
  }
});

if (import.meta.main) {
  const port = Number(process.env.PORT ?? 3000);
  app.listen(port, () => console.log(`listening on :${port}, facilitator ${FACILITATOR}`));
}

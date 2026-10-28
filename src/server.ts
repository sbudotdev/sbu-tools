import express, { type Request, type RequestHandler } from "express";
import { createGatewayMiddleware } from "@circle-fin/x402-batching/server";
import { isAddress } from "viem";
import { audit, NotFound } from "./audit.ts";
import { openApiSpec } from "./openapi.ts";

const PRICE_PER_AUDIT_USD = "0.01";
const DEFAULT_PUBLIC_URL = "https://api.sbu.dev";
const MAX_BODY_SIZE = "1kb";
const MAX_PACKAGE_NAME_LENGTH = 214;
const NPM_PACKAGE_NAME = /^(@[a-z0-9-~][a-z0-9-._~]*\/)?[a-z0-9-~][a-z0-9-._~]*$/;
const PACKAGE_VERSION = /^[0-9A-Za-z.+-]{1,64}$/;
const TESTNET_FACILITATOR_URL = "https://gateway-api-testnet.circle.com";

const facilitatorUrl = process.env.FACILITATOR_URL ?? TESTNET_FACILITATOR_URL;
const publicUrl = process.env.PUBLIC_URL ?? DEFAULT_PUBLIC_URL;
const sellerAddress = process.env.SELLER_ADDRESS ?? "";
if (!isAddress(sellerAddress)) throw new Error("SELLER_ADDRESS must be a valid EVM address");

const gateway = createGatewayMiddleware({
  sellerAddress,
  facilitatorUrl,
  description: "npm package security verdict: CVEs, typosquatting, deprecation, staleness",
});

type AuditRequest = { package: string; version?: string };
type Payment = { payer: string; amount: string; network: string; transaction?: string };

function isValidAuditRequest(body: unknown): body is AuditRequest {
  const { package: name, version } = (body ?? {}) as Record<string, unknown>;
  const isValidName = typeof name === "string" && name.length <= MAX_PACKAGE_NAME_LENGTH && NPM_PACKAGE_NAME.test(name);
  const isValidVersion = version === undefined || (typeof version === "string" && PACKAGE_VERSION.test(version));
  return isValidName && isValidVersion;
}

function paymentOf(req: Request): Payment | undefined {
  return (req as Request & { payment?: Payment }).payment;
}

const rejectInvalidInputBeforePayment: RequestHandler = (req, res, next) => {
  if (isValidAuditRequest(req.body)) return next();
  res.status(400).json({ error: "body must be {\"package\": string, \"version\"?: string} with a valid npm name" });
};

export const app = express();
app.disable("x-powered-by");
app.use(express.json({ limit: MAX_BODY_SIZE }));
app.use((_req, res, next) => {
  res.setHeader("X-Powered-By", "sbu.dev");
  next();
});

app.get("/health", (_req, res) => {
  res.json({ ok: true, facilitator: facilitatorUrl });
});

const spec = openApiSpec(publicUrl, PRICE_PER_AUDIT_USD);
app.get("/openapi.json", (_req, res) => {
  res.json(spec);
});

app.post("/npm-audit", rejectInvalidInputBeforePayment, gateway.require(`$${PRICE_PER_AUDIT_USD}`), async (req, res) => {
  const { package: name, version } = req.body as AuditRequest;
  console.log(JSON.stringify({ event: "paid_call", package: name, ...paymentOf(req) }));
  try {
    res.json(await audit(name, version));
  } catch (error) {
    if (error instanceof NotFound) return res.status(404).json({ error: error.message });
    console.error(error);
    res.status(502).json({ error: "upstream error" });
  }
});

if (import.meta.main) {
  const port = Number(process.env.PORT ?? 3000);
  const server = app.listen(port, () => console.log(`listening on :${port}, facilitator ${facilitatorUrl}`));
  process.on("SIGTERM", () => server.close());
}

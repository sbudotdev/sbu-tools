# sbu-tools

Paid HTTP tools for AI agents, part of [sbu.dev](https://sbu.dev). Agents pay per call in USDC over [x402](https://x402.org) via Circle Gateway: no account, no API key.

## `POST /npm-audit`

Security verdict for an npm package before an agent installs it. $0.01 per call.

```bash
curl -i -X POST https://<host>/npm-audit \
  -H 'content-type: application/json' \
  -d '{"package":"lodash","version":"4.17.15"}'
```

Without payment the server answers `402 Payment Required` with a `PAYMENT-REQUIRED` header. An x402 client (for example `GatewayClient` from `@circle-fin/x402-batching/client`) pays and retries. Paid response:

```json
{
  "package": "lodash",
  "version": "4.17.15",
  "score": 0,
  "confidence": "high",
  "signals": [
    { "kind": "cve", "detail": "Command Injection in lodash", "source": "https://osv.dev/vulnerability/GHSA-35jh-r3h4-6jhm", "penalty": 25 }
  ]
}
```

| Signal | Penalty | Source |
| --- | --- | --- |
| `typosquat` | 60 | Name within 1-2 edits of a popular package |
| `cve` | 25 each | [OSV.dev](https://osv.dev) |
| `deprecated` | 20 | npm registry |
| `stale` | 15 | No registry change in 2 years |

`version` is optional and defaults to `latest`. `confidence` is `low` when OSV could not be reached.

## Run

```bash
npm install
SELLER_ADDRESS=0xYourPublicAddress npm start
npm test
```

| Variable | Default | |
| --- | --- | --- |
| `SELLER_ADDRESS` | required | Public EVM address that receives USDC. Never a private key. |
| `FACILITATOR_URL` | `https://gateway-api-testnet.circle.com` | Set `https://gateway-api.circle.com` for mainnet (real, irreversible USDC). |
| `PORT` | `3000` | |

Deploy: the `Dockerfile` runs as-is on Coolify, Fly.io or any Docker host, with a built-in health check on `GET /health`.

## Known limits

- Payment settles before the audit runs: if npm or OSV fail afterwards the caller gets a 502 and is not refunded. Invalid input is rejected before payment.
- Typosquat detection compares against a fixed list of 50 popular packages. A download-ranked list is the upgrade.
- Paid calls are logged to stdout as JSON (`"event":"paid_call"`), no database yet.
- No response cache: every paid call hits npm and OSV.

## License

MIT

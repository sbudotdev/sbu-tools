# Circle Agent Marketplace listing: npm-audit

Intake form: https://agents.circle.com/services ("Get listed").

## Form fields

| Field | Value |
| --- | --- |
| Endpoint URL | `https://api.sbu.dev/npm-audit` |
| Payout wallet | `0x106334BC40633215ACF28f55f1248De0e7013e67` |
| Short description | Security verdict for an npm package before an agent installs it: known CVEs, typosquatting, deprecation and staleness, scored 0-100 with a source link for every signal. $0.01 per call. |
| OpenAPI spec | `https://api.sbu.dev/openapi.json` |
| Category | Developer tools / Software supply-chain security |
| Price | $0.01 USDC per call |
| Support | https://github.com/sbudotdev/sbu-tools/issues |
| Source code | https://github.com/sbudotdev/sbu-tools (MIT) |

## Example prompts for agents

- "Before installing any npm package, call npm-audit and stop if the score is under 50."
- "Is `lodash@4.17.15` safe to add to this project?"
- "Check every dependency I am about to add in this PR for typosquats and known CVEs."
- "I typed `npm install lodahs`. Is that the package I meant?"

## Proof

Unpaid request returns 402 with x402 payment requirements:

```bash
curl -i -X POST https://api.sbu.dev/npm-audit \
  -H 'content-type: application/json' -d '{"package":"lodash"}'
# HTTP/2 402
# payment-required: eyJ4NDAyVmVyc2lvbiI6Mi...
```

Paid requests on Arc Testnet (`eip155:5042002`) returned 200, settled through Circle Gateway on 2026-10-28:

| Package | Amount | Gateway transaction |
| --- | --- | --- |
| `lodash@4.17.15` | 0.01 USDC | `492bae98-fa8d-40ed-bbcd-cdef45bbc28a` |
| `express` | 0.01 USDC | `10c4736f-0e31-48cd-aa6f-b1b43959c04b` |
| `lodahs` | 0.01 USDC | `7e1cb35b-0a83-4754-855a-13c2162b3f6b` |

Reproduce with `npm run buyer pay lodash 4.17.15` (see README).

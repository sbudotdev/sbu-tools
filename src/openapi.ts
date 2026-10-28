const signalSchema = {
  type: "object",
  required: ["kind", "detail", "source", "penalty"],
  properties: {
    kind: { type: "string", enum: ["typosquat", "cve", "deprecated", "stale"] },
    detail: { type: "string", description: "Human-readable reason, e.g. the CVE summary" },
    source: { type: "string", format: "uri", description: "Link to the evidence (OSV advisory, npm registry, popular package)" },
    penalty: { type: "integer", description: "Points subtracted from 100" },
  },
};

export function openApiSpec(serverUrl: string, priceUsd: string) {
  return {
    openapi: "3.1.0",
    info: {
      title: "sbu.dev npm-audit",
      version: "1.0.0",
      description:
        `Security verdict for an npm package before an AI agent installs it: known CVEs (OSV.dev), typosquatting, deprecation and staleness, scored 0-100 with a source link for every signal. Paid per call (${priceUsd} USDC) over x402 via Circle Gateway; no account or API key.`,
      contact: { url: "https://github.com/sbudotdev/sbu-tools/issues" },
      license: { name: "MIT", identifier: "MIT" },
    },
    servers: [{ url: serverUrl }],
    paths: {
      "/npm-audit": {
        post: {
          operationId: "auditNpmPackage",
          summary: "Audit an npm package",
          description: "Call before `npm install <package>`. A score under 50 means do not install without human review.",
          "x-price": { amount: priceUsd, currency: "USDC", protocol: "x402" },
          requestBody: {
            required: true,
            content: {
              "application/json": {
                schema: {
                  type: "object",
                  required: ["package"],
                  additionalProperties: false,
                  properties: {
                    package: { type: "string", maxLength: 214, description: "npm package name, optionally scoped", examples: ["lodash", "@types/node"] },
                    version: { type: "string", description: "Exact version; defaults to the latest dist-tag", examples: ["4.17.15"] },
                  },
                },
                example: { package: "lodash", version: "4.17.15" },
              },
            },
          },
          responses: {
            "200": {
              description: "Verdict",
              content: {
                "application/json": {
                  schema: {
                    type: "object",
                    required: ["package", "version", "score", "confidence", "signals"],
                    properties: {
                      package: { type: "string" },
                      version: { type: "string" },
                      score: { type: "integer", minimum: 0, maximum: 100, description: "100 = no issues found" },
                      confidence: { type: "string", enum: ["high", "low"], description: "low when the CVE database could not be reached" },
                      signals: { type: "array", items: signalSchema },
                    },
                  },
                  example: {
                    package: "lodahs",
                    version: "0.0.1-security",
                    score: 0,
                    confidence: "high",
                    signals: [
                      { kind: "typosquat", detail: "name is close to popular package \"lodash\"", source: "https://www.npmjs.com/package/lodash", penalty: 60 },
                    ],
                  },
                },
              },
            },
            "400": { description: "Invalid package name or version; rejected before payment, nothing is charged" },
            "402": { description: "Payment required; the PAYMENT-REQUIRED header carries the x402 payment requirements" },
            "404": { description: "Package or version not found on npm" },
            "502": { description: "npm registry unreachable" },
          },
        },
      },
    },
  };
}

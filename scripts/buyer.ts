import { GatewayClient } from "@circle-fin/x402-batching/client";
import { isAddress, isHex, type Address } from "viem";

const TESTNET_CHAINS = ["arcTestnet", "baseSepolia"] as const;
type TestnetChain = (typeof TESTNET_CHAINS)[number];

const apiUrl = process.env.API_URL ?? "https://api.sbu.dev";
const chain = (process.env.BUYER_CHAIN ?? "arcTestnet") as TestnetChain;
const privateKey = process.env.BUYER_PRIVATE_KEY;

if (!TESTNET_CHAINS.includes(chain)) throw new Error(`BUYER_CHAIN must be one of ${TESTNET_CHAINS.join(", ")}`);
if (!isHex(privateKey) || privateKey.length !== 66) throw new Error("BUYER_PRIVATE_KEY must be a 0x-prefixed 32-byte hex key of a testnet-only wallet");

const gateway = new GatewayClient({ chain, privateKey });
const [command, ...args] = process.argv.slice(2);

async function showBalance(address: Address = gateway.account.address): Promise<void> {
  const { wallet, gateway: deposited } = await gateway.getBalances(address);
  console.log(`${address} on ${chain}`);
  console.log(`wallet USDC:  ${wallet.formatted}`);
  console.log(`gateway USDC: ${deposited.formattedTotal}`);
}

async function deposit(amount: string): Promise<void> {
  const result = await gateway.deposit(amount);
  console.log(JSON.stringify(result, (_key, value) => (typeof value === "bigint" ? value.toString() : value), 2));
}

async function payForAudit(packageName: string, version?: string): Promise<void> {
  const result = await gateway.pay(`${apiUrl}/npm-audit`, {
    method: "POST",
    body: { package: packageName, version },
  });
  console.log(`paid ${result.formattedAmount} USDC, status ${result.status}, tx ${result.transaction}`);
  console.log(JSON.stringify(result.data, null, 2));
}

switch (command) {
  case "balance":
    if (args[0] && !isAddress(args[0])) throw new Error("usage: npm run buyer balance [0xAddress]");
    await showBalance(args[0] as Address | undefined);
    break;
  case "deposit":
    await deposit(args[0] ?? "1");
    break;
  case "pay":
    if (!args[0]) throw new Error("usage: npm run buyer pay <package> [version]");
    await payForAudit(args[0], args[1]);
    break;
  default:
    console.log("usage: npm run buyer <balance [0xAddress] | deposit [amount] | pay <package> [version]>");
}

import { z } from "zod";
import {
  decodeUtf8,
  fromBase64Url,
  toBase64Url,
  utf8,
} from "../security/encoding";

export const MAX_OPTION_CHAIN_RESPONSE_BYTES = 8 * 1_024 * 1_024;

const optionalMarketNumber = z.number().finite().nullable().optional();

const optionContractSchema = z
  .object({
    symbol: z.string().min(1),
    volatility: optionalMarketNumber,
    delta: optionalMarketNumber,
    gamma: optionalMarketNumber,
    theta: optionalMarketNumber,
    vega: optionalMarketNumber,
    rho: optionalMarketNumber,
    theoreticalOptionValue: optionalMarketNumber,
    theoreticalVolatility: optionalMarketNumber,
    quoteTimeInLong: optionalMarketNumber,
    tradeTimeInLong: optionalMarketNumber,
  })
  .passthrough();

const strikeMapSchema = z.record(z.string(), z.array(optionContractSchema));
const expirationMapSchema = z.record(z.string(), strikeMapSchema);

const optionChainResponseSchema = z
  .object({
    symbol: z.string().min(1).optional(),
    status: z.string().optional(),
    callExpDateMap: expirationMapSchema.optional(),
    putExpDateMap: expirationMapSchema.optional(),
  })
  .passthrough();

type OptionChainResponse = z.infer<typeof optionChainResponseSchema>;

export interface OptionChainPageOptions {
  outputMode: "paged" | "raw";
  contractCursor?: string | undefined;
  contractLimit: number;
}

export function formatOptionChainResponse(
  value: unknown,
  options: OptionChainPageOptions,
): unknown {
  const chain = optionChainResponseSchema.parse(value);
  if (options.outputMode === "raw") return value;

  const contracts = [
    ...flattenContracts("CALL", chain.callExpDateMap),
    ...flattenContracts("PUT", chain.putExpDateMap),
  ].sort(compareContracts);
  const afterKey = options.contractCursor
    ? decodeCursor(options.contractCursor)
    : undefined;
  const start =
    afterKey === undefined
      ? 0
      : contracts.findIndex(
          (contract) => compareKeys(contractKey(contract), afterKey) > 0,
        );
  const effectiveStart = start < 0 ? contracts.length : start;
  const end = Math.min(
    effectiveStart + options.contractLimit,
    contracts.length,
  );
  const selected = contracts.slice(effectiveStart, end);
  const metadata: Record<string, unknown> = { ...chain };
  delete metadata.callExpDateMap;
  delete metadata.putExpDateMap;

  return {
    source: "schwab",
    metadata,
    page: {
      cursor: options.contractCursor ?? null,
      limit: options.contractLimit,
      returned: selected.length,
      totalContracts: contracts.length,
      nextCursor:
        end < contracts.length && selected.length > 0
          ? encodeCursor(contractKey(selected[selected.length - 1]!))
          : null,
      fetchedAt: new Date().toISOString(),
    },
    contracts: selected,
  };
}

interface PagedContract {
  contractType: "CALL" | "PUT";
  expirationKey: string;
  strikeKey: string;
  contract: z.infer<typeof optionContractSchema>;
}

function flattenContracts(
  contractType: PagedContract["contractType"],
  expirationMap: OptionChainResponse["callExpDateMap"],
): PagedContract[] {
  if (!expirationMap) return [];
  const contracts: PagedContract[] = [];
  for (const [expirationKey, strikeMap] of Object.entries(expirationMap)) {
    for (const [strikeKey, values] of Object.entries(strikeMap)) {
      for (const contract of values) {
        contracts.push({ contractType, expirationKey, strikeKey, contract });
      }
    }
  }
  return contracts;
}

function compareContracts(left: PagedContract, right: PagedContract): number {
  return compareKeys(contractKey(left), contractKey(right));
}

function contractKey(value: PagedContract): string {
  const strike = Number(value.strikeKey);
  const sortableStrike = Number.isFinite(strike)
    ? strike.toFixed(8).padStart(32, "0")
    : value.strikeKey;
  return [
    value.expirationKey,
    sortableStrike,
    value.contractType,
    value.contract.symbol,
  ].join("\u0000");
}

function encodeCursor(key: string): string {
  return `v1.${toBase64Url(utf8(key))}`;
}

function decodeCursor(cursor: string): string {
  if (!cursor.startsWith("v1.")) throw new Error("Invalid option-chain cursor");
  try {
    return decodeUtf8(fromBase64Url(cursor.slice(3)));
  } catch {
    throw new Error("Invalid option-chain cursor");
  }
}

function compareKeys(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

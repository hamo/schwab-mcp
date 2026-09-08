import { z } from "zod";

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
  contractOffset: number;
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
  const end = Math.min(
    options.contractOffset + options.contractLimit,
    contracts.length,
  );
  const metadata: Record<string, unknown> = { ...chain };
  delete metadata.callExpDateMap;
  delete metadata.putExpDateMap;

  return {
    source: "schwab",
    metadata,
    page: {
      offset: options.contractOffset,
      limit: options.contractLimit,
      returned: Math.max(0, end - options.contractOffset),
      totalContracts: contracts.length,
      nextOffset: end < contracts.length ? end : null,
    },
    contracts: contracts.slice(options.contractOffset, end),
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
  return (
    left.expirationKey.localeCompare(right.expirationKey) ||
    Number(left.strikeKey) - Number(right.strikeKey) ||
    left.contractType.localeCompare(right.contractType) ||
    left.contract.symbol.localeCompare(right.contract.symbol)
  );
}

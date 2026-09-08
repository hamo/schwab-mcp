import { z } from "zod";

export const marketSymbolSchema = z
  .string()
  .trim()
  .min(1)
  .max(32)
  .regex(/^[A-Za-z0-9.$/:_-]+$/);

export const tradableSymbolSchema = z
  .string()
  .trim()
  .min(1)
  .max(64)
  .regex(
    /^[A-Za-z0-9.$/:_ -]+$/,
    "Symbol may contain only supported market-symbol characters",
  );

export const quoteFieldSchema = z.enum([
  "quote",
  "fundamental",
  "extended",
  "reference",
  "regular",
  "all",
]);

export const quoteFieldsInputSchema = z
  .union([quoteFieldSchema, z.array(quoteFieldSchema).min(1).max(6)])
  .transform((value) => (Array.isArray(value) ? value : [value]));

export const priceHistoryInputSchema = z
  .object({
    symbol: marketSymbolSchema,
    periodType: z.enum(["day", "month", "year", "ytd"]).optional(),
    period: z
      .union([
        z.literal(1),
        z.literal(2),
        z.literal(3),
        z.literal(4),
        z.literal(5),
        z.literal(6),
        z.literal(10),
        z.literal(15),
        z.literal(20),
      ])
      .optional(),
    frequencyType: z.enum(["minute", "daily", "weekly", "monthly"]).optional(),
    frequency: z
      .union([
        z.literal(1),
        z.literal(5),
        z.literal(10),
        z.literal(15),
        z.literal(30),
      ])
      .optional(),
    startDate: z
      .union([z.number().int().nonnegative(), z.string().date()])
      .optional(),
    endDate: z
      .union([z.number().int().nonnegative(), z.string().date()])
      .optional(),
    needExtendedHoursData: z.boolean().optional(),
    needPreviousClose: z.boolean().optional(),
    outputMode: z.enum(["paged", "raw"]).default("paged"),
    outputCursor: z.string().max(2_048).optional(),
    outputLimit: z.number().int().positive().max(50).default(25),
  })
  .strict()
  .superRefine((value, context) => {
    const allowedPeriods: Record<string, number[]> = {
      day: [1, 2, 3, 4, 5, 10],
      month: [1, 2, 3, 6],
      year: [1, 2, 3, 5, 10, 15, 20],
      ytd: [1],
    };
    if (value.period !== undefined && value.periodType === undefined) {
      context.addIssue({
        code: "custom",
        path: ["periodType"],
        message: "periodType is required when period is provided",
      });
    }
    if (
      value.periodType &&
      value.period !== undefined &&
      !allowedPeriods[value.periodType]?.includes(value.period)
    ) {
      context.addIssue({
        code: "custom",
        path: ["period"],
        message: `Invalid period for periodType=${value.periodType}`,
      });
    }
    if (
      value.startDate !== undefined &&
      value.endDate !== undefined &&
      toEpochMillis(value.startDate) > toEpochMillis(value.endDate, "end")
    ) {
      context.addIssue({
        code: "custom",
        path: ["endDate"],
        message: "endDate must not precede startDate",
      });
    }
    if (
      value.frequencyType &&
      value.frequency !== undefined &&
      value.frequencyType !== "minute" &&
      value.frequency !== 1
    ) {
      context.addIssue({
        code: "custom",
        path: ["frequency"],
        message: `frequency must be 1 for ${value.frequencyType} candles`,
      });
    }
    const allowedFrequencyTypes: Record<string, string[]> = {
      day: ["minute"],
      month: ["daily", "weekly"],
      year: ["daily", "weekly", "monthly"],
      ytd: ["daily", "weekly"],
    };
    if (
      value.periodType &&
      value.frequencyType &&
      !allowedFrequencyTypes[value.periodType]?.includes(value.frequencyType)
    ) {
      context.addIssue({
        code: "custom",
        path: ["frequencyType"],
        message: `Invalid frequencyType for periodType=${value.periodType}`,
      });
    }
  });

export function normalizePriceHistoryDates(
  value: Record<string, string | number | boolean | undefined>,
): Record<string, string | number | boolean | undefined> {
  const startDate = value.startDate;
  const endDate = value.endDate;
  return {
    ...value,
    ...(typeof startDate === "string" || typeof startDate === "number"
      ? { startDate: toEpochMillis(startDate) }
      : {}),
    ...(typeof endDate === "string" || typeof endDate === "number"
      ? { endDate: toEpochMillis(endDate, "end") }
      : {}),
  };
}

export const optionChainInputSchema = z
  .object({
    symbol: marketSymbolSchema,
    contractType: z.enum(["CALL", "PUT", "ALL"]).default("ALL"),
    strikeCount: z.number().int().positive().max(100).default(20),
    includeUnderlyingQuote: z.boolean().default(false),
    strategy: z
      .enum([
        "SINGLE",
        "ANALYTICAL",
        "COVERED",
        "VERTICAL",
        "CALENDAR",
        "STRANGLE",
        "STRADDLE",
        "BUTTERFLY",
        "CONDOR",
        "DIAGONAL",
        "COLLAR",
        "ROLL",
      ])
      .optional(),
    interval: z.number().positive().optional(),
    strike: z.number().positive().optional(),
    range: z.enum(["ITM", "NTM", "OTM", "SAK", "SBK", "SNK", "ALL"]).optional(),
    fromDate: z.string().date().optional(),
    toDate: z.string().date().optional(),
    volatility: z.number().nonnegative().optional(),
    underlyingPrice: z.number().positive().optional(),
    interestRate: z.number().finite().optional(),
    daysToExpiration: z.number().int().nonnegative().optional(),
    expMonth: z
      .enum([
        "ALL",
        "JAN",
        "FEB",
        "MAR",
        "APR",
        "MAY",
        "JUN",
        "JUL",
        "AUG",
        "SEP",
        "OCT",
        "NOV",
        "DEC",
      ])
      .optional(),
    optionType: z.enum(["S", "NS", "ALL"]).optional(),
    entitlement: z.enum(["PN", "NP", "PP"]).optional(),
    outputMode: z
      .enum(["paged", "raw"])
      .default("paged")
      .describe(
        "Use paged for bounded contract output; use raw only with narrow date and strike filters",
      ),
    contractCursor: z
      .string()
      .max(2_048)
      .optional()
      .describe("Opaque nextCursor returned by the preceding contract page"),
    contractLimit: z
      .number()
      .int()
      .positive()
      .max(50)
      .default(25)
      .describe("Maximum contracts returned in paged output"),
  })
  .strict()
  .refine(
    (value) =>
      !value.fromDate || !value.toDate || value.fromDate <= value.toDate,
    { path: ["toDate"], message: "toDate must not precede fromDate" },
  );

export const marketSchema = z.enum([
  "equity",
  "option",
  "bond",
  "future",
  "forex",
]);

export const moverIndexSchema = z.enum([
  "$DJI",
  "$COMPX",
  "$SPX",
  "NYSE",
  "NASDAQ",
  "OTCBB",
  "INDEX_ALL",
  "EQUITY_ALL",
  "OPTION_ALL",
  "OPTION_PUT",
  "OPTION_CALL",
]);

export const instrumentProjectionSchema = z.enum([
  "symbol-search",
  "symbol-regex",
  "desc-search",
  "desc-regex",
  "search",
  "fundamental",
]);

function toEpochMillis(
  value: number | string,
  boundary: "start" | "end" = "start",
): number {
  if (typeof value === "number") return value;
  const start = Date.parse(`${value}T00:00:00.000Z`);
  return boundary === "end" ? start + 24 * 60 * 60 * 1_000 - 1 : start;
}

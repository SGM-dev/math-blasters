/**
 * Normalise raw submission before comparison:
 * - handles numbers and strings
 * - trimmed
 * - unicode minus (U+2212) and dashes (U+2013, U+2014) converted to ASCII '-'
 * - '1,000' and '1 000' read as a thousand
 * - empty or null/undefined submissions return empty string
 */
export function normalizeSubmission(raw: unknown): string {
  if (raw == null) return "";
  const str = typeof raw === "string" ? raw : String(raw);
  const trimmed = str.trim();
  if (trimmed === "") return "";

  // Normalize Unicode minus and dashes to ASCII '-'
  const dashNormalized = trimmed.replace(/[\u2212\u2013\u2014]/g, "-");

  // Normalize thousands separators: "1,000" and "1 000" -> "1000"
  const thousandsNormalized = dashNormalized.replace(
    /(?<=\d)[, ](?=\d{3}(?!\d))/g,
    "",
  );

  return thousandsNormalized;
}

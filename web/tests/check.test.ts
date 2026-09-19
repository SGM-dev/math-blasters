import { describe, it, expect } from "vitest";
import { normalizeSubmission } from "../src/content/check";
import { checkEquivalent } from "../src/content/equivalent";
import type { EquivalentCriterion } from "../src/content/types";

describe("normalizeSubmission", () => {
  it("trims whitespace from input", () => {
    expect(normalizeSubmission("  42  ")).toBe("42");
    expect(normalizeSubmission("\t\n 100 \n\t")).toBe("100");
  });

  it("normalizes unicode minus (U+2212) and dashes to ASCII minus", () => {
    expect(normalizeSubmission("−5")).toBe("-5");
    expect(normalizeSubmission("–42")).toBe("-42");
    expect(normalizeSubmission("—100")).toBe("-100");
  });

  it("normalizes numbers with comma or space thousands separators", () => {
    expect(normalizeSubmission("1,000")).toBe("1000");
    expect(normalizeSubmission("1 000")).toBe("1000");
    expect(normalizeSubmission("-1 000")).toBe("-1000");
    expect(normalizeSubmission("1,000,000")).toBe("1000000");
    expect(normalizeSubmission("1 000 000")).toBe("1000000");
  });

  it("handles numbers passed directly as submission", () => {
    expect(normalizeSubmission(42)).toBe("42");
    expect(normalizeSubmission(0)).toBe("0");
    expect(normalizeSubmission(-15)).toBe("-15");
  });

  it("returns empty string for empty or whitespace-only submissions", () => {
    expect(normalizeSubmission("")).toBe("");
    expect(normalizeSubmission("   ")).toBe("");
    expect(normalizeSubmission("\t\n ")).toBe("");
    expect(normalizeSubmission(null)).toBe("");
    expect(normalizeSubmission(undefined)).toBe("");
  });
});

describe("checkEquivalent stub", () => {
  it("throws indicating checkEquivalent is not yet implemented without leaking expected", () => {
    const criterion: EquivalentCriterion = {
      check: "equivalent",
      expected: "secret_formula_x^2 + 2x + 1",
      reason_code: "not_symbolically_equivalent",
    };

    let thrownError: Error | undefined;
    try {
      checkEquivalent(criterion, "x^2 + 2x + 1");
    } catch (err) {
      thrownError = err as Error;
    }

    expect(thrownError).toBeDefined();
    expect(thrownError?.message).toBe("checkEquivalent is not yet implemented");
    expect(thrownError?.message).not.toContain(criterion.expected);
  });
});

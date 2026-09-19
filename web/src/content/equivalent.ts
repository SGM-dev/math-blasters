import type { CriterionResult, EquivalentCriterion } from "./types";

/**
 * Stub for symbolic math equivalence via mathjs.
 * Throws until symbolic equivalence is fully implemented.
 * Never logs, throws, or returns the authored expected value.
 */
export function checkEquivalent(
  _criterion: EquivalentCriterion,
  _submission: unknown,
): CriterionResult {
  throw new Error("checkEquivalent is not yet implemented");
}

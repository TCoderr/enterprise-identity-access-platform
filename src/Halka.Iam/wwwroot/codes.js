// @ts-check
// Pure helpers for code entry fields (shared by the page script and its unit tests).

/**
 * Keeps the digits of a pasted or typed one-time code ("123 456", "123-456") and limits it to six.
 * @param {string} value
 * @returns {string}
 */
export function normalizeOneTimeCode(value) {
  return value.replace(/\D+/g, "").slice(0, 6);
}

/**
 * Normalizes a recovery code to upper-case groups of four separated by dashes.
 * Characters outside the base32 alphabet used for recovery codes are dropped.
 * @param {string} value
 * @returns {string}
 */
export function normalizeRecoveryCode(value) {
  const compact = value.toUpperCase().replace(/[^A-Z2-7]+/g, "").slice(0, 16);
  return compact.replace(/(.{4})(?=.)/g, "$1-");
}

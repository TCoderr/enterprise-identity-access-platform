import assert from "node:assert/strict";
import { test } from "node:test";
import { normalizeOneTimeCode, normalizeRecoveryCode } from "../../wwwroot/codes.js";

test("one-time codes keep six digits and drop separators", () => {
  assert.equal(normalizeOneTimeCode("123 456"), "123456");
  assert.equal(normalizeOneTimeCode("123-456"), "123456");
  assert.equal(normalizeOneTimeCode(" 12 34 56 "), "123456");
  assert.equal(normalizeOneTimeCode("1234567"), "123456");
  assert.equal(normalizeOneTimeCode("abc"), "");
  assert.equal(normalizeOneTimeCode(""), "");
});

test("one-time codes pasted with surrounding text keep only digits", () => {
  assert.equal(normalizeOneTimeCode("Your code is 482 913."), "482913");
});

test("recovery codes are upper-cased and grouped by four", () => {
  assert.equal(normalizeRecoveryCode("abcdefghijklmnop"), "ABCD-EFGH-IJKL-MNOP");
  assert.equal(normalizeRecoveryCode("abcd efgh ijkl mnop"), "ABCD-EFGH-IJKL-MNOP");
  assert.equal(normalizeRecoveryCode("ABCD-EFGH-IJKL-MNOP"), "ABCD-EFGH-IJKL-MNOP");
});

test("recovery codes drop characters outside the base32 alphabet and extra input", () => {
  assert.equal(normalizeRecoveryCode("ab01cd89"), "ABCD");
  assert.equal(normalizeRecoveryCode("abcdefghijklmnopqrst"), "ABCD-EFGH-IJKL-MNOP");
  assert.equal(normalizeRecoveryCode("abc"), "ABC");
  assert.equal(normalizeRecoveryCode(""), "");
});

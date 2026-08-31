import { describe, expect, it } from "vitest";

import {
  validateDirectorCredentialModalReply,
  validateDirectorDecisionModalReply,
} from "../../src/main/authority-modal-contracts";
import { directorReview } from "../fixtures/director-review";

describe("Director authority modal contracts", () => {
  it("accepts only the exact nonce-bound credential submission", () => {
    expect(
      validateDirectorCredentialModalReply(
        {
          nonce: "nonce_01",
          action: "submit",
          passphrase: "correct horse battery staple",
        },
        "nonce_01",
      ),
    ).toEqual({
      action: "submit",
      passphrase: "correct horse battery staple",
    });
    expect(
      validateDirectorCredentialModalReply(
        { nonce: "nonce_01", action: "submit", passphrase: "😀".repeat(4) },
        "nonce_01",
      ),
    ).toEqual({ action: "submit", passphrase: "😀".repeat(4) });
    expect(
      validateDirectorCredentialModalReply(
        { nonce: "nonce_01", action: "cancel" },
        "nonce_01",
      ),
    ).toEqual({ action: "cancel" });

    for (const value of [
      { nonce: "wrong", action: "cancel" },
      { nonce: "nonce_01", action: "submit", passphrase: "too short" },
      { nonce: "nonce_01", action: "submit", passphrase: "\ud800".repeat(6) },
      { nonce: "nonce_01", action: "submit", passphrase: "\udfff".repeat(6) },
      { nonce: "nonce_01", action: "submit", passphrase: "a".repeat(16) + "\ud800" },
      {
        nonce: "nonce_01",
        action: "submit",
        passphrase: "correct horse battery staple",
        persist: true,
      },
    ]) {
      expect(() =>
        validateDirectorCredentialModalReply(value, "nonce_01"),
      ).toThrow();
    }
  });

  it("accepts only canonical candidate selection and a future expiry", () => {
    expect(
      validateDirectorDecisionModalReply(
        {
          nonce: "nonce_02",
          action: "approve",
          approvedToolIds: ["source.read"],
          expiresAtMs: 20_000,
        },
        {
          expectedNonce: "nonce_02",
          review: directorReview,
          nowMs: 10_000,
        },
      ),
    ).toEqual({
      action: "approve",
      approvedToolIds: ["source.read"],
      expiresAtMs: 20_000,
    });
    expect(
      validateDirectorDecisionModalReply(
        { nonce: "nonce_02", action: "deny" },
        {
          expectedNonce: "nonce_02",
          review: directorReview,
          nowMs: 10_000,
        },
      ),
    ).toEqual({ action: "deny" });

    for (const value of [
      {
        nonce: "nonce_02",
        action: "approve",
        approvedToolIds: ["world.validate", "source.read"],
        expiresAtMs: 20_000,
      },
      {
        nonce: "nonce_02",
        action: "approve",
        approvedToolIds: ["source.read"],
        expiresAtMs: 10_000,
      },
      {
        nonce: "nonce_02",
        action: "approve",
        approvedToolIds: ["source.read"],
        expiresAtMs: 20_000,
        reviewerId: "director_local",
      },
    ]) {
      expect(() =>
        validateDirectorDecisionModalReply(value, {
          expectedNonce: "nonce_02",
          review: directorReview,
          nowMs: 10_000,
        }),
      ).toThrow();
    }
  });
});

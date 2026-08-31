// @vitest-environment jsdom

import { readFile } from "node:fs/promises";
import path from "node:path";

import { fireEvent } from "@testing-library/dom";
import { afterEach, describe, expect, it, vi } from "vitest";

import { directorReview } from "../fixtures/director-review";

afterEach(() => {
  vi.resetModules();
  Reflect.deleteProperty(window, "worldForgeAuthorityModal");
  document.body.replaceChildren();
});

describe("Director credential authority modal", () => {
  it("renders the cost ceiling as exact minor units", async () => {
    const html = await readFile(
      path.join(process.cwd(), "src/authority-modal/index.html"),
      "utf8",
    );
    const parsed = new DOMParser().parseFromString(html, "text/html");
    document.body.replaceWith(parsed.body);

    let receivePayload!: (payload: Record<string, unknown>) => void;
    Object.defineProperty(window, "worldForgeAuthorityModal", {
      configurable: true,
      value: {
        onPayload(callback: typeof receivePayload) {
          receivePayload = callback;
        },
        reply: vi.fn(),
      },
    });
    // @ts-expect-error The isolated browser script intentionally has no module declarations.
    await import("../../src/authority-modal/renderer.js");

    receivePayload({
      kind: "director-decision",
      nonce: "nonce_exact_minor_units",
      review: directorReview,
    });

    expect(document.body).toHaveTextContent("Max cost (minor units)");
    expect(document.querySelector("#director-cost")).toHaveTextContent(
      /^25 minor units \(USD\)$/u,
    );
    expect(document.querySelector("#director-cost")).not.toHaveTextContent(
      /^25 USD$/u,
    );
  });

  it("validates the documented UTF-8 byte bounds before returning a passphrase", async () => {
    const html = await readFile(
      path.join(process.cwd(), "src/authority-modal/index.html"),
      "utf8",
    );
    const parsed = new DOMParser().parseFromString(html, "text/html");
    document.body.replaceWith(parsed.body);

    let receivePayload!: (payload: Record<string, unknown>) => void;
    const reply = vi.fn();
    Object.defineProperty(window, "worldForgeAuthorityModal", {
      configurable: true,
      value: {
        onPayload(callback: typeof receivePayload) {
          receivePayload = callback;
        },
        reply,
      },
    });
    // @ts-expect-error The isolated browser script intentionally has no module declarations.
    await import("../../src/authority-modal/renderer.js");
    receivePayload({
      kind: "director-credential",
      nonce: "nonce_utf8_bounds",
      credentialId: "director_local",
      mode: "enroll",
    });

    const input = document.querySelector<HTMLInputElement>("#director-passphrase");
    const form = document.querySelector<HTMLFormElement>("#credential-form");
    expect(input).not.toBeNull();
    expect(form).not.toBeNull();
    expect(input).toHaveAttribute("autocomplete", "off");

    input!.value = "é".repeat(600);
    fireEvent.submit(form!);
    expect(reply).not.toHaveBeenCalled();
    expect(document.querySelector("#modal-status")).toHaveTextContent(
      "Passphrase must be 16–1024 UTF-8 bytes.",
    );
    expect(input).toHaveAttribute("aria-invalid", "true");

    for (const surrogate of [
      "\ud800".repeat(6),
      "\udfff".repeat(6),
      "a".repeat(16) + "\ud800",
    ]) {
      input!.value = surrogate;
      fireEvent.submit(form!);
      expect(reply).not.toHaveBeenCalled();
      expect(document.querySelector("#modal-status")).toHaveTextContent(
        "Passphrase must be 16–1024 UTF-8 bytes.",
      );
      expect(input).toHaveAttribute("aria-invalid", "true");
    }

    input!.value = "😀".repeat(4);
    fireEvent.submit(form!);
    expect(reply).toHaveBeenCalledWith({
      nonce: "nonce_utf8_bounds",
      action: "submit",
      passphrase: "😀".repeat(4),
    });
    expect(input).toHaveValue("");
  });
});

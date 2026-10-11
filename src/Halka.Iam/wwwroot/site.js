// @ts-check
// Progressive enhancement only: every flow works without this file. Nothing is written to web storage.
import { normalizeOneTimeCode, normalizeRecoveryCode } from "./codes.js";

/** @param {ParentNode} root */
function enhanceCodeInputs(root) {
  for (const input of root.querySelectorAll("input[data-code]")) {
    if (!(input instanceof HTMLInputElement)) continue;
    const normalize = input.dataset.code === "recovery" ? normalizeRecoveryCode : normalizeOneTimeCode;
    input.addEventListener("paste", (event) => {
      const text = event.clipboardData?.getData("text");
      if (text === undefined) return;
      event.preventDefault();
      input.value = normalize(text);
    });
    input.addEventListener("blur", () => {
      input.value = normalize(input.value);
    });
  }
}

/** @param {ParentNode} root */
function enhanceCopyButtons(root) {
  for (const button of root.querySelectorAll("button[data-copy-from]")) {
    if (!(button instanceof HTMLButtonElement)) continue;
    button.hidden = !navigator.clipboard;
    button.addEventListener("click", async () => {
      const source = document.getElementById(button.dataset.copyFrom ?? "");
      const status = document.getElementById(button.dataset.copyStatus ?? "");
      if (!source) return;
      try {
        await navigator.clipboard.writeText(source.textContent?.trim() ?? "");
        if (status) status.textContent = "Copied to clipboard.";
      } catch {
        if (status) status.textContent = "Copy failed. Select the text and copy it manually.";
      }
    });
  }
}

/** @param {ParentNode} root */
function enhancePrintButtons(root) {
  for (const button of root.querySelectorAll("button[data-print]")) {
    if (!(button instanceof HTMLButtonElement)) continue;
    button.hidden = false;
    button.addEventListener("click", () => window.print());
  }
}

enhanceCodeInputs(document);
enhanceCopyButtons(document);
enhancePrintButtons(document);

// Certificate.Display(): the certificate's fields in a window on the page, in a shadow root like the PIN window's, where
// CryptoPro shows the system's certificate window. It closes on its button or Escape.
import { element, style } from "./pin-dialog.ts";

export const CERTIFICATE_HOST_ID = "rutoken-cades-bridge-certificate";

const extra = `
  dl { margin: 0; display: grid; grid-template-columns: max-content 1fr; gap: 4px 12px; }
  dt { color: #555; }
  dd { margin: 0; overflow-wrap: anywhere; }
`;

// Resolves once the user has closed the window.
export function showCertificateDialog(doc: Document, fields: [string, string][]): Promise<void> {
  const host = element(doc, "div", { id: CERTIFICATE_HOST_ID });
  const root = host.attachShadow({ mode: "open" });
  const close = element(doc, "button", { type: "submit", name: "confirm" }, "Закрыть");
  const form = element(
    doc,
    "form",
    { className: "dialog" },
    element(doc, "h2", {}, "Сертификат"),
    element(doc, "dl", {}, ...fields.flatMap(([label, value]) => [element(doc, "dt", {}, label), element(doc, "dd", {}, value)])),
    element(doc, "div", { className: "buttons" }, close),
  );
  form.setAttribute("role", "dialog");
  form.setAttribute("aria-label", "Сертификат");
  root.append(element(doc, "style", {}, style + extra), element(doc, "div", { className: "backdrop" }, form));
  (doc.body ?? doc.documentElement).append(host);
  close.focus();
  return new Promise((resolve) => {
    const done = () => {
      host.remove();
      resolve();
    };
    form.addEventListener("submit", (event) => {
      event.preventDefault();
      done();
    });
    form.addEventListener("keydown", (event) => {
      if (event.key === "Escape") done();
    });
  });
}

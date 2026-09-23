// The window shown before every operation that needs the token's PIN (a signature, a new key, writing a
// certificate): which site asks, what it asks for, and the PIN field. It lives in the page, in the shadow DOM of our own element: the PIN reaches the
// Rutoken Plugin through the adapter's postMessage in the page world anyway, so a window isolated
// from the page would not hide it (docs/PLAN.md of stage 4).

export interface PinRequest {
  origin: string;
  // Completes "Сайт <origin> …", e.g. "просит подписать данные."
  action: string;
  // One paragraph each: what is signed, with which certificate, on which token.
  details: string[];
  // The confirming button, e.g. "Подписать".
  confirm: string;
}

export interface PinDialog {
  // Resolves with the PIN, or null when the user cancels. `error` is shown above the field.
  ask(error?: string): Promise<string | null>;
  close(): void;
}

export const HOST_ID = "rutoken-cades-bridge-pin";

const style = `
  :host { all: initial; }
  .backdrop { position: fixed; inset: 0; z-index: 2147483647; background: rgba(0, 0, 0, 0.45);
    display: flex; align-items: center; justify-content: center; font: 14px/1.4 system-ui, sans-serif; }
  .dialog { background: #fff; color: #1b1b1b; border-radius: 8px; padding: 20px 24px; width: min(420px, calc(100vw - 32px));
    box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3); }
  h2 { font-size: 17px; margin: 0 0 12px; }
  p { margin: 0 0 8px; }
  .origin { font-weight: 600; word-break: break-all; }
  label { display: block; margin: 12px 0 4px; }
  input { box-sizing: border-box; width: 100%; font: inherit; padding: 6px 8px; border: 1px solid #888; border-radius: 4px; }
  .error { color: #b00020; min-height: 1.4em; margin: 6px 0 0; }
  .buttons { display: flex; justify-content: flex-end; gap: 8px; margin-top: 16px; }
  button { font: inherit; padding: 6px 16px; border-radius: 4px; border: 1px solid #888; background: #f3f3f3; cursor: pointer; }
  button[name="confirm"] { background: #1a5fb4; border-color: #1a5fb4; color: #fff; }
`;

function element<K extends keyof HTMLElementTagNameMap>(
  doc: Document,
  tag: K,
  props: Partial<HTMLElementTagNameMap[K]> = {},
  ...children: (Node | string)[]
): HTMLElementTagNameMap[K] {
  const node = Object.assign(doc.createElement(tag), props);
  node.append(...children);
  return node;
}

export function openPinDialog(doc: Document, request: PinRequest): PinDialog {
  const host = element(doc, "div", { id: HOST_ID });
  const root = host.attachShadow({ mode: "open" });
  const pin = element(doc, "input", { type: "password", name: "pin", autocomplete: "off" });
  const error = element(doc, "p", { className: "error" });
  error.setAttribute("role", "alert");
  const confirm = element(doc, "button", { type: "submit", name: "confirm" }, request.confirm);
  const cancel = element(doc, "button", { type: "button", name: "cancel" }, "Отмена");
  const form = element(
    doc,
    "form",
    { className: "dialog" },
    element(doc, "h2", {}, "Рутокен вместо КриптоПро"),
    element(doc, "p", {}, "Сайт ", element(doc, "span", { className: "origin" }, request.origin), ` ${request.action}`),
    ...request.details.map((line) => element(doc, "p", {}, line)),
    element(doc, "label", {}, "PIN-код Рутокена", pin),
    error,
    element(doc, "div", { className: "buttons" }, cancel, confirm),
  );
  form.setAttribute("role", "dialog");
  form.setAttribute("aria-label", "PIN-код Рутокена");
  root.append(element(doc, "style", {}, style), element(doc, "div", { className: "backdrop" }, form));
  (doc.body ?? doc.documentElement).append(host);

  let answer: ((pin: string | null) => void) | undefined;
  const respond = (value: string | null) => {
    const resolve = answer;
    answer = undefined;
    resolve?.(value);
  };
  form.addEventListener("submit", (event) => {
    event.preventDefault();
    if (pin.value) respond(pin.value);
  });
  cancel.addEventListener("click", () => respond(null));
  form.addEventListener("keydown", (event) => {
    if (event.key === "Escape") respond(null);
  });

  return {
    ask(message = "") {
      error.textContent = message;
      pin.value = "";
      confirm.disabled = false;
      pin.focus();
      return new Promise((resolve) => {
        answer = (value) => {
          confirm.disabled = true;
          resolve(value);
        };
      });
    },
    close() {
      respond(null);
      host.remove();
    },
  };
}

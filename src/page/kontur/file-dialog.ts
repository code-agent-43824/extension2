// The windows of Kontur.Plugin's ui.openFile, ui.saveFile and ui.selectFolder (src/page/kontur/files.ts), in a shadow
// root like the PIN window's, where the host shows the system's file windows. Choosing a file needs the user's click
// on the page's file input, which is why the extension's own window comes first; saving and folders name only where
// the browser's downloads will be.
import { element, style } from "../pin-dialog.ts";

export const FILES_HOST_ID = "rutoken-cades-bridge-files";

export interface ChosenFile {
  name: string;
  bytes: Uint8Array;
}

export interface FileDialogs {
  // The files chosen and read, or null when the user cancels.
  open(options: { origin: string; title: string; multiple: boolean; accept: string }): Promise<ChosenFile[] | null>;
  // The name to save under, or null.
  save(options: { origin: string; title: string; filename: string }): Promise<string | null>;
  // Whether the user agreed to have the site's files go to the downloads.
  folder(options: { origin: string; title: string }): Promise<boolean>;
}

const extra = `
  input[type="file"] { border: none; padding: 0; }
  .note { font-style: normal; color: #555; }
`;

// One window: its form with these fields, and a way to wait for the answer; the window goes away with it.
function show<T>(doc: Document, title: string, lead: Node[], fields: Node[], confirmText: string, read: () => T | Promise<T> | undefined): { confirm: HTMLButtonElement; done: Promise<T | null> } {
  const host = element(doc, "div", { id: FILES_HOST_ID });
  const root = host.attachShadow({ mode: "open" });
  const confirm = element(doc, "button", { type: "submit", name: "confirm" }, confirmText);
  const cancel = element(doc, "button", { type: "button", name: "cancel" }, "Отмена");
  const form = element(doc, "form", { className: "dialog" }, element(doc, "h2", {}, title), ...lead, ...fields, element(doc, "div", { className: "buttons" }, cancel, confirm));
  form.setAttribute("role", "dialog");
  form.setAttribute("aria-label", title);
  root.append(element(doc, "style", {}, style + extra), element(doc, "div", { className: "backdrop" }, form));
  (doc.body ?? doc.documentElement).append(host);
  const done = new Promise<T | null>((resolve) => {
    const finish = (value: T | null) => {
      host.remove();
      resolve(value);
    };
    form.addEventListener("submit", (event) => {
      event.preventDefault();
      const value = read();
      if (value === undefined) return;
      confirm.disabled = true;
      void Promise.resolve(value).then(finish, () => finish(null));
    });
    cancel.addEventListener("click", () => finish(null));
    form.addEventListener("keydown", (event) => {
      if (event.key === "Escape") finish(null);
    });
  });
  return { confirm, done };
}

const asking = (doc: Document, origin: string, what: string) => [element(doc, "p", {}, "Сайт ", element(doc, "span", { className: "origin" }, origin), ` ${what}`)];
const downloadsNote = (doc: Document, text: string) => element(doc, "p", { className: "note" }, text);

export function pageFileDialogs(doc: Document): FileDialogs {
  return {
    open({ origin, title, multiple, accept }) {
      const input = element(doc, "input", { type: "file", name: "files", multiple, accept });
      const opened = show(doc, title, asking(doc, origin, multiple ? "просит файлы для Контур.Плагина." : "просит файл для Контур.Плагина."), [input], "Выбрать", () => {
        const files = Array.from(input.files ?? []);
        if (!files.length) return undefined;
        return Promise.all(files.map(async (file) => ({ name: file.name, bytes: new Uint8Array(await file.arrayBuffer()) })));
      });
      opened.confirm.disabled = true;
      input.addEventListener("change", () => {
        opened.confirm.disabled = !input.files?.length;
      });
      return opened.done;
    },
    save({ origin, title, filename }) {
      const name = element(doc, "input", { type: "text", name: "filename", value: filename });
      const saved = show(
        doc,
        title,
        asking(doc, origin, "сохраняет файл Контур.Плагином."),
        [element(doc, "label", {}, "Имя файла", name), downloadsNote(doc, "Файл сохранится в загрузки браузера.")],
        "Сохранить",
        () => name.value.trim() || undefined,
      );
      name.focus();
      return saved.done;
    },
    folder({ origin, title }) {
      const chosen = show(doc, title, asking(doc, origin, "просит папку для файлов Контур.Плагина."), [downloadsNote(doc, "Файлы, которые сайт запишет в эту папку, сохранятся в загрузки браузера.")], "Выбрать", () => true);
      chosen.confirm.focus();
      return chosen.done.then((value) => value === true);
    },
  };
}

// Saves bytes from the page as a download under the name.
export function pageDownload(doc: Document): (name: string, bytes: Uint8Array) => void {
  return (name, bytes) => {
    const url = URL.createObjectURL(new Blob([bytes as BlobPart]));
    const link = element(doc, "a", { href: url, download: name });
    (doc.body ?? doc.documentElement).append(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 60_000);
  };
}

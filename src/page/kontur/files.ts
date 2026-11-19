// Kontur.Plugin's files (docs/JOURNAL.md, 2026-11-19). The host reads and writes any path for Kontur's own sites and
// hands out paths from its file windows (ui.openFile, ui.saveFile, ui.selectFolder). A page cannot reach the disk, so
// here the windows are the extension's (file-dialog.ts) and their paths stand for what the user chose: a file opened
// is read once, when chosen, and kept for the page; a file saved, or written into a folder chosen, goes to the
// browser's downloads. Any other path is refused as the host refuses one it does not allow ("access denied").
import { KonturError, invalidStructure, pluginError } from "./errors.ts";
import type { FileDialogs } from "./file-dialog.ts";

const isObject = (value: unknown): value is Record<string, unknown> => typeof value === "object" && value !== null && !Array.isArray(value);

export const accessDenied = () => pluginError(16, "access denied");
const fileExists = () => new KonturError({ type: "system", code: 17, context: "open", message: "POSIX[0x00000011]open File exists" });

// The paths' look: a Windows path for a Windows browser, a POSIX one otherwise; the directories are made up, one per
// window, so that two files of one name do not meet.
function roots(platform: string): { root: string; separator: string } {
  return platform === "windows" ? { root: "C:\\Browser\\", separator: "\\" } : { root: "/browser/", separator: "/" };
}

export class FileStore {
  readonly #opened = new Map<string, Uint8Array>();
  readonly #written = new Map<string, Uint8Array>();
  readonly #saveTargets = new Set<string>();
  readonly #folders = new Set<string>();
  readonly #root: string;
  readonly #separator: string;
  readonly #download: (name: string, bytes: Uint8Array) => void;
  #windows = 0;

  constructor(platform: string, download: (name: string, bytes: Uint8Array) => void) {
    ({ root: this.#root, separator: this.#separator } = roots(platform));
    this.#download = download;
  }

  // A new directory for one window's files.
  directory(kind: "opened" | "saved"): string {
    this.#windows += 1;
    return `${this.#root}${kind}-${this.#windows}`;
  }

  join(directory: string, name: string): string {
    return `${directory}${this.#separator}${name}`;
  }

  get separator(): string {
    return this.#separator;
  }

  addOpened(path: string, bytes: Uint8Array): void {
    this.#opened.set(path, bytes);
  }

  addSaveTarget(path: string): void {
    this.#saveTargets.add(path);
  }

  addFolder(path: string): void {
    this.#folders.add(path);
  }

  read(path: string): Uint8Array | undefined {
    return this.#opened.get(path) ?? this.#written.get(path);
  }

  // Writes a file the user chose to save, or one into a folder chosen: to the downloads, under its name.
  write(path: string, bytes: Uint8Array): void {
    if (this.#opened.has(path) || this.#written.has(path)) throw fileExists();
    const cut = path.lastIndexOf(this.#separator);
    const folder = path.slice(0, cut);
    const name = path.slice(cut + 1);
    if (!this.#saveTargets.has(path) && !(this.#folders.has(folder) && name)) throw accessDenied();
    this.#written.set(path, bytes);
    this.#download(name, bytes);
  }
}

// The file windows' options as the host takes them: strings, a boolean, a number, filters as [{name, pattern}];
// anything else is its "invalid command structure".
interface Filter {
  name: string;
  pattern: string;
}

function checkOptions(request: Record<string, unknown>, fields: string[]): void {
  for (const field of fields) {
    const value = request[field];
    if (value === undefined) continue;
    const ok =
      field === "multiple"
        ? typeof value === "boolean"
        : field === "filterIndex"
          ? typeof value === "number"
          : field === "filter"
            ? Array.isArray(value) && value.every((item) => isObject(item) && typeof item.name === "string" && typeof item.pattern === "string")
            : typeof value === "string";
    if (!ok) throw invalidStructure();
  }
}

// "*.txt;*.xml" as the file input's accept list; "*" and "*.*" accept anything.
function accept(filters: Filter[] | undefined): string {
  const patterns = (filters ?? []).flatMap((filter) => filter.pattern.split(/[;,\s]+/)).filter(Boolean);
  if (!patterns.length || patterns.some((pattern) => pattern === "*" || pattern === "*.*")) return "";
  return patterns.map((pattern) => pattern.replace(/^\*/, "")).join(",");
}

export interface FilesContext {
  files: FileStore;
  dialogs: FileDialogs;
  origin: string;
}

// ui.openFile {title?, multiple?, resultFormat?, filter?, filterIndex?, initialDir?}: the path; several as
// "<dir>|<name>|<name>…"; with resultFormat "array" a list of paths; "" when the user cancels.
export async function openFile(context: FilesContext, request: Record<string, unknown>): Promise<unknown> {
  checkOptions(request, ["title", "multiple", "resultFormat", "filter", "filterIndex", "initialDir"]);
  const multiple = request.multiple === true;
  const chosen = await context.dialogs.open({
    origin: context.origin,
    title: (request.title as string | undefined) ?? (multiple ? "Выберите файлы" : "Выберите файл"),
    multiple,
    accept: accept(request.filter as Filter[] | undefined),
  });
  if (!chosen?.length) return "";
  const directory = context.files.directory("opened");
  const paths = chosen.map(({ name, bytes }) => {
    const path = context.files.join(directory, name);
    context.files.addOpened(path, bytes);
    return path;
  });
  if (request.resultFormat === "array") return paths;
  return multiple ? [directory, ...chosen.map(({ name }) => name)].join("|") : paths[0];
}

// ui.saveFile {title?, filename?, filter?, filterIndex?, initialDir?}: the path the site then writes to, "" when the
// user cancels.
export async function saveFile(context: FilesContext, request: Record<string, unknown>): Promise<string> {
  checkOptions(request, ["title", "filename", "filter", "filterIndex", "initialDir"]);
  const name = await context.dialogs.save({ origin: context.origin, title: (request.title as string | undefined) ?? "Сохранить файл как", filename: (request.filename as string | undefined) ?? "" });
  if (!name) return "";
  const path = context.files.join(context.files.directory("saved"), name.split(/[\\/]/).pop()!);
  context.files.addSaveTarget(path);
  return path;
}

// ui.selectFolder {title?, initialDir?}: the folder whose files go to the downloads, "" when the user cancels.
export async function selectFolder(context: FilesContext, request: Record<string, unknown>): Promise<string> {
  checkOptions(request, ["title", "initialDir"]);
  if (!(await context.dialogs.folder({ origin: context.origin, title: (request.title as string | undefined) ?? "Выберите папку" }))) return "";
  const path = context.files.directory("saved");
  context.files.addFolder(path);
  return path;
}

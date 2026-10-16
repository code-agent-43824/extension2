// Firefox on the stand (docs/PLAN.md, action 31): Mozilla's build unpacked by `npm run stand`, driven over WebDriver
// BiDi by this small client on Node's WebSocket, since Playwright drives only Firefox builds of its own. The Rutoken
// adapter for Firefox (signed by AMO, as downloaded) and our dist/firefox build go in as temporary add-ons, ours with
// the stand's host access in its manifest, as standExtension() gives it to Chrome. Pitfalls (docs/JOURNAL.md,
// 2026-10-16): our extension's pages open only with -remote-allow-system-access, and while one of them is open in a
// tab the adapter answers in seconds, so the options page is closed after use.
import { spawn, type ChildProcess } from "node:child_process";
import { cpSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { FIREFOX_ID, firefoxDir } from "../../scripts/build.ts";
import { vendorPath } from "../../scripts/fetch-vendor.ts";
import { stand, standDir } from "../../scripts/setup-stand.ts";

// The internal id Firefox gives our add-on, fixed in the profile so that its pages have a known address.
const EXTENSION_UUID = "6c1f0a52-3d7e-4b8a-9f21-5e4d3c2b1a09";

interface Pending {
  resolve: (result: unknown) => void;
  reject: (error: Error) => void;
}

interface RemoteNode {
  sharedId: string;
}

interface Evaluated {
  type: "success" | "exception";
  result?: { type: string; value?: unknown; sharedId?: string };
  exceptionDetails?: { text: string };
}

class Bidi {
  readonly #socket: WebSocket;
  readonly #pending = new Map<number, Pending>();
  #id = 0;

  constructor(socket: WebSocket) {
    this.#socket = socket;
    socket.addEventListener("message", (event) => {
      const message = JSON.parse(String(event.data)) as { id?: number; type: string; result?: unknown; error?: string; message?: string };
      const pending = message.id === undefined ? undefined : this.#pending.get(message.id);
      if (!pending) return;
      this.#pending.delete(message.id!);
      if (message.type === "error") pending.reject(new Error(`${message.error}: ${message.message}`));
      else pending.resolve(message.result);
    });
  }

  send<T>(method: string, params: object = {}): Promise<T> {
    const id = ++this.#id;
    this.#socket.send(JSON.stringify({ id, method, params }));
    return new Promise<T>((resolve, reject) => this.#pending.set(id, { resolve: resolve as (result: unknown) => void, reject }));
  }

  close(): void {
    this.#socket.close();
  }
}

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

export class FirefoxTab {
  readonly #bidi: Bidi;
  readonly context: string;

  constructor(bidi: Bidi, context: string) {
    this.#bidi = bidi;
    this.context = context;
  }

  async navigate(url: string): Promise<void> {
    await this.#bidi.send("browsingContext.navigate", { context: this.context, url, wait: "complete" });
  }

  async #evaluate(expression: string, ownership: "none" | "root"): Promise<Evaluated["result"]> {
    const evaluated = await this.#bidi.send<Evaluated>("script.evaluate", {
      expression,
      target: { context: this.context },
      awaitPromise: true,
      resultOwnership: ownership,
    });
    if (evaluated.type === "exception") throw new Error(`in the page: ${evaluated.exceptionDetails?.text}`);
    return evaluated.result;
  }

  // The value of `expression` (awaited) in the page, passed through JSON.
  async evaluate<T>(expression: string): Promise<T> {
    const result = await this.#evaluate(`(async () => JSON.stringify(await (${expression})))()`, "none");
    return (typeof result?.value === "string" ? JSON.parse(result.value) : undefined) as T;
  }

  // The first truthy value of `expression`, polled.
  async waitFor<T>(expression: string, timeoutMs = 30_000): Promise<T> {
    const deadline = Date.now() + timeoutMs;
    for (;;) {
      const value = await this.evaluate<T>(expression).catch(() => undefined);
      if (value) return value;
      if (Date.now() > deadline) throw new Error(`timed out waiting for ${expression}`);
      await sleep(200);
    }
  }

  // A click of the user's, which the browser counts as one (permissions.request needs it), on the element
  // `expression` finds.
  async click(expression: string): Promise<void> {
    const node = (await this.#evaluate(`((element) => (element?.scrollIntoView({ block: "center" }), element))(${expression})`, "root")) as RemoteNode | undefined;
    if (!node?.sharedId) throw new Error(`no element: ${expression}`);
    await this.#bidi.send("input.performActions", {
      context: this.context,
      actions: [
        {
          type: "pointer",
          id: "mouse",
          actions: [
            { type: "pointerMove", origin: { type: "element", element: { sharedId: node.sharedId } }, x: 0, y: 0 },
            { type: "pointerDown", button: 0 },
            { type: "pointerUp", button: 0 },
          ],
        },
      ],
    });
  }

  async close(): Promise<void> {
    await this.#bidi.send("browsingContext.close", { context: this.context });
  }
}

export interface LaunchOptions {
  home?: string;
  // Host patterns granted to our extension besides the stand's pages.
  hosts?: string[];
}

export class Firefox {
  readonly #process: ChildProcess;
  readonly #bidi: Bidi;

  private constructor(process: ChildProcess, bidi: Bidi) {
    this.#process = process;
    this.#bidi = bidi;
  }

  static async launch({ home = stand.home, hosts = [] }: LaunchOptions = {}): Promise<Firefox> {
    const extension = join(standDir, "firefox-extension");
    rmSync(extension, { recursive: true, force: true });
    cpSync(firefoxDir, extension, { recursive: true });
    const manifestPath = join(extension, "manifest.json");
    const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
    manifest.host_permissions = ["http://127.0.0.1/*", ...hosts];
    writeFileSync(manifestPath, JSON.stringify(manifest, null, 2));

    const profile = join(standDir, "firefox-profile");
    rmSync(profile, { recursive: true, force: true });
    mkdirSync(profile, { recursive: true });
    const prefs: Record<string, unknown> = {
      // The stand is offline: no proxy, no updates, no first-run pages.
      "network.proxy.type": 0,
      "app.update.disabledForTesting": true,
      "browser.shell.checkDefaultBrowser": false,
      "browser.startup.homepage_override.mstone": "ignore",
      "datareporting.policy.dataSubmissionEnabled": false,
      "toolkit.telemetry.reportingpolicy.firstRun": false,
      // Firefox's own question about site access is browser UI the tests cannot answer: yes, as Chrome's stand has
      // the access in advance.
      "extensions.webextOptionalPermissionPrompts": false,
      "extensions.webextensions.uuids": JSON.stringify({ [FIREFOX_ID]: EXTENSION_UUID }),
    };
    writeFileSync(join(profile, "user.js"), Object.entries(prefs).map(([name, value]) => `user_pref(${JSON.stringify(name)}, ${JSON.stringify(value)});`).join("\n"));

    const child = spawn(stand.firefox, ["--headless", "--no-remote", "-remote-allow-system-access", "--profile", profile, "--remote-debugging-port=0", "about:blank"], {
      env: { ...process.env, HOME: home, MOZ_HEADLESS: "1" },
      stdio: ["ignore", "ignore", "pipe"],
    });
    const url = await new Promise<string>((resolve, reject) => {
      let output = "";
      const timer = setTimeout(() => reject(new Error(`Firefox did not start WebDriver BiDi:\n${output}`)), 30_000);
      child.stderr!.on("data", (chunk) => {
        output += String(chunk);
        const found = /WebDriver BiDi listening on (ws:\/\/[^\s]+)/.exec(output);
        if (found) {
          clearTimeout(timer);
          resolve(found[1]!);
        }
      });
      child.on("exit", (code) => reject(new Error(`Firefox exited with ${code}:\n${output}`)));
    });
    const socket = new WebSocket(`${url.replace(/\/$/, "")}/session`);
    await new Promise((resolve, reject) => {
      socket.addEventListener("open", resolve);
      socket.addEventListener("error", reject);
    });
    const bidi = new Bidi(socket);
    await bidi.send("session.new", { capabilities: {} });
    await bidi.send("webExtension.install", { extensionData: { type: "archivePath", path: vendorPath("rutoken-adapter-firefox") } });
    await bidi.send("webExtension.install", { extensionData: { type: "path", path: extension } });
    return new Firefox(child, bidi);
  }

  extensionUrl(path: string): string {
    return `moz-extension://${EXTENSION_UUID}/${path}`;
  }

  async newTab(url?: string): Promise<FirefoxTab> {
    const { context } = await this.#bidi.send<{ context: string }>("browsingContext.create", { type: "tab" });
    const tab = new FirefoxTab(this.#bidi, context);
    if (url) await tab.navigate(url);
    return tab;
  }

  // A window the extension opens itself (its questions to the user), once it has loaded `url`'s page.
  async windowAt(url: string, timeoutMs = 30_000): Promise<FirefoxTab> {
    const deadline = Date.now() + timeoutMs;
    for (;;) {
      const { contexts } = await this.#bidi.send<{ contexts: { context: string; url: string }[] }>("browsingContext.getTree", { maxDepth: 0 });
      const found = contexts.find((context) => context.url.startsWith(url));
      if (found) {
        const tab = new FirefoxTab(this.#bidi, found.context);
        await tab.waitFor(`document.readyState === "complete"`);
        return tab;
      }
      if (Date.now() > deadline) throw new Error(`no window at ${url}`);
      await sleep(200);
    }
  }

  async close(): Promise<void> {
    this.#bidi.close();
    this.#process.kill();
    await new Promise((resolve) => (this.#process.exitCode !== null ? resolve(undefined) : this.#process.once("exit", resolve)));
  }
}

// Turns the extension on for `site` the way a user does on the options page, then closes it.
export async function enableSite(firefox: Firefox, site: string): Promise<void> {
  const options = await firefox.newTab(firefox.extensionUrl("options.html"));
  await options.evaluate(`document.querySelector("input[name=site]").value = ${JSON.stringify(site)}`);
  await options.click(`document.querySelector("#add button[type=submit]")`);
  const origin = new URL(site).origin;
  await options.waitFor(`[...document.querySelectorAll("#sites li")].some((item) => item.textContent.includes(${JSON.stringify(origin)}))`, 10_000);
  await options.close();
}

// Our PIN window, in an open shadow root.
export const pinDialog = `document.querySelector("#rutoken-cades-bridge-pin")?.shadowRoot?.querySelector("[role=dialog]")`;

export async function enterPin(tab: FirefoxTab, pin: string): Promise<void> {
  await tab.waitFor(`${pinDialog}?.querySelector("input[name=pin]")`);
  await tab.evaluate(`(() => { (${pinDialog}).querySelector("input[name=pin]").value = ${JSON.stringify(pin)}; return true; })()`);
  await tab.click(`(${pinDialog}).querySelector("button[name=confirm]")`);
}

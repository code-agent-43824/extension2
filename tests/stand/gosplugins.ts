// Talks to the real Gosuslugi plug-in cores that scripts/setup-gosplugins.ts unpacked, over Native Messaging as their
// extensions do: a little-endian length, then JSON. Answers are decoded as Chrome decodes them, invalid UTF-8 replaced
// by U+FFFD (Gosplugin's core writes raw CKA_ID bytes into its JSON). Gosplugin's core asks for the PIN in its own Qt
// window, on the X display the stand starts (Xvfb), into which typePin types.
import { execFileSync, spawn, spawnSync, type ChildProcess } from "node:child_process";
import { randomUUID } from "node:crypto";
import { gosplugins } from "../../scripts/setup-gosplugins.ts";

export interface NativeHost {
  ask(message: unknown, timeoutMs?: number): Promise<any>;
  close(): void;
}

function nativeHost(command: string, args: string[], env: NodeJS.ProcessEnv): NativeHost {
  const child: ChildProcess = spawn(command, args, { env, stdio: ["pipe", "pipe", "ignore"] });
  let buffer = Buffer.alloc(0);
  const waiting: ((value: any) => void)[] = [];
  child.stdout!.on("data", (chunk: Buffer) => {
    buffer = Buffer.concat([buffer, chunk]);
    while (buffer.length >= 4 && buffer.length >= 4 + buffer.readUInt32LE(0)) {
      const length = buffer.readUInt32LE(0);
      const text = new TextDecoder().decode(buffer.subarray(4, 4 + length));
      buffer = buffer.subarray(4 + length);
      waiting.shift()?.(JSON.parse(text));
    }
  });
  return {
    ask(message, timeoutMs = 60_000) {
      const body = Buffer.from(JSON.stringify(message));
      const header = Buffer.alloc(4);
      header.writeUInt32LE(body.length);
      return new Promise((resolve, reject) => {
        const timer = setTimeout(() => reject(new Error(`no answer to ${JSON.stringify(message).slice(0, 120)}`)), timeoutMs);
        waiting.push((value) => {
          clearTimeout(timer);
          resolve(value);
        });
        child.stdin!.write(Buffer.concat([header, body]));
      });
    },
    close() {
      child.stdin!.end();
      child.kill();
    },
  };
}

export function ifcHost(): NativeHost {
  return nativeHost(gosplugins.ifc.host, [], { ...process.env, HOME: gosplugins.home, LD_LIBRARY_PATH: gosplugins.ifc.lib });
}

export const display = ":99";

// The X display Gosplugin's core shows its PIN window on.
export function startDisplay(): void {
  if (spawnSync("xdpyinfo", ["-display", display]).status === 0) return;
  spawn("Xvfb", [display, "-screen", "0", "1280x800x24"], { detached: true, stdio: "ignore" }).unref();
  for (let i = 0; i < 50 && spawnSync("xdpyinfo", ["-display", display]).status !== 0; i++) execFileSync("sleep", ["0.1"]);
}

export function gosHost(): NativeHost {
  startDisplay();
  const root = gosplugins.gos.root;
  return nativeHost(gosplugins.gos.binary, ["chrome-extension://jabjbhgjaidecageckilhonbggakppme/"], {
    ...process.env,
    HOME: gosplugins.home,
    // A desktop's UTF-8 locale: under C the core fails on a certificate label in Cyrillic (boost's codecvt).
    LANG: "C.UTF-8",
    DISPLAY: display,
    QT_PLUGIN_PATH: `${root}/plugins`,
    LD_LIBRARY_PATH: `${root}/bin:${root}/lib`,
  });
}

// A Gosplugin message as its crypto.js and content script send it on to the core.
export function gosMessage(module: string, method: string, data = ""): Record<string, unknown> {
  return {
    id: randomUUID(),
    node: "1998854141",
    error: "",
    mode: "",
    module: { type: module, version: "0.0.0.0" },
    method: { type: method, data, result: "" },
    meta: {
      format: { type: "message", version: "0.0.0.0", category: "gosuslugi.plugin" },
      content: { type: "application/json", charset: "utf8", transferEncoding: "" },
      routes: [{ node: `gosuslugi.plugin.extension.${module}`, time: new Date().toLocaleString("en-US"), transfer: "" }],
      data: {},
      userAgent: "Mozilla/5.0 (X11; Linux x86_64) Chrome/153.0.0.0 Safari/537.36",
      protocol: { category: "protocol", type: "nmh", description: "chrome.gosuslugi.plugin", version: "" },
    },
  };
}

// Types the PIN into the core's PIN window once it shows (and ticks "remember" when asked), or presses Escape. Qt
// ignores synthetic key events sent to a window, so the window gets the focus (there is no window manager on the
// display) and the keys go through XTEST.
export function typePin(pin: string | undefined, { remember = false, timeoutMs = 30_000 } = {}): void {
  const env = { ...process.env, DISPLAY: display };
  const deadline = Date.now() + timeoutMs;
  let window = "";
  while (!window && Date.now() < deadline) {
    window = spawnSync("xdotool", ["search", "--onlyvisible", "--name", "."], { env, encoding: "utf8" }).stdout.trim().split("\n").filter(Boolean).pop() ?? "";
    if (!window) execFileSync("sleep", ["0.2"]);
  }
  if (!window) throw new Error("the core's PIN window did not show");
  execFileSync("sleep", ["0.5"]);
  execFileSync("xdotool", ["windowfocus", "--sync", window], { env });
  if (pin === undefined) {
    execFileSync("xdotool", ["key", "Escape"], { env });
    return;
  }
  execFileSync("xdotool", ["type", "--delay", "30", pin], { env });
  if (remember) execFileSync("xdotool", ["key", "Tab", "space"], { env });
  execFileSync("xdotool", ["key", "Return"], { env });
}

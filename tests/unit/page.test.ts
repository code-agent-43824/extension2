import { existsSync, readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { vendorPath } from "../../scripts/fetch-vendor.ts";
import { constantsFile, extractConstants, generateConstants } from "../../scripts/gen-constants.ts";
import { createCadesplugin, LOAD_TIMEOUT, PLUGIN_UNAVAILABLE } from "../../src/page/cadesplugin.ts";
import { CadesError, getLastError } from "../../src/page/errors.ts";
import { createObject } from "../../src/page/objects/index.ts";
import { CadesVersion } from "../../src/page/objects/version.ts";
import { ADAPTER_KEY, loadRutokenPlugin, type Clock, type RutokenPlugin } from "../../src/page/rutoken.ts";
import { asyncSpawn } from "../../src/page/spawn.ts";

// A clock whose timers fire only when the test advances it.
class FakeClock implements Clock {
  time = 0;
  timers: { at: number; callback: () => void }[] = [];
  setTimeout(callback: () => void, ms: number) {
    this.timers.push({ at: this.time + ms, callback });
  }
  now() {
    return this.time;
  }
  async advance(ms: number) {
    const end = this.time + ms;
    for (;;) {
      await new Promise((resolve) => setImmediate(resolve));
      this.timers.sort((a, b) => a.at - b.at);
      const next = this.timers[0];
      if (!next || next.at > end) break;
      this.timers.shift();
      this.time = next.at;
      next.callback();
    }
    this.time = end;
    await new Promise((resolve) => setImmediate(resolve));
  }
}

// Only what About and the loader touch.
const plugin = { version: Promise.resolve("4.12.3.0") } as unknown as RutokenPlugin;

function adapter(overrides: Record<string, unknown> = {}) {
  return {
    initialize: async () => {},
    isPluginInstalled: async () => true,
    loadPlugin: async () => plugin,
    ...overrides,
  };
}

// Just enough of window for createCadesplugin: callbacks, message events, a parsed document.
function fakeWindow(extra: Record<string, unknown> = {}) {
  const listeners: ((event: { data: unknown; source: unknown }) => void)[] = [];
  const win: Record<string, unknown> = {
    document: { readyState: "complete", addEventListener() {} },
    addEventListener: (_type: string, listener: (typeof listeners)[number]) => listeners.push(listener),
    postMessage: (data: unknown) => setImmediate(() => listeners.forEach((listener) => listener({ data, source: win }))),
    ...extra,
  };
  return win;
}

describe("constants", () => {
  it.skipIf(!existsSync(vendorPath("cryptopro-cadesplugin_api-js")))("match cadesplugin_api.js", () => {
    expect(readFileSync(constantsFile, "utf8")).toBe(generateConstants());
  });

  it("keep the last value of a name assigned twice", () => {
    const source = "function set_constantValues() {\n  cadesplugin.A = 1;\n\n  cadesplugin.B = \"x\";\n  cadesplugin.A = 0x10;\n    }";
    expect([...extractConstants(source)]).toEqual([["A", 16], ["B", "x"]]);
  });
});

describe("async_spawn", () => {
  it("feeds resolved values back and rethrows rejections into the generator", async () => {
    const result = await asyncSpawn(function* (args) {
      const a = (yield Promise.resolve(2)) as number;
      try {
        yield Promise.reject(new Error("boom"));
      } catch (err) {
        return [args, a, (err as Error).message];
      }
    }, "arg");
    expect(result).toEqual([["arg"], 2, "boom"]);
  });
});

describe("getLastError", () => {
  it("formats like cadesplugin_api.js", () => {
    expect(getLastError(new CadesError("Нет объекта", 0x80040154))).toBe("Нет объекта (0x80040154)");
    expect(getLastError(new CadesError("Нет объекта", -2147221164))).toBe("Нет объекта (0x80040154)");
    expect(getLastError(new Error("просто текст"))).toBe("просто текст");
    expect(getLastError("строка")).toBe("строка");
  });
});

describe("CAdESCOM objects", () => {
  it("version members are promises", async () => {
    const version = new CadesVersion("2.0.15000");
    expect([await version.MajorVersion, await version.MinorVersion, await version.BuildVersion]).toEqual([2, 0, 15000]);
    expect(await version.toString()).toBe("2.0.15000");
  });

  it("About reports the compatibility versions and names the Rutoken Plugin", async () => {
    const about = createObject("CADESCOM.ABOUT", { plugin }) as import("../../src/page/objects/about.ts").About;
    expect(await (await about.PluginVersion).toString()).toBe("2.0.15000");
    const csp = await about.CSPVersion("", 80);
    expect(`${await csp.MajorVersion}.${await csp.MinorVersion}.${await csp.BuildVersion}`).toBe("5.0.13000");
    expect(await about.CSPName(80)).toBe("Rutoken Plugin 4.12.3.0");
  });

  it("unknown objects fail with a class-not-registered error", () => {
    expect(() => createObject("CAdESCOM.CPLicense", { plugin })).toThrow(CadesError);
  });
});

describe("loadRutokenPlugin", () => {
  it("waits for the adapter object and initialises it", async () => {
    const clock = new FakeClock();
    const win: Record<string, unknown> = {};
    let initialized = 0;
    const loading = loadRutokenPlugin(win, 3000, clock);
    await clock.advance(500);
    // Like the real adapter: loadPlugin appears only after initialize().
    const late: Record<string, unknown> = adapter({ loadPlugin: undefined });
    late.initialize = async () => {
      initialized++;
      late.loadPlugin = async () => plugin;
    };
    win[ADAPTER_KEY] = late;
    await clock.advance(100);
    expect(await loading).toBe(plugin);
    expect(initialized).toBe(1);
  });

  it("does not initialise twice when the site already did", async () => {
    const clock = new FakeClock();
    const win: Record<string, unknown> = {
      [ADAPTER_KEY]: adapter({
        initializePromise: {},
        initialize: () => Promise.reject(new Error("initialise has already been called")),
        loadPlugin: undefined,
      }),
    };
    const loading = loadRutokenPlugin(win, 3000, clock);
    await clock.advance(200);
    (win[ADAPTER_KEY] as Record<string, unknown>).loadPlugin = async () => plugin;
    await clock.advance(100);
    expect(await loading).toBe(plugin);
  });

  it("gives up when no adapter appears", async () => {
    const clock = new FakeClock();
    const loading = loadRutokenPlugin({}, 3000, clock);
    const failed = expect(loading).rejects.toThrow("Адаптер Рутокен Плагин");
    await clock.advance(3100);
    await failed;
  });

  it("fails when the Rutoken Plugin is not installed", async () => {
    const win = { [ADAPTER_KEY]: adapter({ isPluginInstalled: async () => false }) };
    await expect(loadRutokenPlugin(win, 3000, new FakeClock())).rejects.toThrow("не установлен");
  });
});

describe("window.cadesplugin", () => {
  it("calls the site callbacks in CryptoPro's order and resolves", async () => {
    const calls: string[] = [];
    const win = fakeWindow({
      [ADAPTER_KEY]: adapter(),
      cadesplugin_extension_loaded_callback: () => calls.push("extension"),
      cadesplugin_plugin_loaded_callback: () => calls.push("plugin"),
    });
    const clock = new FakeClock();
    const cadesplugin = createCadesplugin(win as never, clock);
    expect(cadesplugin.LOG_LEVEL_DEBUG).toBe(4);
    expect(cadesplugin.CADESCOM_CADES_BES).toBe(1);
    await clock.advance(1);
    await expect(cadesplugin).resolves.toBeUndefined();
    expect(calls).toEqual(["extension", "plugin"]);
    const about = (await (cadesplugin.CreateObjectAsync as (name: string) => Promise<unknown>)("CAdESCOM.About")) as {
      CSPName(): Promise<string>;
    };
    expect(await about.CSPName()).toBe("Rutoken Plugin 4.12.3.0");
  });

  it("rejects with CryptoPro's text when the Rutoken adapter is missing", async () => {
    const clock = new FakeClock();
    const cadesplugin = createCadesplugin(fakeWindow() as never, clock);
    const rejected = expect(cadesplugin).rejects.toBe(PLUGIN_UNAVAILABLE);
    await clock.advance(3100);
    await rejected;
    await expect((cadesplugin.CreateObjectAsync as (name: string) => Promise<unknown>)("CAdESCOM.About")).rejects.toThrow(
      PLUGIN_UNAVAILABLE,
    );
  });

  it("times out like CryptoPro when the plugin never loads", async () => {
    let timedOut = false;
    const win = fakeWindow({
      [ADAPTER_KEY]: adapter({ loadPlugin: () => new Promise(() => {}) }),
      cadesplugin_load_timeout: 5000,
      cadesplugin_timeout_failed_callback: () => (timedOut = true),
    });
    const clock = new FakeClock();
    const cadesplugin = createCadesplugin(win as never, clock);
    const rejected = expect(cadesplugin).rejects.toBe(LOAD_TIMEOUT);
    await clock.advance(5001);
    await rejected;
    expect(timedOut).toBe(true);
  });

  it("answers the extension version request over postMessage", async () => {
    const win = fakeWindow({ [ADAPTER_KEY]: adapter() });
    const cadesplugin = createCadesplugin(win as never, new FakeClock());
    const version = await new Promise((resolve) => (cadesplugin.get_extension_version as (cb: unknown) => void)(resolve));
    expect(version).toBe("0.0.0-test");
  });
});

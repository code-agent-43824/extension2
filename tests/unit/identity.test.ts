/// <reference types="chrome" />
// The made-up user, computer and network of Gosplugin's answers (src/extension/identity.ts, src/page/identity.ts).
import { describe, expect, it } from "vitest";
import { GENERATOR_URL, identity, IDENTITY_KEY, newIdentity, storedIdentity } from "../../src/extension/identity.ts";
import { BUILT_IN_IDENTITIES, builtInIdentity, ipConfig } from "../../src/page/identity.ts";

function fakeStorage() {
  const store: Record<string, unknown> = {};
  const api = {
    storage: {
      local: {
        get: async (key: string) => (key in store ? { [key]: store[key] } : {}),
        set: async (items: Record<string, unknown>) => void Object.assign(store, items),
      },
    },
  } as unknown as typeof chrome;
  return { api, store };
}

const generator = (body: unknown, status = 200) => {
  const asked: string[] = [];
  const fetcher = async (input: string) => {
    asked.push(input);
    return new Response(JSON.stringify(body), { status });
  };
  return { fetcher, asked };
};

describe("the made-up identity", () => {
  it("takes the generator's user name, address and MAC, and makes a Windows computer name of its UUID", async () => {
    const { api, store } = fakeStorage();
    const { fetcher, asked } = generator({ status: "OK", data: [{ user: "sbragin", ip: "172.29.158.60", mac: "DB:E3:00:62:99:24", uuid: "7c9d028e-e00f-30d6-904d-e99c4a6c7e2c" }] });
    const made = await newIdentity(api, fetcher, "Win32");
    expect(asked).toEqual([GENERATOR_URL]);
    // The MAC made unicast and globally unique (the first byte's two low bits cleared).
    expect(made).toEqual({ user: "sbragin", computer: "DESKTOP-7C9D028", ip: "172.29.158.60", mac: "D8:E3:00:62:99:24", source: "fakerapi.it" });
    expect(store[IDENTITY_KEY]).toEqual(made);
    expect((await newIdentity(api, fetcher, "Linux x86_64")).computer).toBe("sbragin-pc");
  });

  it("takes the built-in ones in turn when the generator does not answer", async () => {
    const { api } = fakeStorage();
    const failing = async () => {
      throw new TypeError("Failed to fetch");
    };
    const sources = [];
    for (let i = 0; i < 4; i++) sources.push((await newIdentity(api, failing, "Win32")).source);
    expect(sources).toEqual(["built-in 1", "built-in 2", "built-in 3", "built-in 1"]);
    expect((await newIdentity(api, generator({ data: [] }).fetcher)).source).toBe("built-in 2");
    expect((await newIdentity(api, generator({}, 500).fetcher)).user).toBe(BUILT_IN_IDENTITIES[2]!.user);
  });

  it("names a built-in identity's computer as a generated one's: DESKTOP-… only on Windows", async () => {
    const computer = async (platform: string) => {
      const { api } = fakeStorage();
      return (await newIdentity(api, generator({}, 500).fetcher, platform)).computer;
    };
    expect(await computer("Win32")).toBe("DESKTOP-4K7QF2M");
    expect(await computer("Linux x86_64")).toBe("asmirnov-pc");
    expect(await computer("MacIntel")).toBe("asmirnov-pc");
    expect([builtInIdentity(1, "Linux x86_64").computer, builtInIdentity(2, "Win32").computer]).toEqual(["ekaterina-pc", "DESKTOP-R61TN0C"]);
  });

  it("is made once and kept", async () => {
    const { api } = fakeStorage();
    const { fetcher, asked } = generator({ data: [{ user: "u", ip: "10.1.2.3", mac: "00:11:22:33:44:55", uuid: "abc" }] });
    const [first, second] = await Promise.all([identity(api, fetcher), identity(api, fetcher)]);
    expect(first).toEqual(second);
    expect(await identity(api, fetcher)).toEqual(first);
    expect(asked).toHaveLength(1);
    expect(await storedIdentity(api)).toEqual(first);
  });

  it("names the network adapters as Qt does on each platform", () => {
    const names = (platform: string) => (ipConfig(BUILT_IN_IDENTITIES[1]!, platform) as { name: string; humanReadableName: string }[]).map((entry) => `${entry.name}/${entry.humanReadableName}`);
    expect(names("Win32")).toEqual(["ethernet_32769/Ethernet", "loopback_0/Loopback Pseudo-Interface 1"]);
    expect(names("MacIntel")).toEqual(["lo0/lo0", "en0/en0"]);
    expect(names("Linux x86_64")).toEqual(["enp3s0/enp3s0", "lo/lo"]);
  });
});

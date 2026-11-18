// The user, computer and network Gosplugin's core would tell a site (meta.userAgent of its answers and system.ipConfig),
// made up: the owner, 2026-11-17, «имя пользователя компьютера и сетевой интерфейс выдаем рандомно-фейковый». The
// extension gets them once from a generator on the internet (src/extension/identity.ts), or, when it does not answer,
// takes the next of three built-in ones, and keeps them; page.js asks the bridge for them (IDENTITY_REQUEST).
import type { Clock } from "./rutoken.ts";

export const IDENTITY_REQUEST = "cryptopro-via-rutoken:identity-request";
export const IDENTITY_RESPONSE = "cryptopro-via-rutoken:identity";

export interface FakeIdentity {
  user: string;
  computer: string;
  // A local IPv4 address of the one network adapter, and its MAC address.
  ip: string;
  mac: string;
}

// The built-in ones, taken in turn when the generator does not answer, with the computer's name as on Windows;
// builtInIdentity names it for the system the browser runs on.
export const BUILT_IN_IDENTITIES: readonly FakeIdentity[] = [
  { user: "a.smirnov", computer: "DESKTOP-4K7QF2M", ip: "192.168.1.37", mac: "3C:52:82:A1:6E:08" },
  { user: "ekaterina", computer: "DESKTOP-9H2LX8D", ip: "192.168.0.104", mac: "F4:6D:04:3B:C2:7A" },
  { user: "ivanovpa", computer: "DESKTOP-R61TN0C", ip: "10.0.0.23", mac: "D8:BB:C1:52:0F:E4" },
];

export const isWindows = (platform: string) => /^Win/i.test(platform);

// A computer's name on a system other than Windows, made of the user's (docs/JOURNAL.md, 2026-11-17).
export function otherComputerName(user: string): string {
  return `${user.replace(/[^a-z0-9-]/gi, "").toLowerCase() || "user"}-pc`;
}

// The built-in identity of this number for the platform: "DESKTOP-…" only on Windows, as a generated one.
export function builtInIdentity(index: number, platform: string): FakeIdentity {
  const identity = BUILT_IN_IDENTITIES[index % BUILT_IN_IDENTITIES.length]!;
  return isWindows(platform) ? identity : { ...identity, computer: otherComputerName(identity.user) };
}

export interface IdentityRequest {
  type: typeof IDENTITY_REQUEST;
  id: string;
}

export interface IdentityResponse {
  type: typeof IDENTITY_RESPONSE;
  id: string;
  identity?: FakeIdentity;
}

export function validIdentity(value: unknown): FakeIdentity | undefined {
  const candidate = value as Partial<FakeIdentity> | null;
  const text = (field: unknown) => typeof field === "string" && field.length > 0 && field.length < 64;
  if (!candidate || !text(candidate.user) || !text(candidate.computer)) return undefined;
  if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(String(candidate.ip)) || !/^([0-9A-F]{2}:){5}[0-9A-F]{2}$/.test(String(candidate.mac))) return undefined;
  return { user: candidate.user!, computer: candidate.computer!, ip: candidate.ip!, mac: candidate.mac! };
}

// The generator answers slowly at worst; the bridge falls back itself.
const WAIT_MS = 15000;
let requests = 0;

export function pageIdentity(win: Window, clock: Clock, waitMs = WAIT_MS): Promise<FakeIdentity> {
  const id = `identity-${clock.now()}-${++requests}`;
  return new Promise((resolve) => {
    let done = false;
    const finish = (identity: FakeIdentity) => {
      if (done) return;
      done = true;
      win.removeEventListener("message", listener);
      resolve(identity);
    };
    const listener = (event: MessageEvent) => {
      const data = event.data as Partial<IdentityResponse> | null;
      if (event.source !== win || data?.type !== IDENTITY_RESPONSE || data.id !== id) return;
      finish(validIdentity(data.identity) ?? builtInIdentity(0, win.navigator.platform));
    };
    win.addEventListener("message", listener);
    clock.setTimeout(() => finish(builtInIdentity(0, win.navigator.platform)), waitMs);
    win.postMessage({ type: IDENTITY_REQUEST, id } satisfies IdentityRequest, "*");
  });
}

const falseTrue = (value: boolean) => (value ? "true" : "false");

function address(text: string, loopback = false) {
  return { loopback: falseTrue(loopback), multicast: "false", scopeId: "", address: text };
}

function networkInterface(name: string, humanReadableName: string, hardwareAddress: string, ip: string, netmask: string, loopBack = false) {
  const broadcast = ip
    .split(".")
    .map((part, index) => Number(part) | (~Number(netmask.split(".")[index]) & 0xff))
    .join(".");
  return {
    valid: "true",
    up: "true",
    running: "true",
    loopBack: falseTrue(loopBack),
    pointToPoint: "false",
    name,
    humanReadableName,
    hardwareAddress,
    networkAddressEntries: [{ ip: address(ip, loopBack), netmask: address(netmask), broadcast: address(broadcast, loopBack) }],
  };
}

// system.ipConfig's answer: the adapter and the loopback, named as Qt names them on the platform.
export function ipConfig(identity: FakeIdentity, platform: string): unknown[] {
  if (/^Win/i.test(platform)) {
    return [
      networkInterface("ethernet_32769", "Ethernet", identity.mac, identity.ip, "255.255.255.0"),
      networkInterface("loopback_0", "Loopback Pseudo-Interface 1", "", "127.0.0.1", "255.0.0.0", true),
    ];
  }
  if (/^Mac/i.test(platform)) {
    return [networkInterface("lo0", "lo0", "", "127.0.0.1", "255.0.0.0", true), networkInterface("en0", "en0", identity.mac, identity.ip, "255.255.255.0")];
  }
  return [networkInterface("enp3s0", "enp3s0", identity.mac, identity.ip, "255.255.255.0"), networkInterface("lo", "lo", "00:00:00:00:00:00", "127.0.0.1", "255.0.0.0", true)];
}

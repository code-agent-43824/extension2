// The made-up user, computer and network the extension tells sites as Gosplugin (src/page/identity.ts): from the
// fakerapi.it generator (a Russian user name, a local IPv4 address, a MAC address, and a UUID the computer's name is
// made of), asked once and kept in chrome.storage.local; when it does not answer, the next of three built-in ones. The
// options page shows them and makes new ones.
import { BUILT_IN_IDENTITIES, validIdentity, type FakeIdentity } from "../page/identity.ts";

type Api = typeof chrome;
type Fetch = (input: string, init?: RequestInit) => Promise<Response>;

export const IDENTITY_KEY = "fakeIdentity";
// The built-in identity to take next.
export const IDENTITY_FALLBACK_KEY = "fakeIdentityFallback";
export const IDENTITY_MESSAGE = "cryptopro-via-rutoken:identity";
export const GENERATOR_URL = "https://fakerapi.it/api/v2/custom?_quantity=1&_locale=ru_RU&user=userName&ip=localIpv4&mac=macAddress&uuid=uuid";
const GENERATOR_WAIT_MS = 8000;

export interface StoredIdentity extends FakeIdentity {
  // Where it came from: the generator, or the built-in one of this number.
  source: string;
}

// A computer's name as Windows makes it, from the generator's UUID.
function computerName(uuid: string, user: string, platform: string): string {
  if (!/^Win/i.test(platform)) return `${user.replace(/[^a-z0-9-]/gi, "").toLowerCase() || "user"}-pc`;
  const letters = uuid.replace(/[^0-9a-z]/gi, "").toUpperCase();
  return `DESKTOP-${letters.slice(0, 7).padEnd(7, "0")}`;
}

// The generator's MAC address as a network adapter's: unicast and globally unique.
function adapterMac(mac: string): string {
  const parts = mac.toUpperCase().split(":");
  parts[0] = (parseInt(parts[0]!, 16) & 0xfc).toString(16).toUpperCase().padStart(2, "0");
  return parts.join(":");
}

async function fromGenerator(fetcher: Fetch, platform: string): Promise<FakeIdentity | undefined> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), GENERATOR_WAIT_MS);
  try {
    const response = await fetcher(GENERATOR_URL, { signal: controller.signal, credentials: "omit", cache: "no-store" });
    if (!response.ok) return undefined;
    const [data] = ((await response.json()) as { data?: { user?: string; ip?: string; mac?: string; uuid?: string }[] }).data ?? [];
    if (!data?.user || !data.ip || !data.mac || !data.uuid) return undefined;
    return validIdentity({ user: data.user, computer: computerName(data.uuid, data.user, platform), ip: data.ip, mac: adapterMac(data.mac) });
  } catch {
    return undefined;
  } finally {
    clearTimeout(timer);
  }
}

// Makes and keeps a new identity.
export async function newIdentity(api: Api = chrome, fetcher: Fetch = (input, init) => fetch(input, init), platform = globalThis.navigator?.platform ?? ""): Promise<StoredIdentity> {
  const generated = await fromGenerator(fetcher, platform);
  let identity: StoredIdentity;
  if (generated) {
    identity = { ...generated, source: "fakerapi.it" };
  } else {
    const index = Number((await api.storage.local.get(IDENTITY_FALLBACK_KEY))[IDENTITY_FALLBACK_KEY] ?? 0) % BUILT_IN_IDENTITIES.length;
    identity = { ...BUILT_IN_IDENTITIES[index]!, source: `built-in ${index + 1}` };
    await api.storage.local.set({ [IDENTITY_FALLBACK_KEY]: (index + 1) % BUILT_IN_IDENTITIES.length });
  }
  await api.storage.local.set({ [IDENTITY_KEY]: identity });
  return identity;
}

export async function storedIdentity(api: Api = chrome): Promise<StoredIdentity | undefined> {
  const stored = (await api.storage.local.get(IDENTITY_KEY))[IDENTITY_KEY] as Partial<StoredIdentity> | undefined;
  const valid = validIdentity(stored);
  return valid ? { ...valid, source: String(stored?.source ?? "") } : undefined;
}

// The kept identity, made on first need. Calls in flight share one generator request.
let pending: Promise<StoredIdentity> | undefined;
export function identity(api: Api = chrome, fetcher?: Fetch): Promise<StoredIdentity> {
  pending ??= storedIdentity(api)
    .then((stored) => stored ?? newIdentity(api, fetcher))
    .finally(() => {
      pending = undefined;
    });
  return pending;
}

/// <reference types="chrome" />
// XAdES-T's timestamp (docs/PLAN.md, action 26): the RFC 3161 request and the checks of the answer (src/page/tsp.ts),
// page.js asking the bridge (src/page/timestamps.ts), and the service worker asking the user for access to the
// service and posting the request (src/extension/timestamps.ts).
import { describe, expect, it } from "vitest";
import { STORAGE_KEY } from "../../src/extension/sites.ts";
import { Timestamps, TSA_KEY, tsaServices } from "../../src/extension/timestamps.ts";
import { children, decodeOid, encode, encodeOid, read } from "../../src/page/asn1.ts";
import type { Clock } from "../../src/page/rutoken.ts";
import { timestampAccess, timestampResponse, TSA_ACCESS_REQUEST, TSA_ACCESS_RESPONSE, TSA_REQUEST, TSA_RESPONSE } from "../../src/page/timestamps.ts";
import { timestampRequest, timestampToken, type TimestampRequest } from "../../src/page/tsp.ts";

const E_INVALIDARG = 0x80070057;
const E_ACCESSDENIED = 0x80070005;
const E_FAIL = 0x80004005;
const ERROR_CANCELLED = 0x800704c7;
const STREEBOG_256 = "1.2.643.7.1.1.2.2";

const hashed = Uint8Array.from({ length: 32 }, (_, i) => i);
const seq = (...parts: Uint8Array[]) => encode(0x30, ...parts);
const integer = (...bytes: number[]) => encode(0x02, Uint8Array.from(bytes));
const oid = (dotted: string) => encode(0x06, encodeOid(dotted));
const octets = (bytes: Uint8Array) => encode(0x04, bytes);

// A TimeStampResp as a service gives it: the status, and a token whose TSTInfo has the imprint and nonce given.
function response(request: TimestampRequest, options: { status?: number; text?: string; hashed?: Uint8Array; nonce?: Uint8Array; token?: boolean } = {}) {
  const tstInfo = seq(
    integer(1),
    oid("2.999.1"),
    seq(seq(oid(request.hashOid)), octets(options.hashed ?? request.hashed)),
    integer(0x2a),
    encode(0x18, new TextEncoder().encode("20261008120000Z")),
    // accuracy and ordering come before the nonce.
    seq(integer(1)),
    encode(0x01, Uint8Array.of(0)),
    encode(0x02, options.nonce ?? request.nonce),
  );
  const signedData = seq(
    integer(3),
    encode(0x31, seq(oid(STREEBOG_256))),
    seq(oid("1.2.840.113549.1.9.16.1.4"), encode(0xa0, octets(tstInfo))),
    encode(0x31),
  );
  const token = seq(oid("1.2.840.113549.1.7.2"), encode(0xa0, signedData));
  const status = seq(integer(options.status ?? 0), ...(options.text ? [seq(encode(0x0c, new TextEncoder().encode(options.text)))] : []));
  return { der: options.token === false ? seq(status) : seq(status, token), token };
}

describe("the RFC 3161 request", () => {
  it("names the hash, asks for the service's certificate and carries a positive nonce", () => {
    const request = timestampRequest("streebog256", hashed, Uint8Array.of(0, 0, 0x9a, 1, 2, 3, 4, 5));
    const [version, imprint, nonce, certReq] = children(read(request.der));
    expect(version!.value).toEqual(Uint8Array.of(1));
    const [algorithm, value] = children(imprint!);
    expect(decodeOid(children(algorithm!)[0]!.value)).toBe(STREEBOG_256);
    expect(value!.value).toEqual(hashed);
    // Leading zeros dropped, and a zero put back in front of a high bit.
    expect(nonce!.value).toEqual(Uint8Array.of(0, 0x9a, 1, 2, 3, 4, 5));
    expect([certReq!.tag, certReq!.value[0]]).toEqual([0x01, 0xff]);
    expect(timestampRequest("streebog512", new Uint8Array(64), Uint8Array.of(1)).hashOid).toBe("1.2.643.7.1.1.2.3");
  });

  it("takes the token of an answer with the request's imprint and nonce, and refuses any other answer", () => {
    const request = timestampRequest("streebog256", hashed, Uint8Array.of(0x11, 0x22, 0x33));
    const granted = response(request);
    expect(timestampToken(granted.der, request)).toEqual(granted.token);
    expect(timestampToken(response(request, { status: 1 }).der, request)).toEqual(granted.token);
    expect(() => timestampToken(response(request, { status: 2, text: "unknown hash" }).der, request)).toThrow("служба отказала, статус 2: unknown hash");
    expect(() => timestampToken(response(request, { token: false }).der, request)).toThrow("нет штампа");
    expect(() => timestampToken(response(request, { hashed: new Uint8Array(32) }).der, request)).toThrow("на другие данные");
    expect(() => timestampToken(response(request, { nonce: Uint8Array.of(0x11, 0x22, 0x34) }).der, request)).toThrow("nonce");
    expect(() => timestampToken(new TextEncoder().encode("<html>busy</html>"), request)).toThrow("не разобран");
  });
});

function fakeWindow() {
  const target = new EventTarget();
  const win = Object.assign(target, {
    postMessage(data: unknown) {
      setTimeout(() => target.dispatchEvent(Object.assign(new Event("message"), { data, source: win })));
    },
  });
  return win as unknown as Window;
}

const clock: Clock = { setTimeout: () => undefined, now: () => 0 };

describe("page.js asking the extension", () => {
  it("gets access and the service's answer to its own request, or the extension's error", async () => {
    const win = fakeWindow();
    const seen: unknown[] = [];
    let refuse = false;
    win.addEventListener("message", (event) => {
      const { data } = event as MessageEvent;
      if (data?.type === TSA_ACCESS_REQUEST) {
        seen.push(data.url);
        win.postMessage({ type: TSA_ACCESS_RESPONSE, id: "other" }, "*");
        win.postMessage({ type: TSA_ACCESS_RESPONSE, id: data.id, error: refuse ? { message: "Пользователь не разрешил", code: ERROR_CANCELLED } : undefined }, "*");
      } else if (data?.type === TSA_REQUEST) {
        seen.push(data.request);
        win.postMessage({ type: TSA_RESPONSE, id: data.id, response: btoa("\x30\x03\x02\x01\x00") }, "*");
      }
    });
    await timestampAccess(win, clock, "http://tsa.example/tsp");
    expect(await timestampResponse(win, clock, "http://tsa.example/tsp", Uint8Array.of(1, 2, 3))).toEqual(Uint8Array.of(0x30, 3, 2, 1, 0));
    expect(seen).toEqual(["http://tsa.example/tsp", btoa("\x01\x02\x03")]);
    refuse = true;
    await expect(timestampAccess(win, clock, "http://tsa.example/tsp")).rejects.toMatchObject({ number: ERROR_CANCELLED });
  });
});

const site = "https://site.example";
const tsa = "http://tsa.example:8080/tsp?x=1";
const tsaOrigin = "http://tsa.example:8080";
const tsaPattern = `${tsaOrigin}/*`;
const tick = () => new Promise((resolve) => setTimeout(resolve));

// `granted`: Chrome's access; `services`: what the user said yes to as a timestamp service.
function fakeChrome(granted: string[] = [], services: string[] = []) {
  const store: Record<string, unknown> = { [STORAGE_KEY]: [site], [TSA_KEY]: services };
  const windows: { url: string; id: number }[] = [];
  const permissions = new Set(granted);
  const api = {
    storage: {
      local: {
        get: async (keys: string | string[]) => Object.fromEntries([keys].flat().filter((key) => key in store).map((key) => [key, structuredClone(store[key])])),
        set: async (items: Record<string, unknown>) => void Object.assign(store, structuredClone(items)),
      },
    },
    permissions: { contains: async ({ origins }: { origins: string[] }) => origins.every((origin) => permissions.has(origin)) },
    runtime: { getURL: (path: string) => `chrome-extension://id/${path}` },
    windows: {
      create: async ({ url }: { url: string }) => {
        const window = { url, id: windows.length + 1 };
        windows.push(window);
        return window;
      },
    },
  };
  return { api: api as unknown as typeof chrome, windows, permissions };
}

interface Posted {
  url: string;
  init: RequestInit;
}

function fakeFetch(answer: () => Response | Promise<Response>) {
  const posted: Posted[] = [];
  const fetcher = (async (url: string, init: RequestInit) => {
    posted.push({ url, init });
    return answer();
  }) as unknown as typeof fetch;
  return { fetcher, posted };
}

const idOf = (window: { url: string }) => new URL(window.url).searchParams.get("id");

describe("the service worker's access to a timestamp service", () => {
  it("has it at once for a service the user said yes to, while Chrome still gives access to it", async () => {
    const { api, windows } = fakeChrome([tsaPattern], [tsaOrigin]);
    expect(await new Timestamps(api).access({ url: tsa }, `${site}/page`)).toEqual({});
    expect(windows).toEqual([]);
  });

  it("asks about an address Chrome gives access to for another reason, an enabled site's, and remembers the yes", async () => {
    const { api, windows } = fakeChrome([tsaPattern, `${site}/*`]);
    const timestamps = new Timestamps(api);
    const asked = timestamps.access({ url: `${site}/tsp` }, `${site}/page`);
    await tick();
    expect(windows).toHaveLength(1);
    timestamps.answer(idOf(windows[0]!), true);
    expect(await asked).toEqual({});
    expect(await tsaServices(api)).toEqual([site]);
    expect(await timestamps.access({ url: `${site}/tsp` }, `${site}/page`)).toEqual({});
    expect(windows).toHaveLength(1);
  });

  it("asks in its window, and has access only when the user said yes and Chrome granted it", async () => {
    const { api, windows, permissions } = fakeChrome();
    const timestamps = new Timestamps(api);
    const asked = timestamps.access({ url: tsa }, `${site}/page`);
    await tick();
    expect(windows[0]!.url).toContain("tsa-access.html?id=");
    expect(timestamps.details(idOf(windows[0]!))).toEqual({ origin: site, url: tsa });
    // The window's click asks Chrome; here Chrome said yes.
    permissions.add(tsaPattern);
    timestamps.answer(idOf(windows[0]!), true);
    expect(await asked).toEqual({});
    expect(await tsaServices(api)).toEqual([tsaOrigin]);

    const noChrome = fakeChrome();
    const other = new Timestamps(noChrome.api);
    const refusedByChrome = other.access({ url: tsa }, `${site}/page`);
    await tick();
    other.answer(idOf(noChrome.windows[0]!), true);
    expect((await refusedByChrome).error?.code).toBe(ERROR_CANCELLED);
    const refused = other.access({ url: tsa }, `${site}/page`);
    await tick();
    other.answer(idOf(noChrome.windows[1]!), false);
    expect((await refused).error?.code).toBe(ERROR_CANCELLED);
    const closed = other.access({ url: tsa }, `${site}/page`);
    await tick();
    other.windowClosed(noChrome.windows[2]!.id);
    expect((await closed).error).toMatchObject({ code: ERROR_CANCELLED, message: expect.stringContaining("не разрешил") });
    expect(await tsaServices(noChrome.api)).toEqual([]);
  });

  it("refuses a site that is not enabled and an address that is not http or https", async () => {
    const { api, windows } = fakeChrome();
    const timestamps = new Timestamps(api);
    expect((await timestamps.access({ url: tsa }, "https://other.example/")).error?.code).toBe(E_ACCESSDENIED);
    expect((await timestamps.access({ url: "ftp://tsa.example/" }, site)).error?.code).toBe(E_INVALIDARG);
    expect((await timestamps.access({}, site)).error?.code).toBe(E_INVALIDARG);
    expect(windows).toEqual([]);
  });
});

describe("the service worker's timestamp request", () => {
  const request = btoa("\x30\x03\x02\x01\x01");

  it("posts the TimeStampReq to the service and answers with its reply", async () => {
    const { api } = fakeChrome([tsaPattern], [tsaOrigin]);
    const { fetcher, posted } = fakeFetch(() => new Response(Uint8Array.of(0x30, 0x03, 0x02, 0x01, 0x00), { headers: { "Content-Type": "application/timestamp-reply" } }));
    expect(await new Timestamps(api, fetcher).request({ url: tsa, request }, `${site}/page`)).toEqual({ response: btoa("\x30\x03\x02\x01\x00") });
    expect(posted).toHaveLength(1);
    expect(posted[0]!.url).toBe(tsa);
    expect(posted[0]!.init).toMatchObject({ method: "POST", headers: { "Content-Type": "application/timestamp-query" }, credentials: "omit" });
    expect(Array.from(posted[0]!.init.body as Uint8Array)).toEqual([0x30, 3, 2, 1, 1]);
  });

  it("needs the user's yes and Chrome's access, an enabled site and a request, and reports the service's failures", async () => {
    const { fetcher, posted } = fakeFetch(() => new Response("busy", { status: 503 }));
    const withoutAccess = new Timestamps(fakeChrome([], [tsaOrigin]).api, fetcher);
    expect((await withoutAccess.request({ url: tsa, request }, site)).error?.code).toBe(E_ACCESSDENIED);
    // An enabled site's address: Chrome gives access, the user never named it a timestamp service.
    const notAService = new Timestamps(fakeChrome([`${site}/*`]).api, fetcher);
    expect((await notAService.request({ url: `${site}/api`, request }, site)).error?.code).toBe(E_ACCESSDENIED);
    const timestamps = new Timestamps(fakeChrome([tsaPattern], [tsaOrigin]).api, fetcher);
    expect((await timestamps.request({ url: tsa, request }, "https://other.example/")).error?.code).toBe(E_ACCESSDENIED);
    expect((await timestamps.request({ url: tsa, request: "%%%" }, site)).error?.code).toBe(E_INVALIDARG);
    expect((await timestamps.request({ url: tsa, request: "" }, site)).error?.code).toBe(E_INVALIDARG);
    expect(posted).toEqual([]);
    expect((await timestamps.request({ url: tsa, request }, site)).error).toEqual({ message: "служба ответила HTTP 503", code: E_FAIL });
    const unreachable = new Timestamps(fakeChrome([tsaPattern], [tsaOrigin]).api, fakeFetch(() => Promise.reject(new TypeError("Failed to fetch"))).fetcher);
    expect((await unreachable.request({ url: tsa, request }, site)).error).toEqual({ message: "служба не ответила (Failed to fetch)", code: E_FAIL });
  });
});

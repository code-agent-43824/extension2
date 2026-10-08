// X509Enrollment.CCspInformation as webtools.html's readers and containers tabs use it (docs/PLAN.md, action 24).
import { afterEach, describe, expect, it, vi } from "vitest";
import { constants } from "../../src/page/constants.ts";
import { getLastError } from "../../src/page/errors.ts";
import { TOKEN_POLL_MS, type CspInformation } from "../../src/page/objects/csp-information.ts";
import { createObject } from "../../src/page/objects/index.ts";
import { fakePlugin, fakeSession, tokenLabel, tokenModel, tokenReader, tokenSerial } from "./fakes.ts";

afterEach(() => {
  vi.useRealTimers();
});

function cspInformation(devices: () => number[]) {
  const plugin = fakePlugin(undefined, { enumerateDevices: async () => devices() });
  return createObject("X509Enrollment.CCspInformation", fakeSession(plugin)) as CspInformation;
}

describe("X509Enrollment.CCspInformation", () => {
  it("lists each connected Rutoken as a reader with its token, indexed from 0", async () => {
    const information = cspInformation(() => [0]);
    await information.InitializeFromName("Rutoken Plugin 4.12.3.0");
    const readers = await information.GetReaderModes();
    expect(await readers.Count).toBe(1);
    const reader = await readers.ItemByIndex(0);
    expect(await reader.Name).toBe(tokenReader);
    expect(await reader.NickName).toBe(tokenLabel);
    expect(await reader.Media).toBe(`${tokenModel} ${tokenSerial}`);
    expect(await reader.CarrierFlags).toBe(constants.CARRIER_FLAG_REMOVABLE | constants.CARRIER_FLAG_UNIQUE);
    await expect(readers.ItemByIndex(1)).rejects.toMatchObject({ number: 0x80070057 });
    expect(await (await cspInformation(() => []).GetReaderModes()).Count).toBe(0);
  });

  // webtools.html shows "Контейнеры отсутствуют." for this code, rather than an error.
  it("has no CryptoPro containers to enumerate", async () => {
    const error = await cspInformation(() => [0])
      .EnumContainers()
      .catch((e: unknown) => e);
    expect(getLastError(error)).toContain("0x80070103");
  });

  it("calls tokeninserted listeners when a token is connected or removed, until they are removed", async () => {
    vi.useFakeTimers();
    let devices = [0];
    const information = cspInformation(() => devices);
    const listener = vi.fn();
    const other = vi.fn();
    await information.addEventListener("tokeninserted", listener);
    await information.addEventListener("tokenremoved", other);
    await vi.advanceTimersByTimeAsync(TOKEN_POLL_MS * 2);
    expect(listener).not.toHaveBeenCalled();

    devices = [0, 1];
    await vi.advanceTimersByTimeAsync(TOKEN_POLL_MS);
    expect(listener).toHaveBeenCalledTimes(1);
    devices = [1];
    await vi.advanceTimersByTimeAsync(TOKEN_POLL_MS);
    expect(listener).toHaveBeenCalledTimes(2);
    await vi.advanceTimersByTimeAsync(TOKEN_POLL_MS * 3);
    expect(listener).toHaveBeenCalledTimes(2);

    await information.removeEventListener("tokeninserted", listener);
    devices = [];
    await vi.advanceTimersByTimeAsync(TOKEN_POLL_MS * 3);
    expect(listener).toHaveBeenCalledTimes(2);
    expect(other).not.toHaveBeenCalled();
    expect(vi.getTimerCount()).toBe(0);
  });
});

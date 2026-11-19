// Kontur.Plugin's page side and plugin.info (docs/PLAN.md, action 57), as the real extension 3.1.11 and host 4.15.1
// answered on the stand (docs/JOURNAL.md, 2026-11-19).
import { describe, expect, it } from "vitest";
import { answerCommand, newKonturContext } from "../../src/page/kontur/commands.ts";
import { KonturError } from "../../src/page/kontur/errors.ts";
import { extensionInfo, isKonturHost } from "../../src/page/kontur/kontur-plugin.ts";
import { CadesError } from "../../src/page/errors.ts";
import { SCARD_W_CANCELLED_BY_USER } from "../../src/page/token-login.ts";
import { fakePlugin, FakePinDialog, fakeSession } from "./fakes.ts";

const clientId = "0b3c3f5e-2d7a-4a8b-9c1d-112233445566";

function setup(platform = "Linux x86_64") {
  const context = newKonturContext(fakeSession(fakePlugin(), new FakePinDialog([])), Promise.resolve({ ifcPinWindow: false, konturClientId: clientId }), platform);
  return { context, ask: (type: string, fields: Record<string, unknown> = {}) => answerCommand(context, { sessionId: "s", type, ...fields }) };
}

describe("Kontur.Plugin", () => {
  it("is the real extension to the page: its id and version, Chrome's or Firefox's", () => {
    expect(extensionInfo("Mozilla/5.0 (X11; Linux x86_64) Chrome/153.0.0.0 Safari/537.36")).toEqual({ id: "hnhppcgejeffnbnioloohhmndpmclaga", type: "chrome", version: "3.1.11" });
    expect(extensionInfo("Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0")).toMatchObject({ id: "kontur.extension@kontur.ru", type: "firefox" });
  });

  it("marks only Kontur's domains, as the real extension", () => {
    for (const host of ["extern.kontur.ru", "ca.kontur-ca.ru", "a.kontur-extern.ru", "x.kontur", "auth.testkontur.ru"]) expect(isKonturHost(host), host).toBe(true);
    for (const host of ["kontur.ru.example.com", "127.0.0.1", "example.ru"]) expect(isKonturHost(host), host).toBe(false);
  });

  it("answers plugin.info as the host on the stand, not denied, with the extension's client id", async () => {
    expect(await setup().ask("plugin.info")).toEqual({ architecture: "x86_64", buildType: "stable", clientId, denied: false, platform: "linux", pluginVersion: "4.15.1.6119" });
    expect(await setup("Win32").ask("plugin.info")).toMatchObject({ platform: "windows" });
    expect(await setup("MacIntel").ask("plugin.info")).toMatchObject({ platform: "mac" });
  });

  it("answers an unknown command and a cancelled PIN window with the host's errors", async () => {
    await expect(setup().ask("no.such")).rejects.toMatchObject({ answer: { type: "plugin", code: 2, message: "PLUGIN[0x00000002] unknown command" } });
    expect(KonturError.of(new CadesError("cancelled", SCARD_W_CANCELLED_BY_USER)).answer).toEqual({ type: "crypto", code: 51, context: "", message: "CRYPTO[0x00000033] the pkcs11 session is not authorized" });
    expect(KonturError.of(new Error("boom")).answer).toEqual({ type: "plugin", code: 0, message: "PLUGIN[0x00000000] boom" });
  });
});

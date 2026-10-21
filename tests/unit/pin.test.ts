// The PIN a page knows (docs/PLAN.md, action 35b): the signer's and the key's KeyPin, and the PIN remembered until
// the page closes, which PrivateKey.CachePin and CacheKey tick in advance or forget.
import { describe, expect, it } from "vitest";
import { constants } from "../../src/page/constants.ts";
import type { Certificate, Certificates } from "../../src/page/objects/certificate.ts";
import { createObject } from "../../src/page/objects/index.ts";
import type { Session } from "../../src/page/objects/session.ts";
import type { CadesSignedData } from "../../src/page/objects/signed-data.ts";
import type { CPSigner } from "../../src/page/objects/signer.ts";
import type { Store } from "../../src/page/objects/store.ts";
import { SCARD_W_CANCELLED_BY_USER } from "../../src/page/signing.ts";
import { fakePlugin, FakePinDialog, fakeSession, userPin } from "./fakes.ts";

interface PrivateKeyApi {
  CachePin: Promise<boolean>;
  propset_CachePin(value: unknown): Promise<void>;
  CacheKey(value: unknown): Promise<void>;
  propset_KeyPin(pin: unknown): Promise<void>;
}

function setup(answers: (string | null)[] = []) {
  const plugin = fakePlugin();
  const dialog = new FakePinDialog(answers);
  return { plugin, dialog, session: fakeSession(plugin, dialog) };
}

async function tokenCertificate(session: Session): Promise<Certificate> {
  const store = createObject("CAdESCOM.Store", session) as Store;
  await store.Open();
  return (await (store.Certificates as Promise<Certificates>)).Item(1);
}

async function sign(session: Session, keyPin?: string): Promise<string> {
  const signer = createObject("CAdESCOM.CPSigner", session) as CPSigner;
  await signer.propset_Certificate(await tokenCertificate(session));
  if (keyPin !== undefined) await signer.propset_KeyPin(keyPin);
  const data = createObject("CAdESCOM.CadesSignedData", session) as CadesSignedData;
  await data.propset_Content("Привет");
  return data.SignCades(signer, constants.CADESCOM_CADES_BES);
}

async function privateKey(session: Session): Promise<PrivateKeyApi> {
  return (await (await tokenCertificate(session)).PrivateKey) as unknown as PrivateKeyApi;
}

describe("the signer's KeyPin", () => {
  it("logs in with the site's PIN after the user's yes, without the PIN field", async () => {
    const { plugin, dialog, session } = setup();
    await sign(session, userPin);
    expect(dialog.notes).toEqual(["PIN-код Рутокена передал сайт."]);
    expect(dialog.errors).toEqual([]);
    expect(plugin.calls.login).toEqual([userPin]);
    expect(plugin.calls.sign).toHaveLength(1);
    expect(plugin.calls.logout).toBe(1);
  });

  it("falls back to the PIN field when the site's PIN is wrong", async () => {
    const { plugin, dialog, session } = setup([userPin]);
    await sign(session, "0000");
    expect(plugin.calls.login).toEqual(["0000", userPin]);
    expect(dialog.errors).toEqual(["PIN-код, который передал сайт, не подошёл. Введите PIN-код."]);
    expect(plugin.calls.sign).toHaveLength(1);
  });

  it("signs nothing when the user says no", async () => {
    const { plugin, dialog, session } = setup();
    dialog.confirms = [false];
    await expect(sign(session, userPin)).rejects.toMatchObject({ number: SCARD_W_CANCELLED_BY_USER });
    expect(plugin.calls.login).toEqual([]);
    expect(dialog.closed).toBe(1);
  });
});

describe("the remembered PIN", () => {
  it("is not kept unless the user ticks the box", async () => {
    const { plugin, dialog, session } = setup([userPin, userPin]);
    await sign(session);
    await sign(session);
    expect(plugin.calls.login).toEqual([userPin, userPin]);
    expect(dialog.notes).toEqual([]);
    expect(dialog.ticked).toEqual([false, false]);
  });

  it("asks only for a yes until the page closes once the user ticks the box", async () => {
    const { plugin, dialog, session } = setup([userPin]);
    dialog.tick = true;
    await sign(session);
    dialog.tick = undefined;
    await sign(session);
    await sign(session);
    expect(dialog.notes).toEqual(["PIN-код запомнен до закрытия страницы.", "PIN-код запомнен до закрытия страницы."]);
    expect(dialog.ticked).toEqual([false, true, true]);
    expect(plugin.calls.login).toEqual([userPin, userPin, userPin]);
    expect(plugin.calls.logout).toBe(3);
  });

  it("is forgotten when the user unticks the box, and when it no longer fits", async () => {
    const { plugin, dialog, session } = setup([userPin, userPin, userPin]);
    dialog.tick = true;
    await sign(session);
    dialog.tick = false;
    await sign(session);
    dialog.tick = true;
    await sign(session);
    expect(dialog.errors).toEqual([undefined, undefined]);
    // The PIN changed elsewhere: the remembered one fails once and goes, the field comes back.
    const login = plugin.login;
    let refusals = 1;
    plugin.login = async (device, pin) => {
      if (refusals-- > 0) {
        plugin.calls.login.push(pin);
        throw new Error("17");
      }
      return login(device, pin);
    };
    await sign(session);
    expect(dialog.errors).toEqual([undefined, undefined, "Запомненный PIN-код не подошёл. Введите PIN-код."]);
    expect(plugin.calls.login).toEqual([userPin, userPin, userPin, userPin, userPin]);
    expect(plugin.calls.sign).toHaveLength(4);
  });

  it("is ticked in advance by PrivateKey.CachePin and CacheKey; CacheKey(false) forgets it, CachePin(false) does not", async () => {
    const { plugin, dialog, session } = setup([userPin, userPin]);
    const key = await privateKey(session);
    expect(await key.CachePin).toBe(false);
    await key.propset_CachePin(true);
    expect(await key.CachePin).toBe(true);
    await sign(session);
    expect(dialog.ticked).toEqual([true]);
    // Честный знак turns it off before each signature: the remembered PIN stays.
    await key.propset_CachePin(false);
    await sign(session);
    expect(dialog.notes).toEqual(["PIN-код запомнен до закрытия страницы."]);
    await key.CacheKey(false);
    await sign(session);
    expect(dialog.ticked).toEqual([true, true, false]);
    expect(dialog.notes).toHaveLength(1);
    await key.CacheKey(true);
    expect(await key.CachePin).toBe(true);
    expect(plugin.calls.login).toEqual([userPin, userPin, userPin]);
  });

  it("belongs to the page: another page's session asks again", async () => {
    const { plugin, dialog, session } = setup([userPin]);
    dialog.tick = true;
    await sign(session);
    const other = new FakePinDialog([userPin]);
    await sign(fakeSession(plugin, other));
    expect(other.notes).toEqual([]);
    expect(other.ticked).toEqual([false]);
  });
});

describe("the key's KeyPin", () => {
  it("serves every operation with the token's key, until the site clears it", async () => {
    const { plugin, dialog, session } = setup([userPin]);
    const key = await privateKey(session);
    await key.propset_KeyPin(userPin);
    await sign(session);
    await sign(session);
    expect(dialog.notes).toEqual(["PIN-код Рутокена передал сайт.", "PIN-код Рутокена передал сайт."]);
    await key.propset_KeyPin("");
    await sign(session);
    expect(dialog.errors).toEqual([undefined]);
    expect(plugin.calls.login).toEqual([userPin, userPin, userPin]);
  });
});

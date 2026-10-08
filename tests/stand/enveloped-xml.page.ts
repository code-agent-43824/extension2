// Bundled by tests/stand/enveloped-xml.spec.ts into a page of its own: CAdESCOM.EnvelopedXML on a session whose fake
// plugin holds one certificate and makes the VKO key itself (the stand's fake token cannot: docs/JOURNAL.md,
// 2026-10-08), so that the browser's DOM runs Encrypt and Decrypt both. The key comes from `derive`, a function the
// spec exposes: the key the certificate's private key makes, computed outside the page.
import { getLastError } from "../../src/page/errors.ts";
import { encryptContent, newContentKey, wrapContentKey } from "../../src/page/gost28147.ts";
import { Certificate } from "../../src/page/objects/certificate.ts";
import { createObject } from "../../src/page/objects/index.ts";
import type { Session } from "../../src/page/objects/session.ts";
import type { PinDialog } from "../../src/page/pin-dialog.ts";
import type { RutokenPlugin } from "../../src/page/rutoken.ts";
import { parseCertificate, pemToDer } from "../../src/page/x509.ts";

export interface FakeToken {
  // The token's one user certificate.
  certificate: string;
  // How many times the PIN window opened, and what derive was asked.
  pins: number;
  derived: { publicKey: string; ukm: string }[];
}

declare global {
  interface Window {
    standDerive(publicKey: string, ukm: string): Promise<string>;
    envelopedXml: typeof api;
  }
}

function session(token: FakeToken): Session {
  const plugin = {
    CERT_CATEGORY_USER: Promise.resolve(1),
    TOKEN_INFO_SERIAL: Promise.resolve(2),
    enumerateDevices: async () => [0],
    getDeviceInfo: async () => "1",
    enumerateCertificates: async (_device: number, category: number) => (category === 1 ? ["ce:rt"] : []),
    getCertificate: async () => token.certificate,
    login: async () => undefined,
    logout: async () => undefined,
    getKeyByCertificate: async () => "ke:y1",
    derive: async (_device: number, _key: string, publicKey: string, options: { ukm: string }) => {
      token.derived.push({ publicKey, ukm: options.ukm });
      return window.standDerive(publicKey, options.ukm);
    },
  } as unknown as RutokenPlugin;
  const dialog: PinDialog = { ask: async () => "12345678", close: () => undefined };
  return {
    plugin,
    origin: "https://site.example",
    pinDialog: () => {
      token.pins++;
      return dialog;
    },
    storeCertificates: async () => ({ roots: [], intermediates: [], extendedValidity: false, offerRoot: false }),
    addCertificate: async () => undefined,
    offerRootByLink: () => undefined,
    timestampAccess: async () => undefined,
    timestamp: async () => {
      throw new Error("no timestamp service on this page");
    },
  };
}

const api = {
  token: (certificate: string): FakeToken => ({ certificate, pins: 0, derived: [] }),
  envelopedXml: (token: FakeToken) => createObject("CAdESCOM.EnvelopedXML", session(token)),
  certificate: (token: FakeToken, pem: string) => new Certificate(session(token), parseCertificate(pemToDer(pem))),
  getLastError,
  // For EncryptedData the tests write themselves: the content key wrapped for a certificate, the content encrypted.
  newContentKey,
  wrapContentKey: (pem: string, cek: Uint8Array) => wrapContentKey(parseCertificate(pemToDer(pem)), cek),
  encryptContent: (cek: Uint8Array, text: string) => encryptContent(cek, new TextEncoder().encode(text)),
};

window.envelopedXml = api;

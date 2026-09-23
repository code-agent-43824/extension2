// Test doubles shared by the unit tests: a Rutoken Plugin with one token holding the stand's
// user certificate, and a PIN window that answers from a script.
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { repoRoot } from "../../scripts/fetch-vendor.ts";
import type { Session } from "../../src/page/objects/session.ts";
import type { PinDialog, PinRequest } from "../../src/page/pin-dialog.ts";
import type { RutokenPlugin, SignOptions } from "../../src/page/rutoken.ts";

export const pem = readFileSync(join(repoRoot, "tests", "fixtures", "stand-user.pem"), "utf8");
export const certId = "cd:ea:7e:ab:5b:e6:b1:67:f2:2b:71:3b:f3:76:e9:b2:8a:db:14:a3";
export const tokenSerial = "1669552163";
export const userPin = "12345678";

export interface SignCall {
  deviceId: number;
  certId: string;
  data: string;
  format: number;
  options: SignOptions;
}

export interface FakeCalls {
  login: string[];
  logout: number;
  sign: SignCall[];
  generateKeyPair: unknown[][];
  createPkcs10: unknown[][];
  deleteKeyPair: string[];
  importCertificate: string[];
  deleteCertificate: string[];
}

export type FakePlugin = RutokenPlugin & { calls: FakeCalls };

// A PKCS#10 request as the plugin returns it; the body is not a real request.
export const requestPem = "-----BEGIN CERTIFICATE REQUEST-----\nMIIBAA==\n-----END CERTIFICATE REQUEST-----\n";

// Constants are thenables, as in the real plugin. Errors are Error objects whose message is the
// Rutoken error code, as the plugin rejects.
export function fakePlugin(certs = [pem], overrides: Partial<RutokenPlugin> = {}): FakePlugin {
  const thenable = (value: number) => ({ then: (resolve: (v: number) => unknown) => resolve(value) }) as PromiseLike<number>;
  const calls: FakeCalls = {
    login: [],
    logout: 0,
    sign: [],
    generateKeyPair: [],
    createPkcs10: [],
    deleteKeyPair: [],
    importCertificate: [],
    deleteCertificate: [],
  };
  return {
    calls,
    version: Promise.resolve("4.12.3.0"),
    CERT_CATEGORY_USER: thenable(1),
    TOKEN_INFO_SERIAL: thenable(2),
    DATA_FORMAT_BASE64: thenable(1),
    PUBLIC_KEY_ALGORITHM_GOST3410_2012_256: thenable(3),
    PUBLIC_KEY_ALGORITHM_GOST3410_2012_512: thenable(4),
    HASH_TYPE_GOST3411_12_256: thenable(5),
    HASH_TYPE_GOST3411_12_512: thenable(6),
    KEY_SPEC_SIGN: thenable(7),
    KEY_SPEC_SIGN_AND_EXCHANGE: thenable(8),
    enumerateDevices: async () => [0],
    enumerateCertificates: async (_device, category) => (category === 1 ? certs.map((_, i) => `${certId}${i || ""}`) : []),
    getCertificate: async (_device, id) => certs[Number(id.slice(certId.length) || 0)]!,
    getDeviceInfo: async (_device, option) => (option === 2 ? tokenSerial : null),
    login: async (_device, pin) => {
      calls.login.push(pin);
      if (pin !== userPin) throw new Error("17");
    },
    logout: async () => {
      calls.logout++;
    },
    sign: async (deviceId, id, data, format, options) => {
      calls.sign.push({ deviceId, certId: id, data, format, options });
      return "MIIsignature";
    },
    generateKeyPair: async (...args) => {
      calls.generateKeyPair.push(args);
      return "ke:y1";
    },
    deleteKeyPair: async (_device, keyId) => {
      calls.deleteKeyPair.push(keyId);
    },
    createPkcs10: async (...args) => {
      calls.createPkcs10.push(args);
      return requestPem;
    },
    importCertificate: async (_device, certificate) => {
      calls.importCertificate.push(certificate);
      return "ne:w1";
    },
    getKeyByCertificate: async () => "ke:y1",
    deleteCertificate: async (_device, id) => {
      calls.deleteCertificate.push(id);
    },
    ...overrides,
  };
}

// Answers ask() with the next scripted PIN (null = cancel) and records what it was shown.
export class FakePinDialog implements PinDialog {
  requests: PinRequest[] = [];
  errors: (string | undefined)[] = [];
  closed = 0;
  private readonly answers: (string | null)[];
  constructor(answers: (string | null)[]) {
    this.answers = answers;
  }
  open = (request: PinRequest): PinDialog => {
    this.requests.push(request);
    return this;
  };
  async ask(error?: string) {
    this.errors.push(error);
    return this.answers.shift() ?? null;
  }
  close() {
    this.closed++;
  }
}

export function fakeSession(plugin: RutokenPlugin, dialog = new FakePinDialog([])): Session {
  return { plugin, origin: "https://site.example", pinDialog: dialog.open };
}

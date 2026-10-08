// CAdESCOM.EnvelopedXML: XML encryption in CryptoPro's format (docs/PLAN.md, action 25; the format: docs/JOURNAL.md,
// 2026-10-08). The whole document becomes an EncryptedData of type Element: GOST 28147-89 in CBC mode, the content
// key wrapped for each recipient in an EncryptedKey carrying the recipient's certificate. Encrypt needs no token: it
// runs in the page (src/page/gost28147.ts). Decrypt finds an EncryptedKey for a certificate on a connected token and,
// after the PIN, has the token make the key-encryption key (the Rutoken Plugin's derive); the rest is in the page.
import { constants } from "../constants.ts";
import { CadesError } from "../errors.ts";
import { GOST_2012_256, GOST_2012_512 } from "../gost.ts";
import { decryptContent, encryptContent, newContentKey, parseKeyTransport, unwrapContentKey, wrapContentKey, type KeyTransport } from "../gost28147.ts";
import { certificateLines, sizeText } from "../signing.ts";
import { userCertificates, type TokenCertificate } from "../token.ts";
import { withLogin } from "../token-login.ts";
import { derToBase64 } from "../x509.ts";
import { x509Of } from "./certificate.ts";
import { Algorithm, pluginFailure, Recipients } from "./enveloped-data.ts";
import { bytesBinary } from "./hashed-data.ts";
import type { Session } from "./session.ts";
import { base64Bytes, decodeContent, parse, serialize, utf8Binary, wrap } from "./signed-xml.ts";

const E_INVALIDARG = 0x80070057;
const NTE_BAD_DATA = 0x80090005;
const NTE_BAD_ALGID = 0x80090008;
const CRYPT_E_NO_DECRYPT_CERT = 0x8009200c;

const XENC = "http://www.w3.org/2001/04/xmlenc#";
const DS = "http://www.w3.org/2000/09/xmldsig#";
const CPXMLSEC = "urn:ietf:params:xml:ns:cpxmlsec";
const ALGORITHMS = `${CPXMLSEC}:algorithms:`;
const GOST28147 = `${ALGORITHMS}gost28147`;

// The key transport each recipient key needs, CryptoPro's addresses (GostConstants.cs of CryptoPro's .NET).
const transports = new Map<string, string>([
  [GOST_2012_256, `${ALGORITHMS}transport-gost2012-256`],
  [GOST_2012_512, `${ALGORITHMS}transport-gost2012-512`],
]);
const knownTransports = new Set([...transports.values(), `${ALGORITHMS}transport-gost2001`]);

function element(doc: Document, namespace: string, name: string, ...children: Node[]): Element {
  const result = doc.createElementNS(namespace, name);
  for (const child of children) result.appendChild(child);
  return result;
}

function childElements(parent: Element | undefined, namespace: string, name: string): Element[] {
  return parent ? Array.from(parent.children).filter((child) => child.namespaceURI === namespace && child.localName === name) : [];
}

function child(parent: Element | undefined, namespace: string, name: string): Element | undefined {
  return childElements(parent, namespace, name)[0];
}

function colonHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join(":");
}

function fromHex(hex: string): Uint8Array {
  return Uint8Array.from(hex.replace(/[^0-9a-f]/gi, "").match(/../g) ?? [], (byte) => parseInt(byte, 16));
}

function cipherValue(parent: Element | undefined): Uint8Array | undefined {
  const text = child(child(parent, XENC, "CipherData"), XENC, "CipherValue")?.textContent;
  return text ? base64Bytes(text) : undefined;
}

// An EncryptedData to decrypt: its key for one of the token's certificates, and the parameter set of its content.
interface Job {
  data: Element;
  transport: KeyTransport;
  token: TokenCertificate;
  content: Uint8Array;
  paramSet: string;
}

// The EncryptedData's key for a certificate on the token, from the certificates its EncryptedKeys carry.
function job(data: Element, tokens: TokenCertificate[]): Job | undefined {
  const method = child(data, XENC, "EncryptionMethod");
  if (method?.getAttribute("Algorithm") !== GOST28147) {
    throw new CadesError(`Алгоритм шифрования ${method?.getAttribute("Algorithm") ?? "(не указан)"} не поддерживается: только ГОСТ 28147-89`, NTE_BAD_ALGID);
  }
  const content = cipherValue(data);
  if (!content) throw new CadesError("Нет зашифрованных данных (CipherValue)", NTE_BAD_DATA);
  // Without Parameters28147 the content uses the key's own parameters, which the key transport names.
  const parameters = child(method, CPXMLSEC, "Parameters28147")?.textContent?.trim().replace(/^urn:oid:/, "");
  for (const encryptedKey of childElements(child(data, DS, "KeyInfo"), XENC, "EncryptedKey")) {
    if (!knownTransports.has(child(encryptedKey, XENC, "EncryptionMethod")?.getAttribute("Algorithm") ?? "")) continue;
    const certificate = base64Bytes(child(child(child(encryptedKey, DS, "KeyInfo"), DS, "X509Data"), DS, "X509Certificate")?.textContent ?? "");
    const token = certificate && tokens.find((candidate) => derToBase64(candidate.x509.der) === derToBase64(certificate));
    const wrapped = cipherValue(encryptedKey);
    if (!token || !wrapped) continue;
    let transport: KeyTransport;
    try {
      transport = parseKeyTransport(wrapped);
    } catch {
      throw new CadesError("Ключ сообщения записан не по ГОСТ Р 34.10-2012 (GostR3410-KeyTransport)", NTE_BAD_DATA);
    }
    return { data, transport, token, content, paramSet: parameters || transport.paramSet };
  }
  return undefined;
}

// The decrypted bytes put in place of the EncryptedData: an element or content, read with the namespaces declared
// around it.
function replace(data: Element, plain: Uint8Array): void {
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(plain);
  } catch {
    throw new CadesError("Расшифрованные данные не в UTF-8", NTE_BAD_DATA);
  }
  const declarations = new Map<string, string>();
  for (let ancestor = data.parentElement; ancestor; ancestor = ancestor.parentElement) {
    for (const attribute of Array.from(ancestor.attributes)) {
      if ((attribute.name === "xmlns" || attribute.name.startsWith("xmlns:")) && !declarations.has(attribute.name)) declarations.set(attribute.name, attribute.value);
    }
  }
  const attributes = Array.from(declarations, ([name, value]) => ` ${name}="${value.replace(/&/g, "&amp;").replace(/"/g, "&quot;").replace(/</g, "&lt;")}"`).join("");
  const wrapper = parse(`<wrapper${attributes}>${text}</wrapper>`).documentElement;
  const doc = data.ownerDocument;
  // Removed first: a document takes its new root element only once the old one is gone.
  const parent = data.parentNode!;
  const next = data.nextSibling;
  parent.removeChild(data);
  for (const node of Array.from(wrapper.childNodes)) parent.insertBefore(doc.importNode(node, true), next);
}

export class EnvelopedXML {
  readonly #session: Session;
  readonly #algorithm = new Algorithm();
  readonly #recipients = new Recipients();
  #content = "";

  constructor(session: Session) {
    this.#session = session;
  }

  // GOST 28147-89 only, as CryptoPro's documentation of EnvelopedXML says; Encrypt refuses the others.
  get Algorithm(): Promise<Algorithm> {
    return Promise.resolve(this.#algorithm);
  }

  get Recipients(): Promise<Recipients> {
    return Promise.resolve(this.#recipients);
  }

  // The document: XML text, or Base64 of its UTF-8 bytes; Encrypt and Decrypt answer the same way.
  get Content(): Promise<string> {
    return Promise.resolve(this.#content);
  }

  propset_Content(content: unknown): Promise<void> {
    this.#content = String(content ?? "");
    return Promise.resolve();
  }

  async Encrypt(): Promise<string> {
    if (Number(await this.#algorithm.Name) !== constants.CADESCOM_ENCRYPTION_ALGORITHM_GOST_28147_89) {
      throw new CadesError("XML шифруется только ГОСТ 28147-89", NTE_BAD_ALGID);
    }
    const recipients = this.#recipients.certificates().map((certificate) => x509Of(certificate)!);
    if (recipients.length === 0) throw new CadesError("Не задан ни один получатель", E_INVALIDARG);
    for (const x509 of recipients) {
      if (!transports.has(x509.publicKeyAlgorithm)) throw new CadesError("Ключ получателя не ГОСТ Р 34.10-2012: зашифровать для него нельзя", NTE_BAD_ALGID);
    }
    const { xml, base64 } = decodeContent(this.#content);
    const doc = parse(xml);
    const root = doc.documentElement;
    const cek = newContentKey();
    const text = (value: Uint8Array) => doc.createTextNode(wrap(btoa(bytesBinary(value))));
    const keyInfo = element(doc, DS, "KeyInfo");
    for (const x509 of recipients) {
      const method = element(doc, XENC, "EncryptionMethod");
      method.setAttribute("Algorithm", transports.get(x509.publicKeyAlgorithm)!);
      const certificate = element(doc, DS, "KeyInfo", element(doc, DS, "X509Data", element(doc, DS, "X509Certificate", text(x509.der))));
      keyInfo.appendChild(element(doc, XENC, "EncryptedKey", method, certificate, element(doc, XENC, "CipherData", element(doc, XENC, "CipherValue", text(wrapContentKey(x509, cek))))));
    }
    const method = element(doc, XENC, "EncryptionMethod");
    method.setAttribute("Algorithm", GOST28147);
    const plain = new TextEncoder().encode(new XMLSerializer().serializeToString(root));
    const data = element(doc, XENC, "EncryptedData", method, keyInfo, element(doc, XENC, "CipherData", element(doc, XENC, "CipherValue", text(encryptContent(cek, plain)))));
    data.setAttribute("Type", `${XENC}Element`);
    doc.replaceChild(data, root);
    const encrypted = serialize(doc, xml);
    return base64 ? wrap(btoa(utf8Binary(encrypted))) : encrypted;
  }

  // Decrypts every EncryptedData of the document; Content becomes the whole decrypted document.
  async Decrypt(message: unknown): Promise<void> {
    const { xml, base64 } = decodeContent(typeof message === "string" ? message : "");
    const doc = parse(xml);
    const encrypted = Array.from(doc.getElementsByTagNameNS(XENC, "EncryptedData"));
    if (encrypted.length === 0) throw new CadesError("В документе нет зашифрованных данных (EncryptedData)", NTE_BAD_DATA);
    const plugin = this.#session.plugin;
    const tokens = await userCertificates(plugin);
    const jobs = encrypted.map((data) => job(data, tokens));
    const first = jobs[0];
    if (!first || jobs.some((item) => !item || item.token.deviceId !== first.token.deviceId)) {
      throw new CadesError("Cannot find the certificate and private key to use for decryption.", CRYPT_E_NO_DECRYPT_CERT);
    }
    const { deviceId } = first.token;
    const request = {
      origin: this.#session.origin,
      action: "просит расшифровать данные.",
      details: [`Зашифрованный XML-документ, ${sizeText(xml.length)}.`, ...certificateLines(first.token.x509)],
      confirm: "Расшифровать",
    };
    const keks = await withLogin(this.#session, deviceId, request, async () => {
      const keyIds = new Map<string, string>();
      const result: Uint8Array[] = [];
      for (const item of jobs as Job[]) {
        let keyId = keyIds.get(item.token.certId);
        if (keyId === undefined) {
          keyId = await plugin.getKeyByCertificate(deviceId, item.token.certId);
          keyIds.set(item.token.certId, keyId);
        }
        try {
          result.push(fromHex(await plugin.derive(deviceId, keyId, colonHex(item.transport.ephemeralKey), { ukm: colonHex(item.transport.ukm) })));
        } catch (error) {
          throw pluginFailure("расшифровал", error, NTE_BAD_DATA);
        }
      }
      return result;
    });
    (jobs as Job[]).forEach((item, i) => {
      let plain: Uint8Array;
      try {
        plain = decryptContent(unwrapContentKey(item.transport, keks[i]!), item.content, item.paramSet);
      } catch {
        throw new CadesError("Не удалось расшифровать: ключ сообщения не подошёл или сообщение повреждено", NTE_BAD_DATA);
      }
      replace(item.data, plain);
    });
    const decrypted = serialize(doc, xml);
    this.#content = base64 ? wrap(btoa(utf8Binary(decrypted))) : decrypted;
  }
}

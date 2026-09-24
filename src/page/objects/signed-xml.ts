// CAdESCOM.SignedXML: GOST XMLDSig signatures, enveloped, enveloping and in a template, as CryptoPro's
// plug-in 2.0.15700 makes and verifies them (docs/JOURNAL.md, 2026-09-24). Canonicalization is xmldsigjs',
// digests and signature checks are the page's own (src/page/gost.ts), the signature is the Rutoken Plugin's
// rawSign() with the certificate's key.
import { XmlCanonicalizer } from "xmldsigjs-canonicalizer";
import { constants } from "../constants.ts";
import { CadesError } from "../errors.ts";
import { digest, GOST_2001, GOST_2012_256, GOST_2012_512, verifyHash, type DigestName } from "../gost.ts";
import { certificateLines } from "../signing.ts";
import { findDevice } from "../token.ts";
import { SCARD_E_NO_SMARTCARD, withLogin } from "../token-login.ts";
import { derToBase64, parseCertificate, type X509 } from "../x509.ts";
import { binaryBytes, bytesBinary } from "./hashed-data.ts";
import type { Session } from "./session.ts";
import { signerCertificate } from "./signer.ts";
import { Signers, type VerifiedSignature } from "./signers.ts";

const E_NOTIMPL = 0x80004001;
// HRESULTs the real plug-in answers with (docs/JOURNAL.md, 2026-09-24).
const ERROR_XML_PARSE_ERROR = 0x800705b9;
const ERROR_NOT_FOUND = 0x80070490;
const CRYPT_E_NOT_FOUND = 0x80092004;
const NTE_BAD_ALGID = 0x80090008;
const NTE_BAD_SIGNATURE = 0x80090006;
const ERROR_INVALID_DATA = 0x8007000d;
const ERROR_XML_SIGNATURE = 0x800705ba;

const DS = "http://www.w3.org/2000/09/xmldsig#";
const XMLNS = "http://www.w3.org/2000/xmlns/";
const XML = "http://www.w3.org/XML/1998/namespace";
const EXC_C14N = "http://www.w3.org/2001/10/xml-exc-c14n#";
const INCLUSIVE_C14N = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";
const ENVELOPED_SIGNATURE = `${DS}enveloped-signature`;

const canonicalizations = new Map<string, { exclusive: boolean; comments: boolean }>([
  [INCLUSIVE_C14N, { exclusive: false, comments: false }],
  [`${INCLUSIVE_C14N}#WithComments`, { exclusive: false, comments: true }],
  [EXC_C14N, { exclusive: true, comments: false }],
  [`${EXC_C14N}WithComments`, { exclusive: true, comments: true }],
]);

const digestMethods = new Map<string, DigestName>([
  [constants.XmlDsigGost3411Url2012256, "streebog256"],
  [constants.XmlDsigGost3411Url2012512, "streebog512"],
  [constants.XmlDsigGost3411Url, "gost94"],
  [constants.XmlDsigGost3411UrlObsolete, "gost94"],
]);

// Each signature method, the key it needs and the hash it signs.
const signatureMethods = new Map<string, { key: string; hash: DigestName }>([
  [constants.XmlDsigGost3410Url2012256, { key: GOST_2012_256, hash: "streebog256" }],
  [constants.XmlDsigGost3410Url2012512, { key: GOST_2012_512, hash: "streebog512" }],
  [constants.XmlDsigGost3410Url, { key: GOST_2001, hash: "gost94" }],
  [constants.XmlDsigGost3410UrlObsolete, { key: GOST_2001, hash: "gost94" }],
]);

// Without SignatureMethod and DigestMethod the real plug-in takes the ones of the key.
const defaultMethods = new Map<string, { signature: string; digest: string }>([
  [GOST_2012_256, { signature: constants.XmlDsigGost3410Url2012256, digest: constants.XmlDsigGost3411Url2012256 }],
  [GOST_2012_512, { signature: constants.XmlDsigGost3410Url2012512, digest: constants.XmlDsigGost3411Url2012512 }],
  [GOST_2001, { signature: constants.XmlDsigGost3410Url, digest: constants.XmlDsigGost3411Url }],
]);

const typeNames = new Map<number, string>([
  [constants.CADESCOM_XML_SIGNATURE_TYPE_ENVELOPED, "вложенная"],
  [constants.CADESCOM_XML_SIGNATURE_TYPE_ENVELOPING, "оборачивающая"],
  [constants.CADESCOM_XML_SIGNATURE_TYPE_TEMPLATE, "по шаблону"],
]);

function signatureMethod(uri: string, keyAlgorithm: string): { key: string; hash: DigestName } {
  const method = signatureMethods.get(uri);
  if (!method) throw new CadesError(`Неизвестный алгоритм подписи ${uri}`, CRYPT_E_NOT_FOUND);
  if (method.key !== keyAlgorithm) throw new CadesError("Алгоритм подписи не подходит к ключу сертификата", NTE_BAD_ALGID);
  return method;
}

function digestMethod(uri: string): DigestName {
  const method = digestMethods.get(uri);
  if (!method) throw new CadesError(`Неизвестный алгоритм хеширования ${uri}`, CRYPT_E_NOT_FOUND);
  return method;
}

// Base64 in lines of 64, as the real plug-in writes it.
function wrap(base64: string): string {
  return base64.replace(/(.{64})(?=.)/g, "$1\n");
}

function hexToBase64(hex: string): string {
  return btoa(bytesBinary(Uint8Array.from(hex.replace(/:/g, "").match(/../g) ?? [], (byte) => parseInt(byte, 16))));
}

function utf8Binary(text: string): string {
  return bytesBinary(new TextEncoder().encode(text));
}

function utf8Digest(name: DigestName, text: string): Uint8Array {
  return digest(name, new TextEncoder().encode(text));
}

function base64Bytes(text: string): Uint8Array | undefined {
  try {
    return binaryBytes(atob(text.replace(/\s+/g, "")));
  } catch {
    return undefined;
  }
}

function same(a: Uint8Array, b: Uint8Array | undefined): boolean {
  return b !== undefined && a.length === b.length && a.every((byte, i) => byte === b[i]);
}

// A random id for the Signature and Object elements; crypto.randomUUID() needs a secure context, sites may not be one.
function randomId(): string {
  const hex = Array.from(crypto.getRandomValues(new Uint8Array(16)), (byte) => byte.toString(16).padStart(2, "0")).join("");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

function parse(xml: string): XMLDocument {
  const doc = new DOMParser().parseFromString(xml, "application/xml");
  if (!xml.trim() || doc.getElementsByTagNameNS("http://www.w3.org/1999/xhtml", "parsererror").length > 0) {
    throw new CadesError("Не удалось разобрать XML-документ.", ERROR_XML_PARSE_ERROR);
  }
  return doc;
}

// Content is an XML string, or Base64 of the document's bytes (the real plug-in's way for other encodings;
// only UTF-8 is taken here). The result goes back the same way.
function decodeContent(content: string): { xml: string; base64: boolean } {
  if (content.trimStart().startsWith("<") || !/^[A-Za-z0-9+/=\s]+$/.test(content)) return { xml: content, base64: false };
  let bytes: Uint8Array;
  try {
    bytes = Uint8Array.from(atob(content.replace(/\s+/g, "")), (char) => char.charCodeAt(0));
  } catch {
    throw new CadesError("Не удалось разобрать XML-документ.", ERROR_XML_PARSE_ERROR);
  }
  const declared = /^(?:﻿)?\s*<\?xml[^>]*encoding\s*=\s*["']([^"']+)["']/.exec(new TextDecoder("latin1").decode(bytes.subarray(0, 200)))?.[1];
  if (declared && !/^utf-?8$/i.test(declared)) throw new CadesError(`Документ в кодировке ${declared} не поддерживается: только UTF-8`, E_NOTIMPL);
  try {
    return { xml: new TextDecoder("utf-8", { fatal: true }).decode(bytes), base64: true };
  } catch {
    throw new CadesError("Не удалось разобрать XML-документ.", ERROR_XML_PARSE_ERROR);
  }
}

// The document as the real plug-in returns it: the XML declaration (the site's, or a plain one), then the
// top-level nodes one per line.
function serialize(doc: XMLDocument, source: string): string {
  const declaration = /^(?:﻿)?\s*(<\?xml[^>]*\?>)/.exec(source)?.[1] ?? '<?xml version="1.0"?>';
  const serializer = new XMLSerializer();
  return `${[declaration, ...Array.from(doc.childNodes, (node) => serializer.serializeToString(node))].join("\n")}\n`;
}

// For inclusive C14N of an element inside a document: a copy that declares the namespaces and carries the
// xml: attributes it inherits (C14N 1.0, 2.4), which the canonicalizer would not see from its ancestors.
function inclusiveSubset(element: Element): Element {
  const copy = element.cloneNode(true) as Element;
  for (let ancestor = element.parentElement; ancestor; ancestor = ancestor.parentElement) {
    for (const attribute of Array.from(ancestor.attributes)) {
      const inherited = attribute.namespaceURI === XMLNS || attribute.namespaceURI === XML;
      if (inherited && !copy.hasAttributeNS(attribute.namespaceURI, attribute.localName)) {
        copy.setAttributeNS(attribute.namespaceURI, attribute.name, attribute.value);
      }
    }
  }
  return copy;
}

function canonicalize(node: Node, algorithm: string, prefixes: string | null, comments?: boolean): string {
  const method = canonicalizations.get(algorithm);
  if (!method) throw new CadesError(`Канонизация ${algorithm} не поддерживается`, E_NOTIMPL);
  const canonicalizer = new XmlCanonicalizer(comments ?? method.comments, method.exclusive);
  if (prefixes) canonicalizer.InclusiveNamespacesPrefixList = prefixes;
  const target = !method.exclusive && node.nodeType === Node.ELEMENT_NODE && node.parentNode?.nodeType === Node.ELEMENT_NODE ? inclusiveSubset(node as Element) : node;
  return canonicalizer.Canonicalize(target);
}

function child(parent: Element, localName: string): Element | undefined {
  return Array.from(parent.children).find((element) => element.namespaceURI === DS && element.localName === localName);
}

function createDs(signature: Element, localName: string): Element {
  return signature.ownerDocument.createElementNS(DS, signature.prefix ? `${signature.prefix}:${localName}` : localName);
}

// "#id": xml:id, as the real plug-in resolves it, and also Id, ID and id, which it does not (checked
// 2026-09-24) but other XMLDSig implementations do.
function findById(doc: XMLDocument, id: string): Element {
  for (const element of Array.from(doc.getElementsByTagName("*"))) {
    if (element.getAttributeNS(XML, "id") === id || ["Id", "ID", "id"].some((name) => element.getAttribute(name) === id)) return element;
  }
  throw new CadesError(`Не найден элемент ${id} для подписи`, ERROR_NOT_FOUND);
}

interface Reference {
  target: Node;
  enveloped: boolean;
  canonicalization: string;
  prefixes: string | null;
  hash: DigestName;
  value: Element;
}

interface Pending {
  signature: Element;
  references: Reference[];
  signedInfo: Element;
  canonicalization: string;
  hash: DigestName;
}

// What a Reference points at and how it is transformed.
function referenceTarget(reference: Element): Omit<Reference, "hash" | "value"> {
  const doc = reference.ownerDocument as XMLDocument;
  // A Reference without URI means the whole document (the real plug-in's documentation of Verify).
  const uri = reference.getAttribute("URI") ?? "";
  if (uri !== "" && !uri.startsWith("#")) throw new CadesError(`Ссылка ${uri} не поддерживается`, E_NOTIMPL);
  let enveloped = false;
  // Without a canonicalization transform the node-set is canonicalized inclusively (XMLDSig, 4.4.3.2).
  let canonicalization = INCLUSIVE_C14N;
  let prefixes: string | null = null;
  for (const transform of Array.from(child(reference, "Transforms")?.children ?? [])) {
    const algorithm = transform.getAttribute("Algorithm") ?? "";
    if (algorithm === ENVELOPED_SIGNATURE) {
      enveloped = true;
    } else if (canonicalizations.has(algorithm)) {
      canonicalization = algorithm;
      prefixes = transform.getElementsByTagNameNS(EXC_C14N, "InclusiveNamespaces")[0]?.getAttribute("PrefixList") ?? null;
    } else {
      throw new CadesError(`Преобразование ${algorithm} не поддерживается`, E_NOTIMPL);
    }
  }
  return { target: uri === "" ? doc : findById(doc, uri.slice(1)), enveloped, canonicalization, prefixes };
}

function references(signedInfo: Element): Element[] {
  return Array.from(signedInfo.children).filter((element) => element.namespaceURI === DS && element.localName === "Reference");
}

// The work a template signature needs, checked before any PIN is asked for.
function prepare(signature: Element, keyAlgorithm: string, methods: { signature: string; digest: string }): Pending {
  const signedInfo = child(signature, "SignedInfo");
  if (!signedInfo) throw new CadesError("В шаблоне подписи нет SignedInfo", CRYPT_E_NOT_FOUND);
  const method = child(signedInfo, "SignatureMethod");
  if (!method) throw new CadesError("В шаблоне подписи нет SignatureMethod", CRYPT_E_NOT_FOUND);
  if (!method.getAttribute("Algorithm")) method.setAttribute("Algorithm", methods.signature);
  const { hash } = signatureMethod(method.getAttribute("Algorithm")!, keyAlgorithm);
  const canonicalization = child(signedInfo, "CanonicalizationMethod")?.getAttribute("Algorithm") ?? INCLUSIVE_C14N;
  if (!canonicalizations.has(canonicalization)) throw new CadesError(`Канонизация ${canonicalization} не поддерживается`, E_NOTIMPL);
  const items = references(signedInfo).map((reference): Reference => {
      const target = referenceTarget(reference);
      let digest = child(reference, "DigestMethod");
      if (!digest) {
        digest = createDs(signature, "DigestMethod");
        reference.insertBefore(digest, child(reference, "DigestValue") ?? null);
      }
      if (!digest.getAttribute("Algorithm")) digest.setAttribute("Algorithm", methods.digest);
      let value = child(reference, "DigestValue");
      if (!value) value = reference.appendChild(createDs(signature, "DigestValue"));
      return { ...target, hash: digestMethod(digest.getAttribute("Algorithm")!), value };
    });
  return { signature, references: items, signedInfo, canonicalization, hash };
}

// The canonical bytes of a Reference: same-document references drop comments (XMLDSig, 4.4.3.3), the
// enveloped-signature transform takes this signature out for the moment.
function referenceData(signature: Element, reference: Omit<Reference, "hash" | "value">): string {
  const detach = reference.enveloped && (reference.target === signature.ownerDocument || reference.target.contains(signature));
  const parent = signature.parentNode!;
  const next = signature.nextSibling;
  if (detach) parent.removeChild(signature);
  try {
    return canonicalize(reference.target, reference.canonicalization, reference.prefixes, false);
  } finally {
    if (detach) parent.insertBefore(signature, next);
  }
}

// Fills KeyInfo with the certificate unless the template put something there (the real plug-in's rule).
function fillKeyInfo(signature: Element, certificate: string) {
  let keyInfo = child(signature, "KeyInfo");
  if (keyInfo && Array.from(keyInfo.childNodes).some((node) => node.nodeType === Node.ELEMENT_NODE || (node.nodeType === Node.TEXT_NODE && node.textContent!.trim()))) return;
  if (!keyInfo) {
    keyInfo = createDs(signature, "KeyInfo");
    const value = child(signature, "SignatureValue")!;
    signature.insertBefore(keyInfo, value.nextSibling);
    signature.insertBefore(signature.ownerDocument.createTextNode("\n"), keyInfo);
  }
  const data = keyInfo.appendChild(createDs(signature, "X509Data"));
  keyInfo.insertBefore(signature.ownerDocument.createTextNode("\n"), data);
  keyInfo.appendChild(signature.ownerDocument.createTextNode("\n"));
  const x509 = data.appendChild(createDs(signature, "X509Certificate"));
  data.insertBefore(signature.ownerDocument.createTextNode("\n"), x509);
  data.appendChild(signature.ownerDocument.createTextNode("\n"));
  x509.textContent = wrap(certificate);
}

// The signature the real plug-in writes for the enveloped and enveloping types, as a template.
function signatureTemplate(id: string, methods: { signature: string; digest: string }, uri: string, transforms: string[], object: string): string {
  const transformLines = transforms.map((algorithm) => `<Transform Algorithm="${algorithm}"/>\n`).join("");
  return (
    `<Signature xmlns="${DS}" Id="Signature1-${id}">\n<SignedInfo>\n<CanonicalizationMethod Algorithm="${EXC_C14N}"/>\n` +
    `<SignatureMethod Algorithm="${methods.signature}"/>\n<Reference URI="${uri}">\n<Transforms>\n${transformLines}</Transforms>\n` +
    `<DigestMethod Algorithm="${methods.digest}"/>\n<DigestValue></DigestValue>\n</Reference>\n</SignedInfo>\n` +
    `<SignatureValue></SignatureValue>\n<KeyInfo></KeyInfo>\n${object}</Signature>`
  );
}

// Checks one ds:Signature as the real plug-in's Verify does: the references' digests and the signature with
// the key of the certificate in KeyInfo; neither the chain nor revocation.
function verifySignature(signature: Element): VerifiedSignature {
  const text = child(signature, "KeyInfo")?.getElementsByTagNameNS(DS, "X509Certificate")[0]?.textContent ?? "";
  const der = base64Bytes(text);
  let certificate: X509;
  try {
    certificate = parseCertificate(der!);
  } catch {
    throw new CadesError("An error was encountered while processing an XML digital signature.", ERROR_XML_SIGNATURE);
  }
  const signedInfo = child(signature, "SignedInfo");
  const method = signatureMethods.get(signedInfo && child(signedInfo, "SignatureMethod")?.getAttribute("Algorithm") || "");
  if (!signedInfo || !method) throw new CadesError("An error was encountered while processing an XML digital signature.", ERROR_XML_SIGNATURE);
  let valid = method.key === certificate.publicKeyAlgorithm;
  for (const reference of references(signedInfo)) {
    const name = digestMethods.get(child(reference, "DigestMethod")?.getAttribute("Algorithm") ?? "");
    if (!name) throw new CadesError("An error was encountered while processing an XML digital signature.", ERROR_XML_SIGNATURE);
    const expected = base64Bytes(child(reference, "DigestValue")?.textContent ?? "");
    valid &&= same(utf8Digest(name, referenceData(signature, referenceTarget(reference))), expected);
  }
  const canonicalization = child(signedInfo, "CanonicalizationMethod")?.getAttribute("Algorithm") ?? INCLUSIVE_C14N;
  const value = base64Bytes(child(signature, "SignatureValue")?.textContent ?? "");
  valid &&= value !== undefined && verifyHash(certificate, utf8Digest(method.hash, canonicalize(signedInfo, canonicalization, null)), value);
  return { certificate, valid };
}

export class SignedXML {
  readonly #session: Session;
  #content = "";
  #type: number = constants.CADESCOM_XML_SIGNATURE_TYPE_ENVELOPED;
  #signatureMethod: string | undefined;
  #digestMethod: string | undefined;
  #signers: VerifiedSignature[] = [];

  constructor(session: Session) {
    this.#session = session;
  }

  get Content(): Promise<string> {
    return Promise.resolve(this.#content);
  }

  propset_Content(content: unknown): Promise<void> {
    this.#content = String(content);
    return Promise.resolve();
  }

  // SignatureType, SignatureMethod and DigestMethod are write-only in the real plug-in.
  get SignatureType(): Promise<never> {
    return Promise.reject(new CadesError("Not implemented", E_NOTIMPL));
  }

  propset_SignatureType(type: number): Promise<void> {
    this.#type = Number(type);
    return Promise.resolve();
  }

  get SignatureMethod(): Promise<never> {
    return Promise.reject(new CadesError("Not implemented", E_NOTIMPL));
  }

  propset_SignatureMethod(uri: unknown): Promise<void> {
    this.#signatureMethod = String(uri);
    return Promise.resolve();
  }

  get DigestMethod(): Promise<never> {
    return Promise.reject(new CadesError("Not implemented", E_NOTIMPL));
  }

  propset_DigestMethod(uri: unknown): Promise<void> {
    this.#digestMethod = String(uri);
    return Promise.resolve();
  }

  // Empty until Verify, as with the real plug-in, and after Sign.
  get Signers(): Promise<Signers> {
    return Promise.resolve(new Signers(this.#session, this.#signers));
  }

  // Verifies every ds:Signature of the document, or those an XPath names, in the page; the document becomes
  // Content. Every signature checked is a signer, the failed ones marked not valid.
  async Verify(message?: unknown, xpath?: unknown): Promise<void> {
    this.#signers = [];
    const { xml } = decodeContent(typeof message === "string" ? message : "");
    const doc = parse(xml);
    let signatures: Element[];
    if (typeof xpath === "string" && xpath) {
      const result = doc.evaluate(xpath, doc, null, XPathResult.ORDERED_NODE_SNAPSHOT_TYPE, null);
      signatures = Array.from({ length: result.snapshotLength }, (_, i) => result.snapshotItem(i)).filter(
        (node): node is Element => node instanceof Element && node.namespaceURI === DS && node.localName === "Signature",
      );
    } else {
      signatures = Array.from(doc.getElementsByTagNameNS(DS, "Signature"));
    }
    if (signatures.length === 0) throw new CadesError("The data is invalid.", ERROR_INVALID_DATA);
    this.#signers = signatures.map(verifySignature);
    this.#content = serialize(doc, xml);
    if (this.#signers.some((signer) => !signer.valid)) throw new CadesError("Invalid Signature.", NTE_BAD_SIGNATURE);
  }

  async Sign(signer?: unknown, xpath?: unknown): Promise<string> {
    this.#signers = [];
    const type = this.#type;
    // The real plug-in answers an unknown type with an empty string rather than an error.
    if (!typeNames.has(type)) return "";
    const { token } = signerCertificate(signer);
    const keyAlgorithm = token.x509.publicKeyAlgorithm;
    const defaults = defaultMethods.get(keyAlgorithm);
    if (!defaults) throw new CadesError("XML-подпись делается только ключами ГОСТ", NTE_BAD_ALGID);
    const methods = { signature: this.#signatureMethod ?? defaults.signature, digest: this.#digestMethod ?? defaults.digest };
    if (type !== constants.CADESCOM_XML_SIGNATURE_TYPE_TEMPLATE) {
      signatureMethod(methods.signature, keyAlgorithm);
      digestMethod(methods.digest);
    }
    const { xml, base64 } = decodeContent(this.#content);
    const source = parse(xml);
    const id = randomId();
    // The enveloped and enveloping types become templates first, put together in the DOM (which keeps each
    // element's namespace) and reparsed, so the DOM is exactly what the returned text will say.
    let doc: XMLDocument;
    if (type === constants.CADESCOM_XML_SIGNATURE_TYPE_ENVELOPED) {
      const template = parse(signatureTemplate(id, methods, "", [ENVELOPED_SIGNATURE, EXC_C14N], "")).documentElement;
      source.documentElement.appendChild(source.importNode(template, true));
      doc = parse(new XMLSerializer().serializeToString(source));
    } else if (type === constants.CADESCOM_XML_SIGNATURE_TYPE_ENVELOPING) {
      const template = parse(signatureTemplate(id, methods, `#Object1-${id}`, [EXC_C14N], `<Object Id="Object1-${id}"></Object>\n`));
      child(template.documentElement, "Object")!.appendChild(template.importNode(source.documentElement, true));
      doc = parse(new XMLSerializer().serializeToString(template));
    } else {
      doc = source;
    }
    const signatures =
      type === constants.CADESCOM_XML_SIGNATURE_TYPE_TEMPLATE
        ? this.#targets(doc, xpath)
        : Array.from(doc.getElementsByTagNameNS(DS, "Signature")).filter((signature) => signature.getAttribute("Id") === `Signature1-${id}`);
    const pending = signatures.map((signature) => prepare(signature, keyAlgorithm, methods));

    const plugin = this.#session.plugin;
    const deviceId = await findDevice(plugin, token.serial);
    if (deviceId === undefined) throw new CadesError("Рутокен с этим сертификатом не подключён.", SCARD_E_NO_SMARTCARD);
    const request = {
      origin: this.#session.origin,
      action: "просит подписать XML-документ.",
      details: [`XML-подпись ${typeNames.get(type)}, ${xml.length < 1024 ? `${xml.length} символов` : `${(xml.length / 1024).toFixed(1)} КБ`}.`, ...certificateLines(token.x509)],
      confirm: "Подписать",
    };
    await withLogin(this.#session, deviceId, request, async () => {
      const keyId = await plugin.getKeyByCertificate(deviceId, token.certId);
      // One signature after another, in document order: a later one may cover an earlier one.
      for (const item of pending) {
        for (const reference of item.references) {
          reference.value.textContent = wrap(btoa(bytesBinary(utf8Digest(reference.hash, referenceData(item.signature, reference)))));
        }
        const hash = utf8Digest(item.hash, canonicalize(item.signedInfo, item.canonicalization, null));
        const raw = await plugin.rawSign(deviceId, keyId, Array.from(hash, (byte) => byte.toString(16).padStart(2, "0")).join(":"), {});
        let value = child(item.signature, "SignatureValue");
        if (!value) value = item.signature.insertBefore(createDs(item.signature, "SignatureValue"), item.signedInfo.nextSibling);
        value.textContent = wrap(hexToBase64(raw));
        fillKeyInfo(item.signature, derToBase64(token.x509.der));
      }
    });
    const signed = serialize(doc, xml);
    return base64 ? wrap(btoa(utf8Binary(signed))) : signed;
  }

  // The ds:Signature elements to fill: every one without a SignatureValue, or with an empty one, unless the
  // site names them with an XPath (template type only, as in the real plug-in).
  #targets(doc: XMLDocument, xpath: unknown): Element[] {
    let found: Element[];
    if (typeof xpath === "string" && xpath) {
      const result = doc.evaluate(xpath, doc, null, XPathResult.ORDERED_NODE_SNAPSHOT_TYPE, null);
      found = Array.from({ length: result.snapshotLength }, (_, i) => result.snapshotItem(i)).filter((node): node is Element => node instanceof Element);
    } else {
      found = Array.from(doc.getElementsByTagNameNS(DS, "Signature")).filter((signature) => !child(signature, "SignatureValue")?.textContent?.trim());
    }
    if (found.length === 0) throw new CadesError("В документе нет подписи для заполнения", CRYPT_E_NOT_FOUND);
    return found;
  }
}

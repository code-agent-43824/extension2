// Kontur.Plugin's qualified certificate rules (docs/JOURNAL.md, 2026-11-19), as its host 4.15.1 applies them in
// cert.verify {qualified} and in a certificate's `qualified` property: found on the host with certificates made to
// break one rule at a time, in its order (the key's algorithm, the extensions, the subject, its issuer), with its
// messages. A site may switch rules off and the host's hidden ones on (`qualified.rules`); two of those never failed
// on the host (AKI's criticality, O of an individual), and have no message to give, so they never fail here either.
import { children, decodeOid, read } from "../asn1.ts";
import type { X509 } from "../x509.ts";
import { keyUsages } from "./certificate.ts";
import { CERT_TRUST_IS_NOT_TIME_VALID, validationChain } from "../chain.ts";
import type { StoreCertificates } from "../roots.ts";
import { cryptoError, invalidStructure, KonturError } from "./errors.ts";

export interface RuleFailure {
  rule: string;
  message: string;
}

const OID = {
  INN: "1.2.643.3.131.1.1",
  INNLE: "1.2.643.100.4",
  OGRN: "1.2.643.100.1",
  OGRNIP: "1.2.643.100.5",
  SNILS: "1.2.643.100.3",
  CN: "2.5.4.3",
  SN: "2.5.4.4",
  G: "2.5.4.42",
  C: "2.5.4.6",
  S: "2.5.4.8",
  O: "2.5.4.10",
};

// The state CAs whose OGRN a legal entity's certificate must be issued under (the host's list: the Federal Tax
// Service, the Federal Treasury, the Bank of Russia).
const STATE_CAS = new Set(["1047707030513", "1047797019830", "1037700013020"]);

const GOST_2001 = "1.2.643.2.2.19";

// Every rule the host names; off unless a site switches it on: the hidden ones.
const RULES = [
  "extensions.exist", "extensions.keyUsages.exist", "extensions.keyUsages.valid", "extensions.policies.exist", "extensions.policies.valid",
  "extensions.authorityKeyIdentifier.exist", "extensions.authorityKeyIdentifier.not.critical", "extensions.authorityKeyIdentifier.valid",
  "extensions.issuerSignTool.exist", "extensions.issuerSignTool.valid", "extensions.subjectSignTool.exist", "extensions.subjectSignTool.valid",
  "extensions.identificationKind.exist", "extensions.identificationKind.valid", "extensions.crlDistributionPoint.exist",
  "extensions.privateKeyUsagePeriod.exist", "extensions.privateKeyUsagePeriod.complete", "issuer.ogrn.valid.legalPersonal", "publicKey.algorithm.actual",
  "subject.c.exist.legal", "subject.cn.exist", "subject.g.exist", "subject.inn.exist", "subject.inn.length", "subject.inn.not.exist.legal", "subject.inn.numeric",
  "subject.innle.exist", "subject.innle.length", "subject.innle.numeric", "subject.o.exist.legal", "subject.o.not.exist.individual", "subject.ogrn.exist.legal",
  "subject.ogrn.length.legal", "subject.ogrn.not.exist.individual", "subject.ogrn.numeric.legal", "subject.ogrn.valid.legal", "subject.ogrnip.exist",
  "subject.ogrnip.length", "subject.ogrnip.not.exist.legal", "subject.ogrnip.numeric", "subject.ogrnip.valid", "subject.s.exist.legal", "subject.sn.exist",
  "subject.snils.exist", "subject.snils.length", "subject.snils.numeric", "subject.type.valid",
];
const HIDDEN = new Set(["extensions.keyUsages.valid", "extensions.authorityKeyIdentifier.not.critical", "subject.inn.not.exist.legal", "subject.ogrn.valid.legal", "subject.o.not.exist.individual", "subject.ogrnip.valid"]);
// The two the host will not let a site switch either way.
const FIXED = new Set(["extensions.exist", "subject.type.valid"]);

export type RuleSwitches = Record<string, boolean>;
const enabled = (switches: RuleSwitches, rule: string) => switches[rule] ?? !HIDDEN.has(rule);

function attribute(name: X509["subject"], oid: string): string | undefined {
  return name.flat().find((entry) => entry.oid === oid)?.value;
}

const missing = (name: string) => `Расширение "${name}" отсутствует`;

function extensionValue(x509: X509, oid: string): Uint8Array | undefined {
  return x509.extensions.find((extension) => extension.oid === oid)?.value;
}

// The certificate has an extensions field at all ([3] in the TBS), even an empty one.
function hasExtensionsField(x509: X509): boolean {
  return children(read(x509.tbs)).some((node) => node.tag === 0xa3);
}

const policyLevel = /^1\.2\.643\.100\.113\.([1-6])$/;

function extensionFailures(x509: X509, switches: RuleSwitches): RuleFailure[] {
  const failures: RuleFailure[] = [];
  const fail = (rule: string, message: string) => {
    if (enabled(switches, rule)) failures.push({ rule, message });
  };
  const usage = extensionValue(x509, "2.5.29.15");
  if (!usage) fail("extensions.keyUsages.exist", missing("Использование ключа"));
  // Read as the host reads the bits (certificate.ts).
  else if (!keyUsages(usage).nonRepudiation) fail("extensions.keyUsages.valid", 'Требуется наличие бита "Неотрекаемость"');
  const policies = extensionValue(x509, "2.5.29.32");
  if (!policies) fail("extensions.policies.exist", missing("Политики сертификата"));
  else {
    const levels = new Set(children(read(policies)).map((policy) => Number(policyLevel.exec(decodeOid(children(policy)[0]!.value))?.[1] ?? 0)).filter(Boolean));
    if (!levels.has(1)) fail("extensions.policies.valid", "Отсутствует обязательная политика 1.2.643.100.113.1");
    else if (levels.size !== Math.max(...levels)) fail("extensions.policies.valid", "Некорректный набор политик");
  }
  const authority = extensionValue(x509, "2.5.29.35");
  if (!authority) fail("extensions.authorityKeyIdentifier.exist", missing("Идентификатор ключа центра сертификатов"));
  else if (!children(read(authority)).some((node) => node.tag === 0x82)) fail("extensions.authorityKeyIdentifier.valid", 'Отсутствует атрибут "Серийный номер сертификата"');
  const issuerTool = extensionValue(x509, "1.2.643.100.112");
  const issuerToolName = "Средство электронной подписи и УЦ создателя";
  if (!issuerTool) fail("extensions.issuerSignTool.exist", missing(issuerToolName));
  else {
    const lines = children(read(issuerTool)).map((node) => Array.from(new TextDecoder().decode(node.value)).length);
    if (lines.length !== 4) fail("extensions.issuerSignTool.valid", `Расширение "${issuerToolName}" содержит неверное количество строк`);
    else if (lines.some((length, index) => length < 1 || length > (index < 2 ? 200 : 100))) fail("extensions.issuerSignTool.valid", `Расширение "${issuerToolName}" содержит строку неверной длины`);
  }
  const subjectTool = extensionValue(x509, "1.2.643.100.111");
  const subjectToolName = "Средство подписи владельца сертификата";
  if (!subjectTool) fail("extensions.subjectSignTool.exist", missing(subjectToolName));
  else {
    const length = Array.from(new TextDecoder().decode(read(subjectTool).value)).length;
    if (length < 1 || length > 200) fail("extensions.subjectSignTool.valid", `Расширение "${subjectToolName}" содержит строку неверной длины`);
  }
  const kind = extensionValue(x509, "1.2.643.100.114");
  const kindName = "Идентификация заявителя сертификата";
  if (!kind) fail("extensions.identificationKind.exist", missing(kindName));
  else {
    const node = read(kind);
    const value = node.value.reduce((sum, byte) => sum * 256 + byte, 0);
    if (node.tag !== 0x02 || value > 3) fail("extensions.identificationKind.valid", `Расширение "${kindName}" содержит неверный идентификатор`);
  }
  if (!extensionValue(x509, "2.5.29.31")) fail("extensions.crlDistributionPoint.exist", missing("Точка распределения списка отзыва"));
  const period = extensionValue(x509, "2.5.29.16");
  if (!period) fail("extensions.privateKeyUsagePeriod.exist", missing("Срок действия ключа ЭП"));
  else {
    const tags = children(read(period)).map((node) => node.tag);
    if (!tags.includes(0x80) || !tags.includes(0x81)) fail("extensions.privateKeyUsagePeriod.complete", 'Расширение "Срок действия ключа ЭП" не содержит начало и/или конец срока');
  }
  return failures;
}

type Kind = "individual" | "entrepreneur" | "legal";

function subjectFailures(x509: X509, kind: Kind, switches: RuleSwitches): RuleFailure[] {
  const failures: RuleFailure[] = [];
  const fail = (rule: string, message: string) => {
    if (enabled(switches, rule)) failures.push({ rule, message });
  };
  const value = (oid: string) => attribute(x509.subject, oid);
  // A number attribute: missing (when required), then its length and its digits, each its own failure.
  const number = (oid: string, label: string, digits: number, rule: string, required: boolean, suffix = "") => {
    const text = value(oid);
    if (text === undefined) {
      if (required) fail(`subject.${rule}.exist${suffix}`, `В имени субъекта ${rule === "inn" || rule === "innle" || rule === "snils" ? `не указан атрибут ${label}` : `атрибут ${label} не указан`}`);
      return;
    }
    if (Array.from(text).length !== digits) fail(`subject.${rule}.length${suffix}`, `В имени субъекта длина атрибута ${label} должна быть ${digits} цифр`);
    if (!/^[0-9]*$/.test(text)) fail(`subject.${rule}.numeric${suffix}`, `В имени субъекта атрибут ${label} должен состоять только из чисел`);
  };
  const present = (oid: string, rule: string, label: string) => {
    if (value(oid) === undefined) fail(rule, `В имени субъекта атрибут ${label} не указан`);
  };
  // All zeros, a hidden rule of OGRN and OGRNIP.
  const zeros = (oid: string, rule: string, label: string) => {
    if (/^0+$/.test(value(oid) ?? "")) fail(rule, `В имени субъекта атрибут ${label} имеет неверный формат. Ошибка: не может состоять из одних нулей`);
  };
  if (kind === "legal") number(OID.INNLE, "ИННЮЛ", 10, "innle", true);
  if (kind === "legal" && enabled(switches, "subject.inn.not.exist.legal") && value(OID.INN) !== undefined) {
    fail("subject.inn.not.exist.legal", "В имени субъекта присутствие атрибута ИНН недопустимо для юридических лиц");
  } else number(OID.INN, "ИНН", 12, "inn", kind === "entrepreneur");
  number(OID.SNILS, "СНИЛС", 11, "snils", true);
  present(OID.SN, "subject.sn.exist", "SN");
  present(OID.G, "subject.g.exist", "G");
  present(OID.CN, "subject.cn.exist", "CN");
  if (kind === "legal") {
    number(OID.OGRN, "ОГРН", 13, "ogrn", true, ".legal");
    zeros(OID.OGRN, "subject.ogrn.valid.legal", "ОГРН");
    present(OID.C, "subject.c.exist.legal", "C");
    present(OID.S, "subject.s.exist.legal", "S");
    present(OID.O, "subject.o.exist.legal", "O");
    if (value(OID.OGRNIP) !== undefined) fail("subject.ogrnip.not.exist.legal", "В имени субъекта наличие атрибута ОГРНИП недопустимо");
  } else if (value(OID.OGRN) !== undefined) fail("subject.ogrn.not.exist.individual", "В имени субъекта наличие атрибута ОГРН недопустимо");
  if (kind === "entrepreneur") {
    number(OID.OGRNIP, "ОГРНИП", 15, "ogrnip", true);
    zeros(OID.OGRNIP, "subject.ogrnip.valid", "ОГРНИП");
  }
  return failures;
}

// The rules a certificate breaks, in the host's order; none for a qualified one.
export function qualificationFailures(x509: X509, switches: RuleSwitches = {}): RuleFailure[] {
  const failures: RuleFailure[] = [];
  if (x509.publicKeyAlgorithm === GOST_2001 && enabled(switches, "publicKey.algorithm.actual")) {
    failures.push({ rule: "publicKey.algorithm.actual", message: "Алгоритм публичного ключа ГОСТ Р 34.10-2001 нельзя использовать с 01.01.2020" });
  }
  if (hasExtensionsField(x509)) failures.push(...extensionFailures(x509, switches));
  else failures.push({ rule: "extensions.exist", message: "Отсутствуют расширения сертификата" });
  const has = (oid: string) => attribute(x509.subject, oid) !== undefined;
  const kind: Kind | undefined = has(OID.INNLE) ? "legal" : has(OID.OGRNIP) ? "entrepreneur" : has(OID.INN) ? "individual" : undefined;
  if (!kind) {
    failures.push({ rule: "subject.type.valid", message: "Отсутствуют атрибуты для определения типа сертификата (ИНН, ИННЮЛ или ОГРНИП)" });
    return failures;
  }
  failures.push(...subjectFailures(x509, kind, switches));
  // A legal entity's certificate with its person (SNILS, SN and G, whatever they hold): only a state CA issues those.
  const withPerson = [OID.SNILS, OID.SN, OID.G].every(has);
  if (kind === "legal" && withPerson && enabled(switches, "issuer.ogrn.valid.legalPersonal") && !STATE_CAS.has(attribute(x509.issuer, OID.OGRN) ?? "")) {
    failures.push({ rule: "issuer.ogrn.valid.legalPersonal", message: "ОГРН издателя сертификата ЮЛ с ФЛ не входит в список государственных УЦ" });
  }
  return failures;
}

export const isQualified = (x509: X509) => qualificationFailures(x509).length === 0;

const isObject = (value: unknown): value is Record<string, unknown> => typeof value === "object" && value !== null && !Array.isArray(value);
const jsonType = (value: unknown) => (value === null ? "null" : Array.isArray(value) ? "array" : typeof value);

// cert.verify's options, checked before the certificate is looked at: `qualified` true or {log?: boolean}, `rules`
// inside it refused; the host's own words for a log that is not a boolean (no type, no code).
export function checkVerifyOptions(request: Record<string, unknown>): void {
  const qualified = request.qualified;
  if (qualified !== undefined && typeof qualified !== "boolean" && !isObject(qualified)) throw invalidStructure();
  if (isObject(qualified)) {
    if (qualified.log !== undefined && typeof qualified.log !== "boolean") {
      throw new KonturError({ message: `[json.exception.type_error.302] type must be boolean, but is ${jsonType(qualified.log)}` } as never);
    }
    ruleSwitches(qualified.rules);
  }
  if (request.trustStatus !== undefined && typeof request.trustStatus !== "number") throw invalidStructure();
}

// `qualified.rules`: {<rule>: boolean}; an empty array the host takes as none.
function ruleSwitches(rules: unknown): RuleSwitches {
  if (rules === undefined || (Array.isArray(rules) && rules.length === 0)) return {};
  if (!isObject(rules)) throw invalidStructure();
  for (const [rule, on] of Object.entries(rules)) {
    if (!RULES.includes(rule)) throw new KonturError({ message: "invalid enumeration value" } as never);
    if (typeof on !== "boolean") throw invalidStructure();
    if (FIXED.has(rule)) throw cryptoError(301, "unassignable qualified rule value");
  }
  return rules as RuleSwitches;
}

// The CERT_TRUST_* error status CryptoAPI gives a chain, here from the chain to the extension's root store as
// Certificate.IsValid() of the CryptoPro emulation builds it (the owner, 2026-11-19): with the options page's
// "extended validity" switch off, the certificate's dates alone; on, the chain to the enabled roots through the
// enabled intermediates, an end without an issuer CERT_TRUST_IS_PARTIAL_CHAIN. Revocation is not checked (the owner,
// 2026-09-24), so none of its bits is ever set.
export const CERT_TRUST_IS_PARTIAL_CHAIN = 0x10000;

export function trustStatus(x509: X509, store: StoreCertificates, at = Date.now()): number {
  if (!store.extendedValidity) return x509.notBefore.getTime() <= at && at <= x509.notAfter.getTime() ? 0 : CERT_TRUST_IS_NOT_TIME_VALID;
  const chain = validationChain(x509, store.intermediates, store.roots, at);
  const status = chain.statuses.reduce((all, one) => all | one, 0);
  const last = chain.certificates.at(-1)!;
  const ended = store.roots.some((root) => root.thumbprint === last.thumbprint) || last.subjectDer.length === last.issuerDer.length && last.subjectDer.every((byte, i) => byte === last.issuerDer[i]);
  return status | (ended ? 0 : CERT_TRUST_IS_PARTIAL_CHAIN);
}

// cert.verify for a certificate in hand: {trustStatus: <the site's mask>, qualified: true | {log, rules}}, as Kontur's
// client asks ({trustStatus: 487, qualified: {log: true}}). The answer: ok when no bit of the mask is in the chain's
// status and no qualified rule fails, the chain's status as trustStatus, the failures when asked to log them. The
// host under Linux cannot check trust without CryptoPro and answers "CryptoPro module not loaded"; here the owner
// chose the CryptoPro emulation's chain instead (2026-11-19). Without either option the host did not answer at all;
// here that is the trust check alone, every bit counting (the agent's choice).
export async function verifyCertificate(request: Record<string, unknown>, x509: X509, store: () => Promise<StoreCertificates>): Promise<unknown> {
  const qualified = request.qualified;
  const qualifiedAsked = qualified === true || (isObject(qualified) && qualified.log !== undefined);
  const trustAsked = request.trustStatus !== undefined || !qualifiedAsked;
  const answer: Record<string, unknown> = {};
  let ok = true;
  if (trustAsked) {
    const status = trustStatus(x509, await store());
    const mask = typeof request.trustStatus === "number" ? request.trustStatus : 0xffffffff;
    answer.trustStatus = status;
    if ((status & mask) !== 0) ok = false;
  }
  if (qualifiedAsked) {
    const failures = qualificationFailures(x509, isObject(qualified) ? ruleSwitches(qualified.rules) : {});
    if (failures.length) ok = false;
    if (isObject(qualified) && qualified.log === true) answer.errors = failures;
  }
  answer.ok = ok;
  return answer;
}

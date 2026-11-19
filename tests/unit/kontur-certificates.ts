// Certificates made from the stand user's copy (tests/fixtures/stand-user.pem) with a chosen subject, issuer, key and
// extensions, each breaking Kontur.Plugin's qualified rules one way, with the rules the host 4.15.1 named for it
// (docs/JOURNAL.md, 2026-11-19). The signature is left as it is: the rules do not check it. kontur.test.ts checks the
// extension against these answers; kontur-reference.spec.ts against the host itself, messages included.
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { repoRoot } from "../../scripts/fetch-vendor.ts";
import { children, encode, encodeOid, read } from "../../src/page/asn1.ts";
import { pemToDer } from "../../src/page/x509.ts";

const base = pemToDer(readFileSync(join(repoRoot, "tests", "fixtures", "stand-user.pem"), "utf8"));

const oid = (dotted: string) => encode(0x06, encodeOid(dotted));
const seq = (...parts: Uint8Array[]) => encode(0x30, ...parts);
const text = (tag: number, value: string) => encode(tag, tag === 0x0c ? new TextEncoder().encode(value) : Uint8Array.from(value, (char) => char.charCodeAt(0)));
const NUMERIC = new Set(["1.2.643.100.1", "1.2.643.100.3", "1.2.643.100.4", "1.2.643.100.5", "1.2.643.3.131.1.1"]);

type Attribute = [string, string];
type Extension = [string, Uint8Array, boolean?];

function name(attributes: Attribute[]): Uint8Array {
  return seq(...attributes.map(([type, value]) => encode(0x31, seq(oid(type), text(type === "2.5.4.6" ? 0x13 : NUMERIC.has(type) ? 0x12 : 0x0c, value)))));
}

// The certificate's DER: the user's, with these parts in place of its own; no extensions field when `extensions` is
// null.
export function certificate(subject: Attribute[], issuer: Attribute[], extensions: Extension[] | null, keyAlgorithm?: Uint8Array): Uint8Array {
  const [tbs, algorithm, signature] = children(read(base));
  const parts = children(tbs!).map((part) => part.der);
  parts[3] = name(issuer);
  parts[5] = name(subject);
  if (keyAlgorithm) parts[6] = seq(keyAlgorithm, children(read(parts[6]!))[1]!.der);
  const fields = parts.slice(0, 7);
  if (extensions) fields.push(encode(0xa3, seq(...extensions.map(([type, value, critical]) => seq(oid(type), ...(critical ? [encode(0x01, Uint8Array.of(0xff))] : []), encode(0x04, value))))));
  return seq(seq(...fields), algorithm!.der, signature!.der);
}

const utf8 = (value: string) => text(0x0c, value);
const time = (value: string) => Uint8Array.from(value, (char) => char.charCodeAt(0));
const ku = (bits: number[]): Extension => ["2.5.29.15", encode(0x03, Uint8Array.of(0, bits.reduce((sum, bit) => sum | (0x80 >> bit), 0))), true];
const policies = (...levels: (number | string)[]): Extension => ["2.5.29.32", seq(...levels.map((level) => seq(oid(typeof level === "number" ? `1.2.643.100.113.${level}` : level))))];
const aki = (serial = true, issuer = true, critical = false): Extension => [
  "2.5.29.35",
  seq(encode(0x80, Uint8Array.of(1, 2, 3, 4)), ...(issuer ? [encode(0xa1, encode(0xa4, name([["2.5.4.3", "CA"]])))] : []), ...(serial ? [encode(0x82, Uint8Array.of(1))] : [])),
  critical,
];
const issuerTool = (...lines: string[]): Extension => ["1.2.643.100.112", seq(...lines.map(utf8))];
const subjectTool = (line: string): Extension => ["1.2.643.100.111", utf8(line)];
const identificationKind = (kind: number): Extension => ["1.2.643.100.114", encode(0x02, Uint8Array.of(kind))];
const cdp: Extension = ["2.5.29.31", seq(seq(encode(0xa0, encode(0xa0, text(0x86, "http://ca.example/crl.crl")))))];
const period = (from = true, to = true): Extension => ["2.5.29.16", seq(...(from ? [encode(0x80, time("20260101000000Z"))] : []), ...(to ? [encode(0x81, time("20270101000000Z"))] : []))];

const FULL: Extension[] = [ku([0, 1]), policies(1), aki(), issuerTool("a", "b", "c", "d"), subjectTool("tool"), identificationKind(0), cdp, period()];
const swap = (index: number, extension: Extension) => FULL.map((each, i) => (i === index ? extension : each));
const drop = (index: number) => FULL.filter((_, i) => i !== index);

const CN = "2.5.4.3", SN = "2.5.4.4", G = "2.5.4.42", C = "2.5.4.6", S = "2.5.4.8", L = "2.5.4.7", O = "2.5.4.10", STREET = "2.5.4.9";
const OGRN = "1.2.643.100.1", SNILS = "1.2.643.100.3", INNLE = "1.2.643.100.4", OGRNIP = "1.2.643.100.5", INN = "1.2.643.3.131.1.1";
const ISSUER: Attribute[] = [[C, "RU"], [O, "УЦ"], [CN, "УЦ"], [OGRN, "1027700132195"], [INNLE, "7707083893"]];
const PERSON: Attribute[] = [[CN, "Иванов Иван Иванович"], [SN, "Иванов"], [G, "Иван Иванович"], [C, "RU"], [S, "77 Москва"], [SNILS, "12345678901"], [INN, "123456789012"]];
const LEGAL: Attribute[] = [[CN, "ООО Ромашка"], [O, "ООО Ромашка"], [C, "RU"], [S, "77 Москва"], [L, "Москва"], [STREET, "ул. 1"], [INNLE, "7707083893"], [OGRN, "1027700132195"], [SNILS, "12345678901"], [SN, "Иванов"], [G, "Иван"]];
const IP: Attribute[] = [[CN, "ИП Иванов"], [SN, "Иванов"], [G, "Иван"], [C, "RU"], [S, "77 Москва"], [SNILS, "12345678901"], [INN, "123456789012"], [OGRNIP, "304500116000157"]];
const without = (attributes: Attribute[], ...types: string[]) => attributes.filter(([type]) => !types.includes(type));
const set = (attributes: Attribute[], type: string, value: string): Attribute[] => [...without(attributes, type), [type, value]];
const FNS = set(ISSUER, OGRN, "1047707030513");
const GOST_2001 = seq(oid("1.2.643.2.2.19"), seq(oid("1.2.643.2.2.35.1"), oid("1.2.643.2.2.30.1")));
const GOST_512 = seq(oid("1.2.643.7.1.1.1.2"), seq(oid("1.2.643.7.1.2.1.2.1"), oid("1.2.643.7.1.1.2.3")));

export interface QualifiedCase {
  label: string;
  der: Uint8Array;
  // The rules the host named, in its order; none for a qualified certificate.
  rules: string[];
}

const make = (label: string, subject: Attribute[], issuer: Attribute[], extensions: Extension[] | null, rules: string[], key?: Uint8Array): QualifiedCase => ({
  label,
  der: certificate(subject, issuer, extensions, key),
  rules,
});

const LEGAL_PERSON = ["subject.snils.exist", "subject.sn.exist", "subject.g.exist"];

export const QUALIFIED_CASES: QualifiedCase[] = [
  make("a qualified individual", PERSON, ISSUER, FULL, []),
  make("without extensions", PERSON, ISSUER, null, ["extensions.exist"]),
  make("with an empty extensions field", PERSON, ISSUER, [], ["extensions.keyUsages.exist", "extensions.policies.exist", "extensions.authorityKeyIdentifier.exist", "extensions.issuerSignTool.exist", "extensions.subjectSignTool.exist", "extensions.identificationKind.exist", "extensions.crlDistributionPoint.exist", "extensions.privateKeyUsagePeriod.exist"]),
  make("an empty subject", [], ISSUER, FULL, ["subject.type.valid"]),
  make("no extensions, no CN", without(PERSON, CN), ISSUER, null, ["extensions.exist", "subject.cn.exist"]),
  make("a GOST 2001 key", PERSON, ISSUER, drop(7), ["publicKey.algorithm.actual", "extensions.privateKeyUsagePeriod.exist"], GOST_2001),
  make("a 512-bit key", PERSON, ISSUER, FULL, [], GOST_512),
  make("an individual without CN, SN and G", without(PERSON, CN, SN, G), ISSUER, FULL, ["subject.sn.exist", "subject.g.exist", "subject.cn.exist"]),
  make("an individual without C and S", without(PERSON, C, S), ISSUER, FULL, []),
  make("an individual without SNILS", without(PERSON, SNILS), ISSUER, FULL, ["subject.snils.exist"]),
  make("an individual without INN", without(PERSON, INN), ISSUER, FULL, ["subject.type.valid"]),
  make("bad INN and SNILS, OGRN", set(set(set(PERSON, INN, "1234"), SNILS, "12x"), OGRN, "1"), ISSUER, FULL, ["subject.inn.length", "subject.snils.length", "subject.snils.numeric", "subject.ogrn.not.exist.individual"]),
  make("INN of 11 with a letter", set(PERSON, INN, "12345678901a"), ISSUER, FULL, ["subject.inn.numeric"]),
  make("an individual with O", [...PERSON, [O, "Org"]], ISSUER, FULL, []),
  make("an individual's INN of zeros", set(PERSON, INN, "000000000000"), ISSUER, FULL, []),
  make("a legal entity under a commercial CA", LEGAL, ISSUER, FULL, ["issuer.ogrn.valid.legalPersonal"]),
  make("a legal entity under the FNS", LEGAL, FNS, FULL, []),
  make("a legal entity under the Treasury", LEGAL, set(ISSUER, OGRN, "1047797019830"), FULL, []),
  make("a legal entity under an issuer without OGRN", LEGAL, without(ISSUER, OGRN), FULL, ["issuer.ogrn.valid.legalPersonal"]),
  make("a legal entity without the person", without(LEGAL, SNILS, SN, G), FNS, FULL, LEGAL_PERSON),
  make("a legal entity without O, C, S, OGRN", without(LEGAL, O, C, S, OGRN), FNS, FULL, ["subject.ogrn.exist.legal", "subject.c.exist.legal", "subject.s.exist.legal", "subject.o.exist.legal"]),
  make("a legal entity with OGRNIP and INN of 10", [...LEGAL, [OGRNIP, "304500116000157"], [INN, "7707083893"]], FNS, FULL, ["subject.inn.length", "subject.ogrnip.not.exist.legal"]),
  make("a legal entity with INN of 12", [...LEGAL, [INN, "123456789012"]], FNS, FULL, []),
  make("bad INNLE and OGRN", set(set(LEGAL, INNLE, "12x"), OGRN, "1x"), FNS, FULL, ["subject.innle.length", "subject.innle.numeric", "subject.ogrn.length.legal", "subject.ogrn.numeric.legal"]),
  make("OGRN of zeros, a wrong checksum", set(LEGAL, OGRN, "0000000000000"), FNS, FULL, []),
  make("an entrepreneur", IP, ISSUER, FULL, []),
  make("an entrepreneur without INN and SN, with OGRN", set(without(IP, INN, SN), OGRN, "1"), ISSUER, FULL, ["subject.inn.exist", "subject.sn.exist", "subject.ogrn.not.exist.individual"]),
  make("an entrepreneur's OGRNIP of 14 with a letter", set(IP, OGRNIP, "3045001160001x"), ISSUER, FULL, ["subject.ogrnip.length", "subject.ogrnip.numeric"]),
  make("only INNLE", [[INNLE, "7707083893"]], ISSUER, FULL, [...LEGAL_PERSON, "subject.cn.exist", "subject.ogrn.exist.legal", "subject.c.exist.legal", "subject.s.exist.legal", "subject.o.exist.legal"]),
  make("a legal entity without SN under a commercial CA", without(LEGAL, SN), ISSUER, FULL, ["subject.sn.exist"]),
  make("a legal entity with a bad SNILS under a commercial CA", set(LEGAL, SNILS, "1"), ISSUER, FULL, ["subject.snils.length", "issuer.ogrn.valid.legalPersonal"]),
  make("key usage without non-repudiation", PERSON, ISSUER, swap(0, ku([0])), []),
  make("policy KC2 alone", PERSON, ISSUER, swap(1, policies(2)), ["extensions.policies.valid"]),
  make("policies KC1 and KB2", PERSON, ISSUER, swap(1, policies(1, 5)), ["extensions.policies.valid"]),
  make("policies KC1 to KA1, another one", PERSON, ISSUER, swap(1, policies(6, 5, 4, 3, 2, 1, "1.2.3.4")), []),
  make("AKI without the serial number", PERSON, ISSUER, swap(2, aki(false)), ["extensions.authorityKeyIdentifier.valid"]),
  make("a critical AKI without the issuer", PERSON, ISSUER, swap(2, aki(true, false, true)), []),
  make("three lines of the CA's tools", PERSON, ISSUER, swap(3, issuerTool("a", "b", "c")), ["extensions.issuerSignTool.valid"]),
  make("an empty line of the CA's tools", PERSON, ISSUER, swap(3, issuerTool("a", "b", "", "d")), ["extensions.issuerSignTool.valid"]),
  make("long lines of the CA's tools", PERSON, ISSUER, swap(3, issuerTool("я".repeat(200), "b".repeat(200), "c".repeat(100), "d".repeat(100))), []),
  make("a line of 101 among the CA's tools", PERSON, ISSUER, swap(3, issuerTool("a", "b", "c", "я".repeat(101))), ["extensions.issuerSignTool.valid"]),
  make("an owner's tool of 201", PERSON, ISSUER, swap(4, subjectTool("a".repeat(201))), ["extensions.subjectSignTool.valid"]),
  make("an empty owner's tool", PERSON, ISSUER, swap(4, subjectTool("")), ["extensions.subjectSignTool.valid"]),
  make("identification kind 3", PERSON, ISSUER, swap(5, identificationKind(3)), []),
  make("identification kind 4", PERSON, ISSUER, swap(5, identificationKind(4)), ["extensions.identificationKind.valid"]),
  make("a key usage period without its end", PERSON, ISSUER, swap(7, period(true, false)), ["extensions.privateKeyUsagePeriod.complete"]),
];

// The hidden rules switched on, and some others off: what the host answered for these.
export const HIDDEN_ON = {
  "extensions.keyUsages.valid": true,
  "extensions.authorityKeyIdentifier.not.critical": true,
  "subject.inn.not.exist.legal": true,
  "subject.ogrn.valid.legal": true,
  "subject.o.not.exist.individual": true,
  "subject.ogrnip.valid": true,
  "subject.ogrnip.exist": true,
};
const BROKEN: Extension[] = [ku([0]), policies(2), aki(false, true, true), ...FULL.slice(3)];
export const SWITCH_CASES: (QualifiedCase & { switches: Record<string, boolean> })[] = [
  { ...make("an individual, the hidden rules on", [[SN, "И"], [SNILS, "1"], [INN, "1"], [O, "O"], [OGRN, "0000000000000"]], ISSUER, BROKEN, ["extensions.keyUsages.valid", "extensions.policies.valid", "extensions.authorityKeyIdentifier.valid", "subject.inn.length", "subject.snils.length", "subject.g.exist", "subject.cn.exist", "subject.ogrn.not.exist.individual"]), switches: HIDDEN_ON },
  { ...make("an entrepreneur, the hidden rules on", [[SN, "И"], [SNILS, "1"], [INN, "1"], [O, "O"], [OGRN, "0"], [OGRNIP, "000000000000000"]], ISSUER, BROKEN, ["extensions.keyUsages.valid", "extensions.policies.valid", "extensions.authorityKeyIdentifier.valid", "subject.inn.length", "subject.snils.length", "subject.g.exist", "subject.cn.exist", "subject.ogrn.not.exist.individual", "subject.ogrnip.valid"]), switches: HIDDEN_ON },
  { ...make("a legal entity, the hidden rules on", [[INNLE, "1"], [INN, "1"], [SNILS, "1"], [SN, "И"], [G, "И"], [OGRN, "0000000000000"], [OGRNIP, "1"]], ISSUER, BROKEN, ["extensions.keyUsages.valid", "extensions.policies.valid", "extensions.authorityKeyIdentifier.valid", "subject.innle.length", "subject.inn.not.exist.legal", "subject.snils.length", "subject.cn.exist", "subject.ogrn.valid.legal", "subject.c.exist.legal", "subject.s.exist.legal", "subject.o.exist.legal", "subject.ogrnip.not.exist.legal", "issuer.ogrn.valid.legalPersonal"]), switches: HIDDEN_ON },
  { ...make("a legal entity, its issuer's rule off", [[INNLE, "1"], [INN, "1"], [SNILS, "1"], [SN, "И"], [G, "И"], [OGRN, "0000000000000"], [OGRNIP, "1"]], ISSUER, BROKEN, ["extensions.policies.valid", "extensions.authorityKeyIdentifier.valid", "subject.innle.length", "subject.inn.length", "subject.snils.length", "subject.cn.exist", "subject.c.exist.legal", "subject.s.exist.legal", "subject.o.exist.legal", "subject.ogrnip.not.exist.legal"]), switches: { "issuer.ogrn.valid.legalPersonal": false } },
  { ...make("no CN and key usage, both rules off", without(PERSON, CN), ISSUER, FULL.slice(1), []), switches: { "extensions.keyUsages.exist": false, "subject.cn.exist": false } },
];

// RFC 3161 timestamps for XAdES-T (docs/PLAN.md, action 26): the request page.js builds and the checks of the answer
// the extension brings back from the service (src/page/timestamps.ts). As with CAdES-T, the token's own signature is
// not checked (the owner, docs/PLAN.md, action 25): the service's chain is not at hand.
import { children, decodeOid, encode, encodeOid, expectTag, octets, read, type Node } from "./asn1.ts";
import { parseSignedData } from "./cms.ts";
import type { DigestName } from "./gost.ts";

const TST_INFO = "1.2.840.113549.1.9.16.1.4";

// The hash of the message imprint, by the names src/page/gost.ts gives them.
const hashOids = new Map<DigestName, string>([
  ["streebog256", "1.2.643.7.1.1.2.2"],
  ["streebog512", "1.2.643.7.1.1.2.3"],
  ["gost94", "1.2.643.2.2.9"],
]);

export interface TimestampRequest {
  // The TimeStampReq.
  der: Uint8Array;
  hashOid: string;
  hashed: Uint8Array;
  // The nonce's INTEGER contents.
  nonce: Uint8Array;
}

// A positive INTEGER's contents, as short as DER wants them.
function positiveInteger(bytes: Uint8Array): Uint8Array {
  let start = 0;
  while (start < bytes.length - 1 && bytes[start] === 0) start++;
  const value = bytes.subarray(start);
  return value[0]! & 0x80 ? Uint8Array.of(0, ...value) : Uint8Array.from(value);
}

function same(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((byte, i) => byte === b[i]);
}

// TimeStampReq version 1 for a hash made with `hash`, with a nonce from `random` and the service's certificate asked
// for (certReq), so the token carries what checking it later needs.
export function timestampRequest(hash: DigestName, hashed: Uint8Array, random: Uint8Array): TimestampRequest {
  const hashOid = hashOids.get(hash);
  if (!hashOid) throw new Error(`хеш ${hash} не подходит для штампа времени`);
  const nonce = positiveInteger(random);
  const imprint = encode(0x30, encode(0x30, encode(0x06, encodeOid(hashOid))), encode(0x04, hashed));
  const der = encode(0x30, encode(0x02, Uint8Array.of(1)), imprint, encode(0x02, nonce), encode(0x01, Uint8Array.of(0xff)));
  return { der, hashOid, hashed, nonce };
}

// PKIFreeText: UTF8Strings, joined.
function freeText(node: Node | undefined): string {
  if (node?.tag !== 0x30) return "";
  return children(node)
    .map((part) => new TextDecoder().decode(part.value))
    .join("; ");
}

// A non-negative INTEGER's value from its contents.
function unsigned(bytes: Uint8Array): bigint {
  return bytes.reduce((value, byte) => value * 256n + BigInt(byte), 0n);
}

// What a TimeStampResp says, and of its token's TSTInfo what the request is checked against.
interface Answer {
  status: bigint;
  reason: string;
  token?: Uint8Array;
  hashOid?: string;
  hashed?: Uint8Array;
  nonce?: bigint;
}

function parseAnswer(response: Uint8Array): Answer {
  try {
    const [status, token] = children(expectTag(read(response), 0x30, "TimeStampResp"));
    const [code, text] = children(expectTag(status, 0x30, "PKIStatusInfo"));
    const answer: Answer = { status: unsigned(expectTag(code, 0x02, "PKIStatus").value), reason: freeText(text) };
    if (!token) return answer;
    answer.token = Uint8Array.from(token.der);
    const signed = parseSignedData(answer.token);
    if (signed.contentType !== TST_INFO || !signed.content) return answer;
    const fields = children(expectTag(read(signed.content), 0x30, "TSTInfo"));
    const [algorithm, hashed] = children(expectTag(fields[2], 0x30, "messageImprint"));
    answer.hashOid = decodeOid(expectTag(children(expectTag(algorithm, 0x30, "hashAlgorithm"))[0], 0x06, "algorithm").value);
    answer.hashed = octets(hashed!);
    // After genTime come the optional accuracy (SEQUENCE), ordering (BOOLEAN), nonce (INTEGER), tsa and extensions.
    const nonce = fields.slice(5).find((field) => field.tag === 0x02);
    if (nonce) answer.nonce = unsigned(nonce.value);
    return answer;
  } catch {
    throw new Error("ответ службы не разобран как ответ RFC 3161");
  }
}

// The TimeStampToken (a CMS ContentInfo) of a service's TimeStampResp, once it is seen to answer `request`: status
// granted (with or without modifications), a TSTInfo with the same message imprint and the same nonce. Throws an Error
// saying what is wrong.
export function timestampToken(response: Uint8Array, request: TimestampRequest): Uint8Array {
  const answer = parseAnswer(response);
  if (answer.status !== 0n && answer.status !== 1n) throw new Error(`служба отказала, статус ${answer.status}${answer.reason ? `: ${answer.reason}` : ""}`);
  if (!answer.token) throw new Error("в ответе службы нет штампа");
  if (!answer.hashed) throw new Error("в штампе нет TSTInfo");
  if (answer.hashOid !== request.hashOid || !same(answer.hashed, request.hashed)) throw new Error("штамп выдан на другие данные");
  if (answer.nonce !== unsigned(request.nonce)) throw new Error("nonce штампа не тот, что в запросе");
  return answer.token;
}

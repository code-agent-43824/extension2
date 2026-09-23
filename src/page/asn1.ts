// A minimal DER reader: enough to take X.509 certificates apart. Not a general BER parser —
// indefinite lengths and high tag numbers are rejected, which DER certificates never use.

export interface Node {
  tag: number;
  // The whole element (header and contents) and the contents alone, as views into the input.
  der: Uint8Array;
  value: Uint8Array;
}

export function read(input: Uint8Array, offset = 0): Node {
  if (offset + 2 > input.length) throw new Error("DER: truncated header");
  const tag = input[offset]!;
  if ((tag & 0x1f) === 0x1f) throw new Error("DER: high tag numbers are not supported");
  let length = input[offset + 1]!;
  let header = 2;
  if (length & 0x80) {
    const count = length & 0x7f;
    if (count === 0 || count > 4) throw new Error("DER: unsupported length");
    length = 0;
    for (let i = 0; i < count; i++) length = length * 256 + input[offset + 2 + i]!;
    header += count;
  }
  const end = offset + header + length;
  if (end > input.length) throw new Error("DER: truncated contents");
  return { tag, der: input.subarray(offset, end), value: input.subarray(offset + header, end) };
}

export function children(node: Node): Node[] {
  const result: Node[] = [];
  for (let offset = 0; offset < node.value.length; ) {
    const child = read(node.value, offset);
    result.push(child);
    offset += child.der.length;
  }
  return result;
}

export function expectTag(node: Node | undefined, tag: number, what: string): Node {
  if (!node || node.tag !== tag) throw new Error(`DER: ${what} expected`);
  return node;
}

export function decodeOid(value: Uint8Array): string {
  const arcs: number[] = [];
  let current = 0;
  for (const byte of value) {
    current = current * 128 + (byte & 0x7f);
    if (byte & 0x80) continue;
    if (arcs.length === 0) {
      const first = Math.min(2, Math.floor(current / 40));
      arcs.push(first, current - first * 40);
    } else {
      arcs.push(current);
    }
    current = 0;
  }
  return arcs.join(".");
}

export function hex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("").toUpperCase();
}

// UTCTime (tag 0x17; YYMMDDHHMMSSZ, years 1950–2049 as in RFC 5280) or GeneralizedTime
// (YYYYMMDDHHMMSSZ), including implicitly tagged GeneralizedTime such as in PrivateKeyUsagePeriod.
export function decodeTime(node: Node): Date {
  const text = new TextDecoder("latin1").decode(node.value);
  const utc = node.tag === 0x17;
  const match = (utc ? /^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/ : /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/).exec(text);
  if (!match) throw new Error(`DER: unsupported time ${text}`);
  const [y, mo, d, h, mi, s] = match.slice(1).map(Number) as [number, number, number, number, number, number];
  const year = utc ? (y < 50 ? 2000 + y : 1900 + y) : y;
  return new Date(Date.UTC(year, mo - 1, d, h, mi, s));
}

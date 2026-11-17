// Windows-1251, in which IFCPlugin's core turns a key's CKA_ID into the container name sites see (docs/JOURNAL.md,
// 2026-11-17).
const decoder = new TextDecoder("windows-1251");
let table: Map<string, number> | undefined;

export function decodeCp1251(bytes: Uint8Array): string {
  return decoder.decode(bytes);
}

// Undefined when a character has no byte in the code page.
export function encodeCp1251(text: string): Uint8Array | undefined {
  table ??= new Map(Array.from({ length: 256 }, (_, byte) => [decoder.decode(Uint8Array.of(byte)), byte] as const).reverse());
  const bytes: number[] = [];
  for (const char of text) {
    const byte = table.get(char);
    if (byte === undefined) return undefined;
    bytes.push(byte);
  }
  return Uint8Array.from(bytes);
}

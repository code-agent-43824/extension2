// Errors in the shape sites expect from the CryptoPro plug-in: a `message`, and an HRESULT in
// `number` that cadesplugin.getLastError() appends as " (0xXXXXXXXX)".

export class CadesError extends Error {
  readonly number: number;

  constructor(message: string, number: number) {
    super(message);
    this.name = "CadesError";
    this.number = number;
  }
}

// HRESULTs we raise; values are the Windows ones for the same situations.
export const REGDB_E_CLASSNOTREG = 0x80040154;

// Same formatting as decimalToHexString() in cadesplugin_api.js 2.4.5.
function toHex(number: number): string {
  const unsigned = number < 0 ? 0xffffffff + number + 1 : number;
  return unsigned.toString(16).toUpperCase();
}

// Same result as GetMessageFromException() in cadesplugin_api.js 2.4.5: sites parse this text.
export function getLastError(exception: unknown): unknown {
  const e = exception as { message?: unknown; number?: unknown } | null | undefined;
  const message = e?.message;
  if (!message) return exception;
  if (typeof e.number === "number" && e.number) return `${message} (0x${toHex(e.number)})`;
  return message;
}

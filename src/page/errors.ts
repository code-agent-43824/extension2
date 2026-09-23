// Errors in the shape sites expect from the CryptoPro plug-in in Chrome: the HRESULT ends the
// `message` as " (0xXXXXXXXX)" — sites test err.message.includes("0x80092004") (testgost2012's
// certfnsh.asp) — and is also in `number`, which some sites read.

export class CadesError extends Error {
  readonly number: number;

  constructor(text: string, number: number) {
    super(`${text}${suffix(number)}`);
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

function suffix(number: number): string {
  return number ? ` (0x${toHex(number)})` : "";
}

// Same result as GetMessageFromException() in cadesplugin_api.js 2.4.5: sites parse this text. A
// CadesError already carries the code in its message and is not given it twice.
export function getLastError(exception: unknown): unknown {
  const e = exception as { message?: unknown; number?: unknown } | null | undefined;
  const message = e?.message;
  if (!message) return exception;
  if (typeof e.number === "number" && e.number && !String(message).endsWith(suffix(e.number))) return `${message}${suffix(e.number)}`;
  return message;
}

// Kontur.Plugin's errors as its host answers them (docs/JOURNAL.md, 2026-11-19): {type, code, message[, context]},
// the message prefixed with the kind and the code in hex, "PLUGIN[0x00000003] invalid command structure".
import { CadesError } from "../errors.ts";
import { rutokenErrorCode } from "../rutoken.ts";
import { SCARD_W_CANCELLED_BY_USER } from "../token-login.ts";

export interface KonturErrorAnswer {
  type: string;
  code?: number;
  message: string;
  context?: string;
}

const hex = (code: number) => `0x${(code >>> 0).toString(16).toUpperCase().padStart(8, "0")}`;

export class KonturError extends Error {
  readonly answer: KonturErrorAnswer;

  constructor(answer: KonturErrorAnswer) {
    super(answer.message);
    this.answer = answer;
  }

  // Any failure as the host's error: the cancelled PIN window as the host's cancelled one, the rest as a plug-in
  // error with code 0 (no such answer of the host was seen; the agent's choice), the Rutoken Plugin's by its code.
  static of(error: unknown): KonturError {
    if (error instanceof KonturError) return error;
    if (error instanceof CadesError && error.number === SCARD_W_CANCELLED_BY_USER) return notAuthorized();
    const code = rutokenErrorCode(error);
    if (code !== undefined) return pluginError(0, `Rutoken Plugin error ${code}`);
    return pluginError(0, error instanceof Error ? error.message : String(error));
  }
}

export function pluginError(code: number, text: string): KonturError {
  return new KonturError({ type: "plugin", code, message: `PLUGIN[${hex(code)}] ${text}` });
}

export function cryptoError(code: number, text: string, context = ""): KonturError {
  return new KonturError({ type: "crypto", code, context, message: `CRYPTO[${hex(code)}] ${text}` });
}

export const unknownCommand = () => pluginError(2, "unknown command");
export const invalidStructure = () => pluginError(3, "invalid command structure");
export const certificateNotFound = () => pluginError(200, "certificate not found");
// The host's answer when its PIN window is cancelled, a wrong PIN before it included.
export const notAuthorized = () => cryptoError(51, "the pkcs11 session is not authorized");

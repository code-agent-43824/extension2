import { CadesError, REGDB_E_CLASSNOTREG } from "../errors.ts";
import { About } from "./about.ts";
import type { Session } from "./session.ts";

type Factory = (session: Session) => object;

// ProgIDs are case-insensitive in COM, and sites rely on it (the demo page asks for "cadescom.cplicense").
const factories = new Map<string, Factory>([["cadescom.about", (session) => new About(session)]]);

export function createObject(name: string, session: Session): object {
  const factory = factories.get(String(name).toLowerCase());
  if (!factory) throw new CadesError(`Объект ${name} не поддерживается расширением`, REGDB_E_CLASSNOTREG);
  return factory(session);
}

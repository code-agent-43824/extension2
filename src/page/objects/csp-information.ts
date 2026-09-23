import { CadesError } from "../errors.ts";

const E_NOTIMPL = 0x80004001;

// X509Enrollment.CCspInformation, only as far as the demo page's certificate card needs it: the page
// creates it before reading the private key usage period and skips that part if creation fails.
// There is no CSP behind us, so it reports no settings and no containers.
export class CspInformation {
  InitializeFromName(_name: string): Promise<void> {
    return Promise.resolve();
  }

  // Undefined, as in plug-in versions without this property; the page then shows nothing about it.
  get ControlKeyTimeValidity(): Promise<undefined> {
    return Promise.resolve(undefined);
  }

  ContainerByName(name: string): Promise<never> {
    return Promise.reject(new CadesError(`Контейнер ${name} недоступен через Рутокен Плагин`, E_NOTIMPL));
  }
}

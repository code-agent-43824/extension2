import { CSP_VERSION, PLUGIN_VERSION } from "../compat.ts";
import type { Session } from "./session.ts";
import { CadesVersion } from "./version.ts";

// CAdESCOM.About: which plug-in and CSP the site talks to. Versions are the compatibility ones from
// compat.ts; the provider name says honestly that the Rutoken Plugin does the work.
export class About {
  readonly #session: Session;

  constructor(session: Session) {
    this.#session = session;
  }

  get Version(): Promise<string> {
    return Promise.resolve(PLUGIN_VERSION);
  }

  get MajorVersion(): Promise<number> {
    return new CadesVersion(PLUGIN_VERSION).MajorVersion;
  }

  get MinorVersion(): Promise<number> {
    return new CadesVersion(PLUGIN_VERSION).MinorVersion;
  }

  get BuildVersion(): Promise<number> {
    return new CadesVersion(PLUGIN_VERSION).BuildVersion;
  }

  get PluginVersion(): Promise<CadesVersion> {
    return Promise.resolve(new CadesVersion(PLUGIN_VERSION));
  }

  // The real method takes a provider name and type; there is one "provider" here, so both are ignored.
  CSPVersion(_providerName?: string, _providerType?: number): Promise<CadesVersion> {
    return Promise.resolve(new CadesVersion(CSP_VERSION));
  }

  async CSPName(_providerType?: number): Promise<string> {
    return `Rutoken Plugin ${await this.#session.plugin.version}`;
  }
}

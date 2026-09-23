// CAdESCOM.Version as returned by About.PluginVersion and About.CSPVersion(): every member,
// toString() included, answers with a Promise, as in the CryptoPro async API.
export class CadesVersion {
  readonly #major: number;
  readonly #minor: number;
  readonly #build: number;

  constructor(version: string) {
    const parts = version.split(".").map(Number);
    if (parts.length !== 3 || parts.some((part) => !Number.isInteger(part))) {
      throw new Error(`not a major.minor.build version: ${version}`);
    }
    [this.#major, this.#minor, this.#build] = parts as [number, number, number];
  }

  get MajorVersion(): Promise<number> {
    return Promise.resolve(this.#major);
  }

  get MinorVersion(): Promise<number> {
    return Promise.resolve(this.#minor);
  }

  get BuildVersion(): Promise<number> {
    return Promise.resolve(this.#build);
  }

  toString(): Promise<string> {
    return Promise.resolve(`${this.#major}.${this.#minor}.${this.#build}`);
  }
}

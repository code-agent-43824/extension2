import { CadesError } from "../errors.ts";

const E_INVALIDARG = 0x80070057;

// CAdESCOM.CadesTools. CryptoPro's demo pages call only PackageManager() at load, to tell the Android plug-in
// ("-") from the desktop one; plug-in 2.0.15700 on Linux answers "(deb)", the package format it was installed
// from, and an argument is E_INVALIDARG (docs/JOURNAL.md, 2026-09-24). The extension was installed by no package
// manager, so the answer is empty: never "-", which would make a Linux touch-screen machine look like Android.
export class CadesTools {
  async PackageManager(...args: unknown[]): Promise<string> {
    if (args.length > 0) throw new CadesError("The parameter is incorrect.", E_INVALIDARG);
    return "";
  }
}

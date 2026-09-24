// Replaced at build time by esbuild (scripts/build.ts) and in unit tests by vitest.config.ts.
declare const __EXTENSION_VERSION__: string;

// The one xmldsigjs file page.js takes (the alias in scripts/build.ts); the part of its
// build/types/canonicalizer.d.ts in use, as that file cannot be reached past the package's "exports" map.
declare module "xmldsigjs-canonicalizer" {
  export class XmlCanonicalizer {
    constructor(withComments: boolean, excC14N: boolean);
    InclusiveNamespacesPrefixList: string;
    Canonicalize(node: Node): string;
  }
}

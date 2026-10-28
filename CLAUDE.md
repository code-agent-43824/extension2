# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

@AGENTS.md

## Project notes

The `@AGENTS.md` line above imports the shared rules; nothing from them is restated here.

## What this repository is

A Chrome extension that makes sites written for the CryptoPro CAdES Browser plug-in + CryptoPro CSP work through
the Rutoken Plugin, its browser adapter and a Rutoken ECP 2.0/3.0 device instead. The approach, the interception
point and the CAdESCOM-to-CryptoPlugin mapping are in `docs/ANALYSIS.md`; stages in `docs/ROADMAP.md`.

## Commands

- `npm install` — dev dependencies (Playwright uses the browsers in `/opt/pw-browsers`; do not run `playwright install` there).
- `node scripts/fetch-vendor.ts` — download third-party stand files into `vendor/`, verified against
  `scripts/vendor-lock.json`.
- `npm run stand` — fetch vendor files, rebuild `stand/` from scratch (Rutoken Plugin, fake Rutoken, adapter,
  Python venv) and provision the token with a key and a test-CA certificate. Needs network (vendor files, PyPI).
- `npm run build` — build the extension into `dist/extension/` for Chrome (load it unpacked) and `dist/firefox/` for
  Firefox, from the same code.
- `npm run package` — build, then pack both into one archive for installing by hand,
  `dist/cryptopro-via-rutoken-<version>.zip`: a folder with `chrome/` (the unpacked build), `firefox/*.xpi` and
  `README.txt` (installing in each browser, from `src/release-readme.txt`); CI uploads it as the
  `cryptopro-via-rutoken` artifact, and its `release` job publishes a version that has no GitHub release yet as a
  pre-release with it.
- `node scripts/gen-constants.ts` — regenerate `src/page/constants.ts` after pinning a new `cadesplugin_api.js`.
- `npm run check` — typecheck (Node code, then `src/page/` with DOM types, then `src/extension/` with Chrome types)
  and unit tests; must pass before every commit.
- `npm run test:stand` — build, then Playwright tests against the built stand; `npx playwright test -g "<name>"` for one.
- `STAND_ONLINE=1 npx playwright test tests/stand/testgost.spec.ts` — after a build: the opt-in experiment against
  testgost2012.cryptopro.ru (internet through the environment proxy); leaves screenshots in `stand/testgost/`.
- `STAND_ONLINE=1 npx playwright test tests/stand/nalog.spec.ts` — after a build: the opt-in experiment on the FNS
  personal accounts (lkfl2.nalog.ru, lkip2.nalog.ru) with testgost2012 certificates; screenshots in `stand/nalog/`.
- `STAND_ONLINE=1 npx playwright test tests/stand/crpt.spec.ts` — after a build: the opt-in experiment on Честный знак
  (markirovka.crpt.ru) with a testgost2012 certificate, the CryptoPro way; screenshots in `stand/crpt/`.
- `node scripts/setup-cryptopro-csp.ts <dir with .deb files>` (root), then
  `STAND_CRYPTOPRO_CSP=1 npx playwright test tests/stand/with-cryptopro-csp.spec.ts` — the opt-in local experiment with
  the real CryptoPro CSP and plug-in installed into the machine; the packages are licensed, never commit them.
- `STAND_ONLINE=1 npx playwright test tests/stand/webtools.spec.ts -g CAdES-T` — after a build: CAdES-T with CryptoPro's
  test timestamp service (testca2012.cryptopro.ru) besides the stand's own.
- `STAND_ONLINE=1 npx playwright test tests/stand/xades.spec.ts -g CryptoPro` — after a build: XAdES-T with CryptoPro's
  test timestamp service, reached by the extension's service worker.
- `STAND_OPENSSL_GOST=1 npx playwright test tests/stand/openssl-gost.spec.ts tests/stand/enveloped-xml.spec.ts` —
  after a build: the opt-in experiment checking CMS and XML encryption against OpenSSL's GOST engine
  (`apt install libengine-gost-openssl`), both directions.
- `node scripts/import-roots.ts <lsb-cprocsp-ca-certs .deb>` — regenerate `src/extension/builtin-roots.ts` from a new
  CryptoPro CSP release (the package comes with the CSP download, after logging in to CryptoPro's site).
- `npx vitest run tests/unit/crx.test.ts` — a single test file; add `-t "<name>"` for one test.

## Map of the code

- `src/manifest.json` — extension manifest; the build fills in the version, and `firefoxManifest` in
  `scripts/build.ts` makes Firefox's from it (background script, add-on id, minimum version). No static content
  script: page.js is registered at run time for the enabled sites only.
- `src/extension/` — the extension's own side, with Chrome types (`src/extension/tsconfig.json`): `browser.ts` (which
  browser the build is for, `__BROWSER__` from `scripts/build.ts`), `sites.ts` (the
  enabled-site list in `chrome.storage.local`, optional host permissions — in Firefox without the port, its
  patterns with one inject nothing —, the confirmed timestamp services' list, taking access back only when nothing
  listed needs it, registering page.js; Chrome's permission
  prompt can close the popup, so `finishPendingSite` in the service worker finishes an interrupted enabling), `background.ts`
  (service worker keeping the registration in sync and running `install.ts` and `timestamps.ts`), `popup.*` (the button's window), `options.*` (site list, the extended validity and root offer switches, the confirmed timestamp services, certificate stores), `roots.ts` (the two certificate stores in
  `chrome.storage.local`: the built-in roots, and the roots of other CAs and intermediates added from files, a
  self-signed one counting as a root) + `roots-view.ts` (their tabs and cards on the options page) + `roots-bridge.ts`
  (isolated-world content script registered beside page.js, handing it the enabled roots, intermediates and the
  extended validity switch over postMessage, and passing Store.Add and XAdES-T's timestamp requests on to the service
  worker) + `install.ts` (Store.Add in the service worker: a root only after the user's yes in `confirm.*`, the
  extension's own window worded after Windows' root warning) + `timestamps.ts` (XAdES-T's request to a timestamp
  service, posted by the service worker only to the services the user confirmed in `tsa-access.*`, which also makes
  Chrome's permission request; the confirmed ones are kept in `chrome.storage.local`) + `prompt-windows.ts` (the windows both ask their question in) +
  `builtin-roots.ts` (generated by `scripts/import-roots.ts`, do not edit).
- `src/page/` — the MAIN-world content script, bundled into one `page.js`: `main.ts` (entry), `cadesplugin.ts`
  (the `window.cadesplugin` promise, callbacks, timeouts, postMessage answers) + `spawn.ts` (`async_spawn` for sites
  driving the API through generators), `rutoken.ts` (waiting for the
  Rutoken adapter object and loading the plugin), `objects/` (emulated CAdESCOM objects, looked up
  case-insensitively by ProgID; `objects/cades-tools.ts` the demo pages' Android check; `objects/hashed-data.ts` hashes and HMACs in the page; `objects/raw-signature.ts` RawSignature, a bare signature of a hash
  (`rawSign`) and its check; `objects/signed-xml.ts`
  makes XMLDSig with xmldsigjs' canonicalizer and `rawSign`, and verifies it, `objects/xades.ts` adds XAdES-BES's
  qualifying properties and XAdES-T's timestamp to it; `objects/signers.ts` the signers a
  verification found; `objects/enveloped-data.ts` CMS encryption on the plugin's `cmsEncrypt`/`cmsDecrypt`;
  `objects/enveloped-xml.ts` XML encryption in CryptoPro's format, encrypted in the page, decrypted with the key the
  plugin's `derive` makes on the token;
  `objects/certificate-extensions.ts` the CAPICOM objects of a certificate's extensions (KeyUsage, ExtendedKeyUsage,
  BasicConstraints, Extensions, EncodedData) on `certificate-info.ts` (GetInfo's names, EKUs, policies, template),
  `certificate-dialog.ts` Display()'s window; `objects/csp-information.ts` the connected tokens as readers, `tokeninserted` by polling; `objects/containers.ts` their keys as CryptoPro's containers, read after each token's PIN once per page), `compat.ts` (versions reported to sites), `errors.ts` (`getLastError` format),
  `constants.ts` (generated, do not edit), `token.ts` (certificates on the tokens), `asn1.ts` + `x509.ts` +
  `dn.ts` + `sha1.ts` (certificate parsing, and `asn1.ts` writes DER too; `dn.ts` holds the CryptoPro name format
  sites match with regexes, and the RFC 4514 names of XAdES), `gost.ts` (hashes, HMAC, GOST R 34.10 signature checks and VKO, on `@li0ard/gost`) +
  `gost28147.ts` (GOST 28147-89 CBC and the key transport of XML encryption) + `cms.ts` (SignedData parsing and signer
  checks, BER included; the recipients of an EnvelopedData) + `chain.ts` (chains to the root store; `validationChain` for `IsValid()` in the extended mode) — verification never touches the plugin,
  `signing.ts` (the plugin's `sign`, data or a hash; CAdES-T through its `tspOptions`; with the site's signed
  attributes the CMS of `cms-sign.ts` around `rawSign`, its CAdES-T timestamp through the extension, as XAdES-T's) + `token-login.ts` (PIN window, login, logout, the single connected token; the PINs a page knows: the
  site's KeyPin and the one remembered until the page closes) + `pin-dialog.ts` (the PIN window, in a shadow root, or
  only its confirming button), `roots.ts` (asks the bridge for the "Root" and "CA" stores and adds to them), `timestamps.ts` (asks it for access to a
  timestamp service and for the service's answer) + `tsp.ts` (the RFC 3161 request and the checks of the answer), `root-links.ts` (after
  InstallResponse's CERT_E_UNTRUSTEDROOT, a click on the CA page's link to its certificate adds the root through
  Store.Add), `objects/enrollment.ts` (X509Enrollment for CA pages:
  key and PKCS#10 request on the token, installing the issued certificate).
  Rutoken Plugin methods return thenables, not Promises: `await` them, never `.catch()`.

- `scripts/` — Node scripts run directly by Node's type stripping (no build step): `fetch-vendor.ts` +
  `vendor-lock.json` (pinned third-party files), `build.ts` (esbuild), `package.ts` (the ZIP), `gen-constants.ts`, `crx.ts` (CRX3 key extraction), `setup-stand.ts` (stand layout,
  PINs, paths), `provision-token.ts` (key + certificate on the fake token; `provisionKey` for a 512-bit key or a copy of the HOME), `setup-cryptopro-csp.ts` (the real
  CryptoPro CSP + plug-in, a key in a CryptoPro file container, a stand profile copy with CryptoPro's native host).
- `tools/` — pasted by hand into the DevTools console on a cadesplugin page, with CryptoPro or with ours
  (`docs/MANUAL-CHECK.md`, the manual install and checklist): `dump-fields.js` dumps the plug-in and certificate
  fields and what `Find` picks as JSON, without a PIN, and `scripts/compare-fields.ts` diffs a real-CryptoPro dump
  against ours; `check-api.js` signs (PIN windows) what the demo pages do not call — site attributes read back,
  RawSignature, KeyPin, CachePin, HasPrivateKey. `demo-page.spec.ts` runs both on the stand.
- `docs/AGENT-CHECK.md` — instructions for an agent with a desktop (Claude Cowork): the release set of
  `MANUAL-CHECK.md` in a Chromium window started by hand on the stand's fake Rutoken, with a testgost2012
  certificate, and the report it writes. English, being executed by a model.
- `tests/unit/` — Vitest unit tests (`vitest.config.ts` limits Vitest to this directory); `fakes.ts` holds the
  fake plugin and PIN window; `tests/fixtures/` holds copies of a stand certificate and its CA so they run without
  the stand, and `verify.json` signatures made by CryptoPro's plug-in and crafted ones (how: `docs/JOURNAL.md`,
  2026-09-24) with the CA they chain to.
- `tests/stand/` — Playwright tests on the stand; `harness.ts` launches Chromium with the adapter and serves pages, offline;
  `smoke.spec.ts` checks the stand itself (plugin, adapter, fake token) without the extension; `sites.spec.ts` the
  per-site enabling from the options page and the popup;
  `demo-page.spec.ts` runs CryptoPro's demo page from `vendor/cryptopro/` at its original path, and the `tools/` scripts on it; `demo-pages.spec.ts` its
  file-signing, XMLDSig and verification pages (`cades_bes_file.html`, `cades_xmldsig_sample.html`, `verify.html`); `testgost.spec.ts`
  (opt-in, online) gets certificates from CryptoPro's test CA on a copy of the stand HOME; `nalog.spec.ts` (opt-in,
  online) signs in by certificate on the FNS personal accounts up to the server refusing the CA; `crpt.spec.ts`
  (opt-in, online) does the same on Честный знак; `testgost-certs.ts` issues their certificates; `firefox.ts` drives
  the stand's Firefox over WebDriver BiDi (its own small client) with the Rutoken adapter for Firefox and our
  `dist/firefox`, and `firefox.spec.ts` runs the plug-in, site enabling, the demo page, XAdES-T and webtools.html in
  it; `with-cryptopro.spec.ts`
  loads CryptoPro's own extension (`stand.cryptoproExtension`) beside ours; `hash-signing.spec.ts` signs hashes the ways sites do; `pin.spec.ts` the remembered PIN and the site's KeyPin; `attributes.spec.ts` the site's signed attributes and the
  chain in CMS; `certificate.spec.ts` the certificate's CAPICOM methods, Find's criteria and Display(); `gost512.spec.ts` a 512-bit
  key made on a copy of the token, signed with every way and decrypted on; `xml-signing.spec.ts` makes XMLDSig signatures of the three types; `xades.spec.ts` XAdES-BES and XAdES-T, with the stand's timestamp service and the window asking for access to another;
  `verification.spec.ts` verifies ours and CryptoPro's signatures in the page; `roots.spec.ts` drives the root store
  on the options page; `validity.spec.ts` the extended validity check and the demo page adding its root; `enrollment.spec.ts` the
  certsrv calls offline on a copy of the token, with the question about the root; `with-cryptopro-csp.spec.ts` (opt-in)
  does the same with the real CryptoPro plug-in behind it; `webtools.spec.ts` runs CryptoPro's `webtools.html`
  (readers and containers, signing with CAdES-T and XAdES, encryption); `openssl-gost.spec.ts` (opt-in) checks encryption against OpenSSL's GOST
  engine; `enveloped-xml.spec.ts` runs XML encryption in Chromium without the extension or the token: esbuild bundles
  `enveloped-xml.page.ts`, the page code with a fake plugin whose `derive` the spec answers with the stand CA's key
  (the fake token cannot make that key); `verify.ts` runs the independent tools on a signature or an encrypted
  message, and starts `tsa.py`.
- `tests/tools/` — independent Python GOST tooling (`gost_ca.py` test CA, `verify_cms.py` CMS verifier with CAdES-T
  timestamps, `tsa.py` RFC 3161 timestamp service with a certificate from the test CA, `verify_xmldsig.py` XMLDSig and XAdES
  verifier on lxml, `verify_raw.py` RawSignature's bare signatures, `enveloped_info.py` what an EnvelopedData is encrypted with and for), hash-pinned in
  `requirements.txt`.

Stand pitfalls (details in `docs/JOURNAL.md`): the native host finds the plugin only via `$HOME/.mozilla/plugins`,
and the plugin loads `librtpkcs11ecp.so` from that same directory, so the stand runs Chromium with its own `HOME`;
use the `chromium` channel, not the headless shell; the stand profile outlives builds and Chromium would keep
running its cached service worker, so `launchStand` deletes `Default/Service Worker` first; wait for the adapter object with `openStandPage`. Tests load
`standExtension()` (the build with the stand's host access pre-granted, since Chrome's permission prompt cannot be
clicked) and turn sites on with `enableSite`, through the options page. Firefox (`firefox.ts`): Playwright cannot drive
Mozilla's Firefox, so the tests talk WebDriver BiDi themselves; our extension's pages open only with
`-remote-allow-system-access`, and while one is open in a tab the adapter answers in seconds — close it before using a
site page.

## Settled decisions

- **Chrome first; other browsers later.** Owner, 2026-09-23. Do not add Firefox/Safari code paths before the
  roadmap stage for them. Stage 7 started with Firefox: owner, 2026-10-16, «делай firefox». Firefox is a second build of
  the same code (`firefoxManifest`, `__BROWSER__`), not a fork; the next browser is the owner's call.

- **The Firefox add-on id is `FIREFOX_ID` in `scripts/build.ts`.** Agent, 2026-10-16. Reason: Firefox keeps an
  add-on's storage under it and AMO would sign under it, so changing it loses the users' enabled sites and stores.

- **Firefox on the stand is Mozilla's build driven over WebDriver BiDi by `tests/stand/firefox.ts`, not
  Playwright.** Agent, 2026-10-16. Reason: Playwright drives only its own patched Firefox, which the environment
  cannot download, and users run Mozilla's; BiDi needs no new dependency (Node's `WebSocket`) and installs
  extensions with `webExtension.install`. Firefox and the adapter are pinned in `vendor-lock.json`.
- **Target keys are PKCS#11 objects on the token that the Rutoken Plugin can see.** Owner, 2026-09-23. CryptoPro
  containers written onto a Rutoken and CryptoPro FKN keys are out of scope: the Rutoken Plugin cannot use them.
- **First target site is the CryptoPro demo page `cades_bes_sample.html`.** Owner, 2026-09-23.
- **Hardware stand-in is the fake Rutoken from `code-agent-43824/SoftHSMv2`** (`FAKE_RUTOKEN_ECP = true`), loaded by
  the real Rutoken Plugin in place of its bundled `librtpkcs11ecp.so`; the test kit also carries OpenSC libraries
  adapted to Rutoken. Owner, 2026-09-23.
- **Stack: TypeScript + esbuild, tests on Vitest and Playwright.** The owner left the choice to the agent
  (2026-09-23, "any, as long as the extension works"). Reason: the emulated CAdESCOM surface is large and
  stringly-typed, types catch mismatched property names; a MAIN-world content script must ship as one bundled file.
- **Interception: define `window.cadesplugin` from a MAIN-world content script at `document_start`.** The site's
  `cadesplugin_api.js` returns early when the object exists. Evidence in `docs/JOURNAL.md`.
- **Signatures are judged by one criterion: they verify.** Owner, 2026-09-23. Reproducing CryptoPro's signed
  object byte for byte is not a goal; a missing field is acceptable as long as an independent verifier accepts the
  signature. So use the Rutoken `sign` method where it covers the request, and write our own CMS code only where
  `sign` cannot produce what is asked. The site's own signed attributes and the certificate chain are asked for:
  owner, 2026-10-21, «делай» on «в подпись не попадают атрибуты от сайта (время подписи, имя документа) и цепочка
  сертификатов». So a signature with the site's attributes is our CMS around the token's `rawSign`
  (`src/page/cms-sign.ts`), one without them is still `sign`'s, and the chain goes into either.

- **The extension is off by default and enabled per site.** Owner, 2026-09-23. Reason: otherwise any site can
  trigger a signature and a real CryptoPro install is intercepted everywhere (risks 7 and 9 in `docs/ANALYSIS.md`).
  Site access is an optional host permission requested when the user enables a site.

- **Independent GOST tooling is Python (`gostcrypto`, `asn1crypto`, `lxml`) in `tests/tools/`, test-only.** Agent,
  2026-09-23. Reason: a verifier must not share code with what it checks (the extension's own verification uses
  `@li0ard/gost`, found later, 2026-09-24); these are on PyPI and pinned by hash. Never ship them in the extension.

- **XMLDSig canonicalization comes from `xmldsigjs`, and only that file goes into page.js.** Owner, 2026-09-24,
  "xmldsig if you find suitable JavaScript libraries"; the choice is the agent's (`docs/JOURNAL.md`). Reason: of
  the libraries checked, only its `XmlCanonicalizer` canonicalizes correctly in the browser; the whole package
  adds about 450 KB, patches the page's `window.crypto` on import and signs CryptoPro's template sample wrongly,
  so the SignedInfo/Reference/KeyInfo layer is ours. The file is reached through the `xmldsigjs-canonicalizer`
  alias (scripts/build.ts, tsconfig.json, vitest.config.ts, the types in `src/page/globals.d.ts`); the version is
  pinned exactly. The XMLDSig verifier uses `lxml` (libxml2) for the same reason `verify_cms.py` exists: a check
  must not share code with what it checks.

- **Signature verification runs in the page, on `@li0ard/gost` (with `@noble/curves` and `@noble/hashes`).** Owner,
  2026-09-24: "verification inside the extension, without the Rutoken Plugin and the token"; the library choice is
  the agent's (`docs/JOURNAL.md`). Reason: it is MIT, pure TypeScript on the audited noble libraries, and checks
  every GOST root in the store; the others found wrap 2016–2020 code or are Node-only. Versions are pinned exactly.
  Hashing (`HashedData`, XMLDSig digests) uses it too, so none of it needs a token.

- **Verification does not check revocation.** Owner, 2026-09-24 (decision card). Reason: CRLs sit on the CAs'
  servers and would need the background worker and access to their hosts; CryptoPro refuses without a CRL, we
  accept. Chains end in the enabled certificates of the extension's root store.

- **The built-in root certificates are committed** (`src/extension/builtin-roots.ts`). Agent, 2026-09-23, on the
  owner's request to pre-fill the store from CryptoPro's package. Reason: they are public CA certificates, not
  software, and `lsb-cprocsp-ca-certs` downloads only after logging in to CryptoPro's site, so no pinned fetch can
  get them at build time. The package itself stays out of git.

- **Containers are listed after the token's PIN.** Owner, 2026-10-08: "спрашивай пин". Reason: CryptoPro names a
  key on a Rutoken `\\.\<reader>\ID_<CKA_ID>`, and the Rutoken Plugin gives key ids only after a login; the owner
  prefers CryptoPro's names to a list without a PIN.

- **XAdES-T's timestamp is requested by the service worker, with access to each service granted by the user.** Agent,
  2026-10-08, on the owner's "xades делай". Reason: the Rutoken Plugin reaches a timestamp service only inside a CMS
  signature, and page.js meets the services' lack of CORS and, on https: sites, mixed content; access stays an
  optional host permission per service (the extension's window, then Chrome's own question), as sites are enabled
  one by one, and only addresses confirmed as services are posted to (enabled sites have access too). The XAdES properties use v1.3.2's `SigningCertificate`, not EN 319 132's `SigningCertificateV2`:
  CryptoPro's verification takes either (`XadesGetSigningCertId`), verifiers of v1.3.2 only the first.

- **CI publishes the releases** (the `release` job in `.github/workflows/ci.yml`). Owner, 2026-09-24: "make it so
  you can publish releases, and publish". Reason: agents cannot push tags through the proxy (AGENTS.md §12), so a
  workflow with `contents: write` creates the tag and the release after the checks pass on `main`. Each release is
  a pre-release until the owner has checked it on a real Rutoken; bumping `package.json` is what releases.

## Versions

The extension version lives only in `package.json`; the build copies it into the manifest and the page-world
script. Before 1.0.0 (the owner's manual-check build, 2026-09-24) it was `0.<stage>.<n>`; from 1.0.0 on it is
semantic versioning: the patch for fixes, the minor for new CAdESCOM objects, methods or site support, the major when
a site's working flow or the stored data (`chrome.storage.local`) changes incompatibly. The CryptoPro versions the shim reports to sites (`PluginVersion`, `CSPVersion`) are
compatibility constants, not our version; why they are what they are is in `docs/PLAN.md` of stage 2 and
`docs/JOURNAL.md`.

## Departures from AGENTS.md

None.

## Owner review

The owner checks each stage by hand (§13): pause after every completed roadmap stage. Stage 5 is his manual run on
real Chrome with a real Rutoken.

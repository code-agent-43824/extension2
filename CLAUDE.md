@AGENTS.md

# Project notes

The line above imports the shared rules; nothing from them is restated here.

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
- `npm run build` — build the extension into `dist/extension/` (load it unpacked in Chrome).
- `npm run package` — build, then pack it into `dist/cryptopro-via-rutoken-<version>.zip` for installing by hand;
  CI uploads the same archive as the `cryptopro-via-rutoken` artifact.
- `node scripts/gen-constants.ts` — regenerate `src/page/constants.ts` after pinning a new `cadesplugin_api.js`.
- `npm run check` — typecheck (Node code, then `src/page/` with DOM types, then `src/extension/` with Chrome types)
  and unit tests; must pass before every commit.
- `npm run test:stand` — build, then Playwright tests against the built stand; `npx playwright test -g "<name>"` for one.
- `STAND_ONLINE=1 npx playwright test tests/stand/testgost.spec.ts` — after a build: the opt-in experiment against
  testgost2012.cryptopro.ru (internet through the environment proxy); leaves screenshots in `stand/testgost/`.
- `node scripts/setup-cryptopro-csp.ts <dir with .deb files>` (root), then
  `STAND_CRYPTOPRO_CSP=1 npx playwright test tests/stand/with-cryptopro-csp.spec.ts` — the opt-in local experiment with
  the real CryptoPro CSP and plug-in installed into the machine; the packages are licensed, never commit them.
- `npx vitest run tests/unit/crx.test.ts` — a single test file; add `-t "<name>"` for one test.

## Map of the code

- `src/manifest.json` — extension manifest; the build fills in the version. No static content script: page.js is
  registered at run time for the enabled sites only.
- `src/extension/` — the extension's own side, with Chrome types (`src/extension/tsconfig.json`): `sites.ts` (the
  enabled-site list in `chrome.storage.local`, optional host permissions, registering page.js), `background.ts`
  (service worker keeping the registration in sync), `popup.*` (the button's window), `options.*` (site list).
- `src/page/` — the MAIN-world content script, bundled into one `page.js`: `main.ts` (entry), `cadesplugin.ts`
  (the `window.cadesplugin` promise, callbacks, timeouts, postMessage answers), `rutoken.ts` (waiting for the
  Rutoken adapter object and loading the plugin), `objects/` (emulated CAdESCOM objects, looked up
  case-insensitively by ProgID), `compat.ts` (versions reported to sites), `errors.ts` (`getLastError` format),
  `constants.ts` (generated, do not edit), `token.ts` (certificates on the tokens), `asn1.ts` + `x509.ts` +
  `dn.ts` + `sha1.ts` (certificate parsing; `dn.ts` holds the CryptoPro name format sites match with regexes),
  `signing.ts` (the plugin's `sign`) + `token-login.ts` (PIN window, login, logout, the single connected token) +
  `pin-dialog.ts` (the PIN window, in a shadow root), `objects/enrollment.ts` (X509Enrollment for CA pages:
  key and PKCS#10 request on the token, installing the issued certificate).
  Rutoken Plugin methods return thenables, not Promises: `await` them, never `.catch()`.

- `scripts/` — Node scripts run directly by Node's type stripping (no build step): `fetch-vendor.ts` +
  `vendor-lock.json` (pinned third-party files), `build.ts` (esbuild), `package.ts` (the ZIP), `gen-constants.ts`, `crx.ts` (CRX3 key extraction), `setup-stand.ts` (stand layout,
  PINs, paths), `provision-token.ts` (key + certificate on the fake token), `setup-cryptopro-csp.ts` (the real
  CryptoPro CSP + plug-in, a key in a CryptoPro file container, a stand profile copy with CryptoPro's native host).
- `tools/dump-fields.js` — pasted by hand into the DevTools console on a cadesplugin page: dumps the plug-in and
  certificate fields as JSON; `scripts/compare-fields.ts` diffs a real-CryptoPro dump against ours
  (`docs/MANUAL-CHECK.md`, the manual install and checklist).
- `tests/unit/` — Vitest unit tests (`vitest.config.ts` limits Vitest to this directory); `fakes.ts` holds the
  fake plugin and PIN window; `tests/fixtures/` holds copies of a stand certificate and its CA so they run without
  the stand.
- `tests/stand/` — Playwright tests on the stand; `harness.ts` launches Chromium with the adapter and serves pages, offline;
  `demo-page.spec.ts` runs CryptoPro's demo page from `vendor/cryptopro/` at its original path; `testgost.spec.ts`
  (opt-in, online) gets certificates from CryptoPro's test CA on a copy of the stand HOME; `with-cryptopro.spec.ts`
  loads CryptoPro's own extension (`stand.cryptoproExtension`) beside ours; `with-cryptopro-csp.spec.ts` (opt-in)
  does the same with the real CryptoPro plug-in behind it; `verify.ts` runs the
  independent verifier on a signature.
- `tests/tools/` — independent Python GOST tooling (`gost_ca.py` test CA, `verify_cms.py` CMS verifier),
  hash-pinned in `requirements.txt`.

Stand pitfalls (details in `docs/JOURNAL.md`): the native host finds the plugin only via `$HOME/.mozilla/plugins`,
and the plugin loads `librtpkcs11ecp.so` from that same directory, so the stand runs Chromium with its own `HOME`;
use the `chromium` channel, not the headless shell; wait for the adapter object with `openStandPage`. Tests load
`standExtension()` (the build with the stand's host access pre-granted, since Chrome's permission prompt cannot be
clicked) and turn sites on with `enableSite`, through the options page.

## Settled decisions

- **Chrome first; other browsers later.** Owner, 2026-09-23. Do not add Firefox/Safari code paths before the
  roadmap stage for them.
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
  object byte for byte is not a goal; a missing field or attribute (e.g. the demo page's document-name attribute)
  is acceptable as long as an independent verifier accepts the signature. So use the Rutoken `sign` method where
  it covers the request, and write our own CMS code only where `sign` cannot produce a verifiable result.

- **The extension is off by default and enabled per site.** Owner, 2026-09-23. Reason: otherwise any site can
  trigger a signature and a real CryptoPro install is intercepted everywhere (risks 7 and 9 in `docs/ANALYSIS.md`).
  Site access is an optional host permission requested when the user enables a site.

- **Independent GOST tooling is Python (`gostcrypto`, `asn1crypto`) in `tests/tools/`, test-only.** Agent,
  2026-09-23. Reason: a verifier must not share code with what it checks, and no maintained npm GOST signature
  library was found; these two are on PyPI and pinned by hash. Never ship them in the extension.

## Versions

The extension version lives only in `package.json`; the build copies it into the manifest and the page-world
script. Until the first release it is `0.<stage>.<n>`: the minor number is the roadmap stage being built, the patch
counts fixes within it. The CryptoPro versions the shim reports to sites (`PluginVersion`, `CSPVersion`) are
compatibility constants, not our version; why they are what they are is in `docs/PLAN.md` of stage 2 and
`docs/JOURNAL.md`.

## Departures from AGENTS.md

None.

## Owner review

The owner checks each stage by hand (§13): pause after every completed roadmap stage. Stage 5 is his manual run on
real Chrome with a real Rutoken.

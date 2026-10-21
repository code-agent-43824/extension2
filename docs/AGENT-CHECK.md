# Release check on the fake Rutoken, for an agent with a desktop

For an agent that can drive a desktop — screenshots, clicks, typing — and run a shell, such as Claude Cowork. It
runs the release set of [`MANUAL-CHECK.md`](MANUAL-CHECK.md) in a real Chromium window, with the SoftHSMv2 fork in
fake Rutoken mode standing in for the device, and a certificate from CryptoPro's test CA. Its report goes to the
owner, who decides whether to lift the pre-release mark. A fake token exercises the extension's logic, not a
device: PIN retry counters, export restrictions and the token's own cryptography stay unchecked (AGENTS.md §4).

## Rules

- Do not change the repository: no edits, commits or pushes. Work in `~/rutoken-check/`.
- A step passes only when the text `MANUAL-CHECK.md` expects is on the screen. For anything else, record the exact
  text and take a screenshot. Do not fix code; carry on with the next step.
- Fake token PINs: user `12345678`, SO `87654321`. Enter a wrong PIN only where a step asks for it, once.
- «Удалить контейнер» only on the key issued in step 5 below, and only as the very last action, if at all.
- Expected results live in `MANUAL-CHECK.md` alone; this file says how to set up, what to run and how to report.

## 1. Environment

Linux x86_64 with a desktop session; Ubuntu 24.04 is what CI runs. Replacing the Rutoken Plugin's PKCS#11 library
is proven only with its Linux build: on Windows or macOS, do all of this inside a Linux virtual machine with a
desktop. Needed: `git`, `curl`, `unzip`, `dpkg-deb`, `python3` with `venv`, Node.js 22.18 or newer. Internet:
github.com, download.rutoken.ru, clients2.google.com, pypi.org, www.cryptopro.ru, testgost2012.cryptopro.ru,
testca2012.cryptopro.ru. Run as an ordinary user, not root.

## 2. The stand: Rutoken Plugin with the fork in place of its library

The release under check is the one the owner names, otherwise the newest at
<https://github.com/code-agent-43824/extension2/releases>. Set its version once and keep it in every shell below:

```sh
VERSION=X.Y.Z                # the release under check, without the "v"
mkdir -p ~/rutoken-check && cd ~/rutoken-check
git clone https://github.com/code-agent-43824/extension2.git
cd extension2
git checkout "v$VERSION"
npm ci
npx playwright install chromium
npm run stand
npx playwright test tests/stand/smoke.spec.ts
```

`npm run stand` installs nothing into the system; it builds `stand/` from the files pinned in
`scripts/vendor-lock.json`:

- unpacks Rutoken Plugin 4.12.3 for Linux into `stand/plugin`;
- puts `libnpRutokenPlugin.so` and the fork's `libsofthsm2.so`, named `librtpkcs11ecp.so`, into
  `stand/home/.mozilla/plugins` — the plugin loads its PKCS#11 library from its own directory, so this is the
  substitution;
- writes `stand/home/softhsm/softhsm.conf` with `FAKE_RUTOKEN_ECP = true` and initialises the token `stand` with the
  PINs above;
- registers the plugin's native messaging host, and unpacks the Rutoken adapter extension under its store id;
- puts a key and a «Stand User» certificate from a local test CA (`stand/ca/ca.pem`) on the token.

The smoke test must pass; if it does not, stop and report its output.

**Fork version.** `scripts/vendor-lock.json` of the checked-out release pins the fork. From `v2.7.0-portable.75` on it
answers the plugin's VKO `derive`, so GOST 28147-89 decryption (W7) and XML decryption (W8) must pass. An older pin
(`v2.7.0-portable.42`, in releases up to 1.10.1) answers error 147 there: report W7 and W8 as KNOWN, then, after the
whole run, unpack `softhsm-portable-linux-x64.zip` of `v2.7.0-portable.88` from
<https://github.com/code-agent-43824/SoftHSMv2/releases> into `~/rutoken-check/softhsm-new`, point the library at
it and repeat W7 and W8 only:

```sh
ln -sf ~/rutoken-check/softhsm-new/libsofthsm2.so stand/home/.mozilla/plugins/librtpkcs11ecp.so
```

Write down which fork release each result came from.

## 3. The extension under test

The release archive, not a build: `cryptopro-via-rutoken-$VERSION.zip` from the release's page, unpacked:

```sh
cd ~/rutoken-check
curl -LO "https://github.com/code-agent-43824/extension2/releases/download/v$VERSION/cryptopro-via-rutoken-$VERSION.zip"
unzip -q "cryptopro-via-rutoken-$VERSION.zip" -d ext   # gives ext/cryptopro-via-rutoken-$VERSION/chrome
```

Releases before 1.10.1 have the Chrome build at the archive's top folder: drop `/chrome` from the paths below. If the
download needs access you do not have, `gh release download "v$VERSION" -R code-agent-43824/extension2` does
the same; failing that, `npm run package` in the checkout of step 2 builds the archive into `dist/`.

## 4. Chromium on the fake token

```sh
cd ~/rutoken-check/extension2
PROFILE="$HOME/rutoken-check/profile"
mkdir -p "$PROFILE" && cp -r stand/profile/NativeMessagingHosts "$PROFILE/"
CHROME=$(node -e 'import("playwright").then((p) => console.log(p.chromium.executablePath()))')
EXT="$PWD/stand/adapter,$HOME/rutoken-check/ext/cryptopro-via-rutoken-$VERSION/chrome"
HOME="$PWD/stand/home" "$CHROME" --user-data-dir="$PROFILE" --no-first-run \
  --disable-extensions-except="$EXT" --load-extension="$EXT"
```

- Chromium, not Google Chrome: branded Chrome ignores `--load-extension`.
- `HOME` is the stand's, so the native host finds the plugin and the plugin the fork's library. The host's manifest
  must be inside the profile: without the copy, the page reports the Rutoken Plugin as not installed.
- Keep this window for the whole run, and close it before starting it again with the same profile.
- Pin «КриптоПро через Рутокен» from the puzzle menu: its button opens the window where sites are enabled.
- On the first page of a fresh profile the adapter may come late: if a CryptoPro page says the plug-in is not loaded,
  reload it once.

Check: on <https://www.cryptopro.ru/sites/default/files/products/cades/demopage/cades_bes_sample.html> before
enabling the site, the page finds no extension (checklist item 1).

## 5. A certificate from CryptoPro's test CA

Section «Ключ и сертификат на токене» of `MANUAL-CHECK.md`, steps 1–5, on testgost2012.cryptopro.ru, with the 256-bit
provider. Save the CA certificate of step 5 as `~/rutoken-check/files/testgost-ca.cer`. If the extension's root
warning window opens (checklist item 17), answer «Да». Chrome's own question about site access, when a site is
enabled, is part of the check: allow it.

The token now holds two certificates, «Stand User» and the testgost2012 one. Sign and encrypt with the testgost2012
one unless a step says otherwise. Wherever a step needs the issuer's certificate on the options page's second tab
(«Промежуточные и сторонние корневые»), add `testgost-ca.cer`, and `stand/ca/ca.pem` for «Stand User».

## 6. The release set

Mandatory, in this order:

1. Checklist items 1–7 and 7а (demo page `cades_bes_sample.html`; 7а — the remembered PIN — from release 1.12.0 on).
2. Checklist items 11–13 (issuer's certificate on the second tab, `verify.html`).
3. webtools.html: W1, W2, W4, W6, W7, W8. In W6, XAdES-T with `http://testca2012.cryptopro.ru/tsp/tsp.srf`: the
   extension's window «Доступ к службе штампов времени» — «Разрешить», then Chrome's own question — allow.

Desirable: W3, W5, W9, W12, W13, checklist items 8–10 and 14, 16–17.

Not applicable here — report N/A: W11 (taking the token out), checklist item 15, the comparisons with a CryptoPro
machine inside W4–W8, and «Сверка полей с КриптоПро»; all need a device or CryptoPro CSP.

On the fake token the reader is `Aktiv Rutoken ECP 0`, the token label `stand`, and the containers
`\\.\Aktiv Rutoken ECP 0\ID_…` are two keys. In W4, «Cannot find the original signer. (0x8009100E)» means the issuer's
certificate is missing from the second tab: add it and verify again; that counts as a pass.

## 7. Report

`~/rutoken-check/report.md`, in Russian:

- Environment: OS, Chromium version, Rutoken Plugin version and extension version (webtools.html, «Общее»), fork
  release, date.
- A table: item (checklist number or W number) | PASS / FAIL / KNOWN / N/A / BLOCKED | for anything but PASS, the
  exact text on the screen | screenshot file. KNOWN is error 147 in W7 and W8 with a fork older than `.75`; BLOCKED is a
  site or the network failing (try once more later), not the extension.
- The files W4–W8 ask to save, in `~/rutoken-check/files/`.
- The last line: «Обязательный набор пройден» or «Обязательный набор не пройден: <items>».

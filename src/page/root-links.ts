// The root of a certificate a CA page installs, offered the way Windows does it (docs/PLAN.md, action 22): after
// InstallResponse answers CERT_E_UNTRUSTEDROOT, certsrv's certfnsh.asp shows «Данный ЦС не является доверенным»
// with a link to the CA certificate, which Windows opens in its certificate installer. In Chrome that link only
// downloads the file, so page.js watches clicks on links to certificate files: one whose file holds the root
// the CA's response carried goes to Store.Add, which asks the user in the extension's window. Other links, and
// any file without that root, work as before.
import { CadesError } from "./errors.ts";
import type { AddStore } from "./roots.ts";
import { responseCertificates } from "./objects/enrollment.ts";
import { commonName } from "./signing.ts";
import { derToBase64, type X509 } from "./x509.ts";

export interface RootOffer {
  root: X509;
  // The intermediates between the certificate and the root that the stores lack.
  intermediates: X509[];
}

type Add = (store: AddStore, certificate: X509) => Promise<void>;

// What the extension answers when the user says no (src/extension/install.ts).
const ERROR_CANCELLED = 0x800704c7;
const CERTIFICATE_FILE = /\.(cer|crt|der|pem|p7b|p7c)$/i;

const same = (a: X509, b: X509) => a.der.length === b.der.length && a.der.every((byte, i) => byte === b.der[i]);

// The offer whose root is in a downloaded file (DER, PEM or Base64, a certificate or a PKCS#7), if any.
export function offerInFile(file: Uint8Array, offers: readonly RootOffer[]): RootOffer | undefined {
  const text = new TextDecoder().decode(file);
  const printable = /^[\x09\x0a\x0d\x20-\x7e]*$/.test(text);
  let certificates: X509[];
  try {
    certificates = responseCertificates(printable ? text : derToBase64(file));
  } catch {
    return undefined;
  }
  return offers.find((offer) => certificates.some((certificate) => same(certificate, offer.root)));
}

export function isCertificateLink(url: URL): boolean {
  return (url.protocol === "https:" || url.protocol === "http:") && CERTIFICATE_FILE.test(url.pathname);
}

const offersByWindow = new WeakMap<Window, RootOffer[]>();

export function offerRootByLink(win: Window, offer: RootOffer, add: Add): void {
  let offers = offersByWindow.get(win);
  if (!offers) {
    offers = [];
    offersByWindow.set(win, offers);
    const list = offers;
    win.document.addEventListener("click", (event) => onClick(win, event, list, add), true);
  }
  if (!offers.some((known) => same(known.root, offer.root))) offers.push(offer);
}

function onClick(win: Window, event: MouseEvent, offers: RootOffer[], add: Add): void {
  if (!offers.length || event.defaultPrevented || event.button !== 0 || event.ctrlKey || event.metaKey || event.shiftKey || event.altKey) return;
  const link = (event.target as Element | null)?.closest?.("a[href]") as HTMLAnchorElement | null;
  if (!link) return;
  const url = new URL(link.href, win.location.href);
  if (!isCertificateLink(url)) return;
  event.preventDefault();
  void installFromLink(win, link, url, offers, add);
}

async function installFromLink(win: Window, link: HTMLAnchorElement, url: URL, offers: RootOffer[], add: Add): Promise<void> {
  let offer: RootOffer | undefined;
  try {
    const response = await win.fetch(url, { credentials: "include" });
    if (response.ok) offer = offerInFile(new Uint8Array(await response.arrayBuffer()), offers);
  } catch {
    // Not readable from the page: the link does what it did.
  }
  if (!offer) {
    win.open(url.href, link.target || "_self");
    return;
  }
  try {
    await add("root", offer.root);
    for (const intermediate of offer.intermediates) await add("ca", intermediate);
  } catch (error) {
    if (!(error instanceof CadesError && error.number === ERROR_CANCELLED)) win.alert(`Корневой сертификат не установлен: ${(error as Error).message}`);
    return;
  }
  offers.splice(offers.indexOf(offer), 1);
  win.alert(`Корневой сертификат «${commonName(offer.root.subject)}» установлен в расширении. Установите свой сертификат ещё раз.`);
}

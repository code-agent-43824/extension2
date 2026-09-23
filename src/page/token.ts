// Certificates on the connected Rutokens, read without a PIN.
import type { RutokenPlugin } from "./rutoken.ts";
import { parseCertificate, pemToDer, type X509 } from "./x509.ts";

export interface TokenCertificate {
  deviceId: number;
  // Token serial number, stable across reconnects unlike deviceId.
  serial: string;
  // The Rutoken Plugin's certificate id (its SHA-1 as colon-separated hex).
  certId: string;
  x509: X509;
}

// The current deviceId of the token with this serial number: ids change when tokens are reconnected.
export async function findDevice(plugin: RutokenPlugin, serial: string): Promise<number | undefined> {
  const serialInfo = await plugin.TOKEN_INFO_SERIAL;
  for (const deviceId of await plugin.enumerateDevices()) {
    if (String(await plugin.getDeviceInfo(deviceId, serialInfo)) === serial) return deviceId;
  }
  return undefined;
}

// User-category certificates of every connected token, in token order. A certificate that fails to
// parse is skipped rather than hiding the others.
export async function userCertificates(plugin: RutokenPlugin): Promise<TokenCertificate[]> {
  const category = await plugin.CERT_CATEGORY_USER;
  const serialInfo = await plugin.TOKEN_INFO_SERIAL;
  const result: TokenCertificate[] = [];
  for (const deviceId of await plugin.enumerateDevices()) {
    const serial = String(await plugin.getDeviceInfo(deviceId, serialInfo));
    for (const certId of await plugin.enumerateCertificates(deviceId, category)) {
      try {
        result.push({ deviceId, serial, certId, x509: parseCertificate(pemToDer(await plugin.getCertificate(deviceId, certId))) });
      } catch (error) {
        console.warn(`Рутокен вместо КриптоПро: сертификат ${certId} пропущен`, error);
      }
    }
  }
  return result;
}

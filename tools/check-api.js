// Runs through window.cadesplugin what CryptoPro's demo pages do not call, for the manual check
// (docs/MANUAL-CHECK.md, items 19–22): a signature with the document's name and description, then its attributes
// read back after verifying it; RawSignature, a bare signature of a hash, and its check; the site's PIN (KeyPin);
// the remembered PIN (CachePin); HasPrivateKey() before and after. Paste into the DevTools console on a page of a
// site the extension is enabled on, e.g. CryptoPro's demo page, with one Rutoken connected. It signs, so the PIN
// window opens several times as it goes. Prints the results as JSON and copies them; with the real CryptoPro the
// same script gives the same fields, to compare.
(async () => {
  // Fill in before pasting, or leave empty:
  const PIN = ""; // the token's PIN, handed over as the site's KeyPin; empty skips that step
  const THUMBPRINT = ""; // the certificate to sign with; empty takes the first one with a private key

  const plugin = window.cadesplugin;
  await plugin;
  const error = (e) => ({ error: String(plugin.getLastError ? plugin.getLastError(e) : e) });
  const read = async (get) => {
    try {
      const value = await get();
      if (value === undefined) return { undefined: true };
      return value instanceof Date ? value.toISOString() : value;
    } catch (e) {
      return error(e);
    }
  };
  const result = { userAgent: navigator.userAgent };
  const step = async (name, run) => {
    try {
      result[name] = await run();
    } catch (e) {
      result[name] = error(e);
    }
  };

  const store = await plugin.CreateObjectAsync("CAdESCOM.Store");
  await store.Open(plugin.CAPICOM_CURRENT_USER_STORE, plugin.CAPICOM_MY_STORE, plugin.CAPICOM_STORE_OPEN_MAXIMUM_ALLOWED);
  const certificates = await store.Certificates;
  const count = await certificates.Count;
  const hasPrivateKey = async () => {
    const out = {};
    for (let i = 1; i <= count; i++) {
      const c = await certificates.Item(i);
      out[await c.Thumbprint] = await read(() => c.HasPrivateKey());
    }
    return out;
  };
  result.hasPrivateKeyBefore = await hasPrivateKey();
  let certificate;
  for (let i = 1; i <= count && !certificate; i++) {
    const c = await certificates.Item(i);
    if (THUMBPRINT ? (await c.Thumbprint).toUpperCase() === THUMBPRINT.replace(/\s+/g, "").toUpperCase() : await c.HasPrivateKey()) {
      certificate = c;
    }
  }
  if (!certificate) {
    result.error = "Нет сертификата с закрытым ключом" + (THUMBPRINT ? ` и отпечатком ${THUMBPRINT}` : "");
  } else {
    const algorithm = await (await (await certificate.PublicKey()).Algorithm).Value;
    result.certificate = { Thumbprint: await certificate.Thumbprint, SubjectName: await certificate.SubjectName, algorithm };
    // CADESCOM_HASH_ALGORITHM_CP_GOST_3411_2012_512 for a 512-bit key, _256 otherwise.
    const hashAlgorithm = algorithm === "1.2.643.7.1.1.1.2" ? 102 : 101;
    const signer = async () => {
      const s = await plugin.CreateObjectAsync("CAdESCOM.CPSigner");
      await s.propset_Certificate(certificate);
      return s;
    };
    const sign = async (s, text) => {
      const data = await plugin.CreateObjectAsync("CAdESCOM.CadesSignedData");
      await data.propset_Content(text);
      return data.SignCades(s, plugin.CADESCOM_CADES_BES);
    };

    // 1. The document's name and description as signed attributes, read back from the verified signer.
    await step("attributes", async () => {
      const s = await signer();
      const attributes = await s.AuthenticatedAttributes2;
      for (const [name, value] of [
        [0, new Date()], // CAPICOM_AUTHENTICATED_ATTRIBUTE_SIGNING_TIME
        [1, "Документ.txt"], // CADESCOM_AUTHENTICATED_ATTRIBUTE_DOCUMENT_NAME
        [2, "Проверка атрибутов"], // CADESCOM_AUTHENTICATED_ATTRIBUTE_DOCUMENT_DESCRIPTION
      ]) {
        const attribute = await plugin.CreateObjectAsync("CADESCOM.CPAttribute");
        await attribute.propset_Name(name);
        await attribute.propset_Value(value);
        await attributes.Add(attribute);
      }
      const signature = await sign(s, "Проверка атрибутов");
      const check = await plugin.CreateObjectAsync("CAdESCOM.CadesSignedData");
      await check.VerifyCades(signature, plugin.CADESCOM_CADES_BES);
      const signerInfo = await (await check.Signers).Item(1);
      const signed = await signerInfo.AuthenticatedAttributes2;
      const back = [];
      for (let i = 1; i <= (await signed.Count); i++) {
        const a = await signed.Item(i);
        back.push({ Name: await read(() => a.Name), OID: await read(async () => (await a.OID).Value), Value: await read(() => a.Value) });
      }
      return {
        verified: true,
        certificatesInSignature: await read(async () => (await check.Certificates).Count),
        SigningTime: await read(() => signerInfo.SigningTime),
        attributes: back,
        signature,
      };
    });

    // 2. RawSignature: the signature of a hash without CMS, checked, then checked again with one digit changed.
    await step("rawSignature", async () => {
      const hashed = await plugin.CreateObjectAsync("CAdESCOM.HashedData");
      await hashed.propset_Algorithm(hashAlgorithm);
      await hashed.Hash("Проверка RawSignature");
      const raw = await plugin.CreateObjectAsync("CAdESCOM.RawSignature");
      const signature = await raw.SignHash(hashed, certificate);
      const verified = await read(async () => (await raw.VerifyHash(hashed, certificate, signature), true));
      const changed = signature.replace(/[0-9A-Fa-f]/, (digit) => (digit === "0" ? "1" : "0"));
      const tampered = await read(async () => (await raw.VerifyHash(hashed, certificate, changed), true));
      return { hash: await hashed.Value, signature, verified, tampered };
    });

    // 3. The site's PIN: our window only confirms, CryptoPro's asks nothing.
    if (PIN) {
      await step("keyPin", async () => {
        const s = await signer();
        await s.propset_KeyPin(PIN);
        return { signed: (await sign(s, "Проверка KeyPin")).length > 0 };
      });
    }

    // 4. The remembered PIN: the box ticked beforehand, the second signature without a PIN, then forgotten.
    await step("cachePin", async () => {
      const key = await certificate.PrivateKey;
      await key.propset_CachePin(true);
      const before = await read(() => key.CachePin);
      const first = (await sign(await signer(), "Проверка CachePin, 1")).length > 0;
      const second = (await sign(await signer(), "Проверка CachePin, 2")).length > 0;
      await key.CacheKey(false);
      return { CachePin: before, first, second, afterCacheKeyFalse: await read(() => key.CachePin) };
    });
  }
  result.hasPrivateKeyAfter = await hasPrivateKey();
  await store.Close();

  const json = JSON.stringify(result, null, 2);
  // copy() exists only in the DevTools console.
  if (typeof copy === "function") copy(json);
  console.log(json);
  return json;
})();

// Prints what window.cadesplugin reports about the plug-in and the certificates in the user's "My"
// store, as JSON, for comparing the real CryptoPro with our extension (docs/MANUAL-CHECK.md).
// Paste into the DevTools console on a page that loads cadesplugin_api.js, e.g. CryptoPro's demo
// page. Nothing is signed and no PIN is asked. Every value is read on its own, so a property one side
// lacks shows up as {"error": "..."} instead of stopping the dump.
(async () => {
  const plugin = window.cadesplugin;
  await plugin;
  const error = (e) => ({ error: String(plugin.getLastError ? plugin.getLastError(e) : e) });
  const read = async (get) => {
    try {
      const value = await get();
      // JSON would drop an undefined value, and the comparison would not see the property is missing.
      if (value === undefined) return { undefined: true };
      return value instanceof Date ? value.toISOString() : value;
    } catch (e) {
      return error(e);
    }
  };
  const version = async (v) => {
    const o = await v;
    return `${await o.MajorVersion}.${await o.MinorVersion}.${await o.BuildVersion}`;
  };
  // The named properties of the object `get` gives, each read on its own.
  const properties = async (get, names) => {
    let object;
    try {
      object = await get();
    } catch (e) {
      return error(e);
    }
    const out = {};
    for (const name of names) out[name] = await read(() => object[name]);
    return out;
  };
  // A CAPICOM collection, each item through `item`.
  const list = async (get, item) => {
    try {
      const collection = await get();
      const count = await collection.Count;
      const out = [];
      for (let i = 1; i <= count; i++) out.push(await item(await collection.Item(i)));
      return out;
    } catch (e) {
      return error(e);
    }
  };

  const about = await plugin.CreateObjectAsync("CAdESCOM.About");
  const result = {
    userAgent: navigator.userAgent,
    about: {
      Version: await read(() => about.Version),
      PluginVersion: await read(() => version(about.PluginVersion)),
      CSPVersion: await read(() => version(about.CSPVersion("", 80))),
      CSPName: await read(() => about.CSPName(80)),
    },
    certificates: [],
    find: {},
  };

  const store = await plugin.CreateObjectAsync("CAdESCOM.Store");
  await store.Open(plugin.CAPICOM_CURRENT_USER_STORE, plugin.CAPICOM_MY_STORE, plugin.CAPICOM_STORE_OPEN_MAXIMUM_ALLOWED);
  const certificates = await store.Certificates;
  const count = await certificates.Count;
  const issuers = new Set();
  for (let i = 1; i <= count; i++) {
    const c = await certificates.Item(i);
    const info = {};
    // CAPICOM_CERT_INFO_TYPE 0–7.
    for (const [type, name] of [
      "SUBJECT_SIMPLE_NAME",
      "ISSUER_SIMPLE_NAME",
      "SUBJECT_EMAIL_NAME",
      "ISSUER_EMAIL_NAME",
      "SUBJECT_UPN",
      "ISSUER_UPN",
      "SUBJECT_DNS_NAME",
      "ISSUER_DNS_NAME",
    ].entries()) {
      info[name] = await read(() => c.GetInfo(type));
    }
    if (typeof info.ISSUER_SIMPLE_NAME === "string") issuers.add(info.ISSUER_SIMPLE_NAME);
    result.certificates.push({
      SubjectName: await read(() => c.SubjectName),
      IssuerName: await read(() => c.IssuerName),
      SerialNumber: await read(() => c.SerialNumber),
      Thumbprint: await read(() => c.Thumbprint),
      Version: await read(() => c.Version),
      ValidFromDate: await read(() => c.ValidFromDate),
      ValidToDate: await read(() => c.ValidToDate),
      HasPrivateKey: await read(() => c.HasPrivateKey()),
      IsValid: await read(async () => (await c.IsValid()).Result),
      GetInfo: info,
      KeyUsage: await properties(
        () => c.KeyUsage(),
        [
          "IsPresent",
          "IsCritical",
          "IsDigitalSignatureEnabled",
          "IsNonRepudiationEnabled",
          "IsKeyEnciphermentEnabled",
          "IsDataEnciphermentEnabled",
          "IsKeyAgreementEnabled",
          "IsKeyCertSignEnabled",
          "IsCRLSignEnabled",
          "IsEncipherOnlyEnabled",
          "IsDecipherOnlyEnabled",
        ],
      ),
      ExtendedKeyUsage: {
        ...(await properties(() => c.ExtendedKeyUsage(), ["IsPresent", "IsCritical"])),
        EKUs: await list(
          async () => (await c.ExtendedKeyUsage()).EKUs,
          async (eku) => ({ Name: await read(() => eku.Name), OID: await read(() => eku.OID) }),
        ),
      },
      BasicConstraints: await properties(
        () => c.BasicConstraints(),
        ["IsPresent", "IsCritical", "IsCertificateAuthority", "IsPathLenConstraintPresent", "PathLenConstraint"],
      ),
      Extensions: await list(
        () => c.Extensions(),
        async (extension) => ({
          OID: await read(async () => (await extension.OID).Value),
          Name: await read(async () => (await extension.OID).Name),
          FriendlyName: await read(async () => (await extension.OID).FriendlyName),
          IsCritical: await read(() => extension.IsCritical),
          EncodedData: await read(async () => (await extension.EncodedData).Value()),
        }),
      ),
      PublicKey: {
        Algorithm: await read(async () => (await (await c.PublicKey()).Algorithm).Value),
        FriendlyName: await read(async () => (await (await c.PublicKey()).Algorithm).FriendlyName),
        Length: await read(async () => (await c.PublicKey()).Length),
        EncodedKey: await read(async () => (await (await c.PublicKey()).EncodedKey).Value()),
        EncodedParameters: await read(async () => (await (await c.PublicKey()).EncodedParameters).Value()),
      },
      PrivateKey: {
        ProviderName: await read(async () => (await c.PrivateKey).ProviderName),
        ProviderType: await read(async () => (await c.PrivateKey).ProviderType),
        ContainerName: await read(async () => (await c.PrivateKey).ContainerName),
        UniqueContainerName: await read(async () => (await c.PrivateKey).UniqueContainerName),
      },
    });
  }

  // Which certificates Certificates.Find picks by the criteria of CAPICOM_CERTIFICATE_FIND_TYPE added in 1.14.0, as
  // sorted thumbprints. The root's name is tried with each issuer's simple name: a certificate a root issued itself.
  const found = async (type, criteria) => {
    const thumbprints = await list(() => certificates.Find(type, criteria), (c) => read(() => c.Thumbprint));
    return Array.isArray(thumbprints) ? thumbprints.sort() : thumbprints;
  };
  for (const issuer of [...issuers].sort()) result.find[`ROOT_NAME ${issuer}`] = await found(3, issuer);
  result.find["EXTENSION 2.5.29.15"] = await found(5, "2.5.29.15");
  result.find["EXTENSION CAPICOM_OID_KEY_USAGE_EXTENSION"] = await found(5, 10);
  result.find["APPLICATION_POLICY 1.3.6.1.5.5.7.3.2"] = await found(7, "1.3.6.1.5.5.7.3.2");
  result.find["APPLICATION_POLICY 1.3.6.1.5.5.7.3.4"] = await found(7, "1.3.6.1.5.5.7.3.4");
  result.find["CERTIFICATE_POLICY 1.2.643.100.113.1"] = await found(8, "1.2.643.100.113.1");
  result.find["KEY_USAGE CAPICOM_DIGITAL_SIGNATURE_KEY_USAGE"] = await found(12, 128);
  await store.Close();

  const json = JSON.stringify(result, null, 2);
  // copy() exists only in the DevTools console.
  if (typeof copy === "function") copy(json);
  console.log(json);
  return json;
})();

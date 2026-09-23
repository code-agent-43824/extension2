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
  };

  const store = await plugin.CreateObjectAsync("CAdESCOM.Store");
  await store.Open(plugin.CAPICOM_CURRENT_USER_STORE, plugin.CAPICOM_MY_STORE, plugin.CAPICOM_STORE_OPEN_MAXIMUM_ALLOWED);
  const certificates = await store.Certificates;
  const count = await certificates.Count;
  for (let i = 1; i <= count; i++) {
    const c = await certificates.Item(i);
    const info = {};
    for (const [name, type] of Object.entries({
      SUBJECT_SIMPLE_NAME: 0,
      ISSUER_SIMPLE_NAME: 1,
      SUBJECT_EMAIL_NAME: 2,
      ISSUER_EMAIL_NAME: 3,
    })) {
      info[name] = await read(() => c.GetInfo(type));
    }
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
      PublicKey: {
        Algorithm: await read(async () => (await (await c.PublicKey()).Algorithm).Value),
        FriendlyName: await read(async () => (await (await c.PublicKey()).Algorithm).FriendlyName),
      },
      PrivateKey: {
        ProviderName: await read(async () => (await c.PrivateKey).ProviderName),
        ProviderType: await read(async () => (await c.PrivateKey).ProviderType),
        ContainerName: await read(async () => (await c.PrivateKey).ContainerName),
        UniqueContainerName: await read(async () => (await c.PrivateKey).UniqueContainerName),
      },
    });
  }
  await store.Close();

  const json = JSON.stringify(result, null, 2);
  // copy() exists only in the DevTools console.
  if (typeof copy === "function") copy(json);
  console.log(json);
  return json;
})();

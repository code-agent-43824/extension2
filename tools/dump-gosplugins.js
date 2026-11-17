// Prints what the Gosuslugi plug-ins answer on this page, as JSON, for comparing the real IFCPlugin and Gosplugin with
// our extension playing them (docs/MANUAL-CHECK.md). Paste into the DevTools console on a page of a site where the
// plug-ins are on: with the real ones, any page their extensions run on; with ours, a site with both "Плагин Госуслуг
// (IFCPlugin)" and "Госплагин" turned on. Nothing is signed and no PIN is asked; a plug-in that does not answer within
// 10 seconds shows {"error": "timeout"}. Ids and container names differ by design (docs/JOURNAL.md, 2026-11-17).
(async () => {
  const timeout = (promise) => Promise.race([promise, new Promise((resolve) => setTimeout(() => resolve({ error: "timeout" }), 10000))]);

  // IFCPlugin: JSON strings, answers in the order of the requests.
  const pending = [];
  const onIfc = (event) => {
    if (typeof event.data !== "string") return;
    let message;
    try {
      message = JSON.parse(event.data);
    } catch {
      return;
    }
    if (message.type === "FROM_IFC_EXT" && message.msg_data.intermediate !== 1) pending.shift()?.(message.msg_data);
  };
  window.addEventListener("message", onIfc);
  const ifc = (func_name, params = {}) =>
    timeout(
      new Promise((resolve) => {
        pending.push(resolve);
        window.postMessage(JSON.stringify({ type: "TO_IFC_EXT", msg_data: { func_name, params } }), "*");
      }),
    );

  // Gosplugin: the page's own message for its extension, then the objects loadScripts puts on the page.
  const send = (module, method, data) =>
    timeout(
      new Promise((resolve) => {
        const id = crypto.randomUUID();
        const message = {
          id, node: "", error: "", mode: "", module: { type: module, version: "0.0.0.0" }, method: { type: method, data, result: "" },
          meta: { format: { type: "message", version: "0.0.0.0", category: "gosuslugi.plugin" }, content: { type: "application/json", charset: "utf8", transferEncoding: "" },
            routes: [{ node: "dump.page", time: new Date().toLocaleString(), transfer: "" }], data: {}, userAgent: navigator.userAgent },
        };
        const listener = (event) => {
          if (event.data && event.data.id === id && event.data.node) {
            window.removeEventListener("message", listener);
            resolve(JSON.parse(JSON.stringify(event.data)));
          }
        };
        window.addEventListener("message", listener);
        window.postMessage(message, "*");
      }),
    );
  const api = (object, method, ...args) =>
    window[object]
      ? timeout(new Promise((resolve) => window[object][method](...args, (answer) => resolve(JSON.parse(JSON.stringify(answer))))))
      : Promise.resolve({ error: `no ${object}` });
  // The result of a Gosplugin answer, parsed when it is JSON.
  const result = (answer) => {
    const text = answer?.method?.result;
    try {
      return { ...answer, method: { ...answer.method, result: JSON.parse(text) } };
    } catch {
      return answer;
    }
  };

  const out = { userAgent: navigator.userAgent, ifc: {}, gos: {} };
  out.ifc.markers = ["ifcplugin-extension-is-installed", "ifc-plugin-is-installed"].map((id) => !!document.getElementById(id));
  out.ifc.version = await ifc("version");
  out.ifc.create = await ifc("create", {});
  out.ifc.get_list_info = await ifc("get_list_info");
  out.ifc.certificates = [];
  for (const token of out.ifc.get_list_info?.ifc_list ?? []) {
    const cryptoID = `${token.alias}/${token.num}`;
    const list = await ifc("get_list_certs", { cryptoID });
    for (const certificate of list?.cert_list ?? []) {
      const { x509Handle } = await ifc("load_x509_from_container", { containerId: `${cryptoID}/${certificate.id}` });
      const info = await ifc("get_x509_info", { x509Handle });
      await ifc("free_x509", { x509Handle });
      const hash = await ifc("hash", { containerId: `${cryptoID}/${certificate.id}`, inDataType: 1, outDataType: 1, data: "Проверка" });
      out.ifc.certificates.push({ list: certificate, info, hash });
    }
  }
  out.ifc.errors = {
    no_slot: await ifc("get_list_certs", { cryptoID: "ruTokenECP" }),
    bad_slot: await ifc("get_list_certs", { cryptoID: "ruTokenECP/9" }),
    keys_without_pin: await ifc("get_list_keys", { cryptoID: "ruTokenECP/0" }),
    unknown_function: await ifc("no_such_function"),
  };
  window.removeEventListener("message", onIfc);

  out.gos.meta = Array.from(document.querySelectorAll('meta[content="extension"]'), (meta) => meta.getAttribute("property"));
  out.gos.registered = result(await send("system", "registered", ""));
  out.gos.loadScripts = result(await send("system", "loadScripts", ["system.js", "crypto.js"]));
  for (const method of ["handshake", "protocol", "lastError"]) out.gos[method] = result(await api("gosuslugiPluginSystem", method));
  out.gos.providers = result(await api("gosuslugiPluginCrypto", "providers", {}));
  out.gos.tokens = result(await api("gosuslugiPluginCrypto", "tokens", {}));
  out.gos.certificates = result(await api("gosuslugiPluginCrypto", "certificates", { store: "", fields: {} }));
  const first = Array.isArray(out.gos.certificates?.method?.result) ? out.gos.certificates.method.result[0] : undefined;
  if (first) {
    const certificate = { content: first.raw, path: "", contentEncoding: "base64" };
    const file = { content: btoa(unescape(encodeURIComponent("Проверка"))), path: "", contentEncoding: "base64" };
    out.gos.certificateFields = result(await api("gosuslugiPluginCrypto", "certificateFields", JSON.stringify({ certificate, fields: [] })));
    out.gos.hash = result(await api("gosuslugiPluginCrypto", "hash", { certificate, file, algorithm: "" }));
    out.gos.unknownSignatureType = result(await api("gosuslugiPluginCrypto", "signature", { files: [file], certificate, type: "cades" }));
  }

  const json = JSON.stringify(out, null, 2);
  // copy() exists only in the DevTools console.
  if (typeof copy === "function") copy(json);
  console.log(json);
  return json;
})();

// Versions the shim reports to sites in place of CryptoPro's. Sites compare them against minimums
// (the crypto-pro npm library wants plug-in >= 2.0.12438 and CSP >= 4.0) and the demo page offers an
// update unless the pair is in its CertifiedCspPluginBundles table, so these are the certified
// CryptoPro pair, not our own version. Chosen in docs/PLAN.md of stage 2.
export const PLUGIN_VERSION = "2.0.15000";
export const CSP_VERSION = "5.0.13000";

// cadesplugin_api.js version whose surface window.cadesplugin reproduces.
export const JS_MODULE_VERSION = "2.4.5";

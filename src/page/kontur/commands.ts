// Kontur.Plugin's host commands over the Rutoken Plugin (docs/PLAN.md, stage 9), answered as the host 4.15.1 answered
// them on the stand (docs/JOURNAL.md, 2026-11-19). The site's access is its being enabled (the owner, 2026-11-19), so
// plugin.info says it is not denied, and no window asks.
import type { Session } from "../objects/session.ts";
import type { Settings } from "../settings.ts";
import { unknownCommand } from "./errors.ts";

export const PLUGIN_VERSION = "4.15.1.6119";

export interface KonturContext {
  session: Session;
  settings: Promise<Settings>;
  platform: string;
  // The host keeps "cache" streams per connection: here per page session id, by name.
  caches: Map<string, Map<string, Uint8Array>>;
}

export function newKonturContext(session: Session, settings: Promise<Settings>, platform: string): KonturContext {
  return { session, settings, platform, caches: new Map() };
}

export type Request = Record<string, unknown> & { sessionId?: unknown; type?: unknown; hostUri?: string };

// The host's platform name: "linux" as it answered on the stand; the others by the same pattern, not seen.
function platformName(platform: string): string {
  if (/^Win/i.test(platform)) return "windows";
  if (/^Mac/i.test(platform)) return "mac";
  return "linux";
}

export async function answerCommand(context: KonturContext, request: Request): Promise<unknown> {
  switch (request.type) {
    case "plugin.info":
      return {
        architecture: "x86_64",
        buildType: "stable",
        clientId: (await context.settings).konturClientId,
        denied: false,
        platform: platformName(context.platform),
        pluginVersion: PLUGIN_VERSION,
      };
  }
  throw unknownCommand();
}

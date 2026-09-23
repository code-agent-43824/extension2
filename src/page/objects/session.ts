import type { RutokenPlugin } from "../rutoken.ts";

// What emulated objects share: the loaded Rutoken Plugin.
export interface Session {
  plugin: RutokenPlugin;
}

import type { PinDialog, PinRequest } from "../pin-dialog.ts";
import type { RutokenPlugin } from "../rutoken.ts";

// What emulated objects share: the loaded Rutoken Plugin and the page they serve.
export interface Session {
  plugin: RutokenPlugin;
  // The page's origin, shown in the PIN window.
  origin: string;
  pinDialog(request: PinRequest): PinDialog;
}

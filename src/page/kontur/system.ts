// Kontur.Plugin's machine.uniqueId, os.getEnvironmentVariable and os.info (docs/JOURNAL.md, 2026-11-19), made up as
// Gosplugin's user and computer are (the owner, 2026-11-19: «идентификаторы фейковые по сценарию госплагина»,
// «переменные окружения - выдавай но выдуманные»): from the same made-up identity (src/page/identity.ts), so they
// stay as long as it stays and change when the options page makes a new one.
import { sha256 } from "@noble/hashes/sha2.js";
import type { FakeIdentity } from "../identity.ts";
import { invalidStructure, pluginError } from "./errors.ts";

type System = "windows" | "mac" | "linux";

const toHex = (bytes: Uint8Array) => Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");

// 64 hexadecimal digits, as the host's: a hash of the made-up computer.
export function machineId(identity: FakeIdentity): string {
  return toHex(sha256(new TextEncoder().encode(`kontur-machine|${identity.user}|${identity.computer}|${identity.mac}`)));
}

// The environment of a session of the made-up user on the made-up computer.
function environment(identity: FakeIdentity, system: System): Record<string, string> {
  const { user, computer } = identity;
  if (system === "windows") {
    const profile = `C:\\Users\\${user}`;
    return {
      ALLUSERSPROFILE: "C:\\ProgramData",
      APPDATA: `${profile}\\AppData\\Roaming`,
      CommonProgramFiles: "C:\\Program Files\\Common Files",
      COMPUTERNAME: computer,
      ComSpec: "C:\\WINDOWS\\system32\\cmd.exe",
      HOMEDRIVE: "C:",
      HOMEPATH: `\\Users\\${user}`,
      LOCALAPPDATA: `${profile}\\AppData\\Local`,
      LOGONSERVER: `\\\\${computer}`,
      NUMBER_OF_PROCESSORS: "8",
      OS: "Windows_NT",
      Path: "C:\\WINDOWS\\system32;C:\\WINDOWS;C:\\WINDOWS\\System32\\Wbem;C:\\WINDOWS\\System32\\WindowsPowerShell\\v1.0\\",
      PATHEXT: ".COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC",
      PROCESSOR_ARCHITECTURE: "AMD64",
      ProgramData: "C:\\ProgramData",
      ProgramFiles: "C:\\Program Files",
      "ProgramFiles(x86)": "C:\\Program Files (x86)",
      PUBLIC: "C:\\Users\\Public",
      SystemDrive: "C:",
      SystemRoot: "C:\\WINDOWS",
      TEMP: `${profile}\\AppData\\Local\\Temp`,
      TMP: `${profile}\\AppData\\Local\\Temp`,
      USERDOMAIN: computer,
      USERNAME: user,
      USERPROFILE: profile,
      windir: "C:\\WINDOWS",
    };
  }
  if (system === "mac") {
    return {
      HOME: `/Users/${user}`,
      LANG: "ru_RU.UTF-8",
      LOGNAME: user,
      PATH: "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin",
      SHELL: "/bin/zsh",
      TMPDIR: "/var/folders/7k/q3n1s8_d4x9b2c0000gn/T/",
      USER: user,
    };
  }
  return {
    DESKTOP_SESSION: "ubuntu",
    DISPLAY: ":0",
    HOME: `/home/${user}`,
    HOSTNAME: computer,
    LANG: "ru_RU.UTF-8",
    LOGNAME: user,
    PATH: "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    PWD: `/home/${user}`,
    SHELL: "/bin/bash",
    USER: user,
    XDG_RUNTIME_DIR: "/run/user/1000",
    XDG_SESSION_TYPE: "x11",
  };
}

// os.getEnvironmentVariable {name}: its value; Windows' names are not case-sensitive; a variable the made-up session
// has not is the host's 13.
export function environmentVariable(request: Record<string, unknown>, identity: FakeIdentity, system: System): string {
  const name = request.name;
  if (typeof name !== "string") throw invalidStructure();
  const variables = environment(identity, system);
  const key = system === "windows" ? Object.keys(variables).find((each) => each.toLowerCase() === name.toLowerCase()) : name;
  const value = key === undefined ? undefined : variables[key];
  if (value === undefined) throw pluginError(13, "environment variable is not defined");
  return value;
}

interface UserAgentData {
  getHighEntropyValues?(hints: string[]): Promise<{ platform?: string; platformVersion?: string; bitness?: string }>;
}

// os.info: {bitness, family, name, release} of the system the browser tells: Chrome's client hints where it gives
// them, the user agent otherwise.
export async function osInfo(navigator: Navigator, system: System): Promise<Record<string, unknown>> {
  let version = "";
  let bitness = /Win64|x86_64|x64|amd64|aarch64|arm64/i.test(navigator.userAgent) ? 64 : 32;
  try {
    const hints = await (navigator as Navigator & { userAgentData?: UserAgentData }).userAgentData?.getHighEntropyValues?.(["platformVersion", "bitness"]);
    version = hints?.platformVersion ?? "";
    if (hints?.bitness) bitness = Number(hints.bitness) || bitness;
  } catch {
    // The user agent alone.
  }
  if (system === "windows") {
    // Chrome's platformVersion 13 and above is Windows 11; the user agent says 10.0 for both.
    const major = Number(version.split(".")[0]);
    return { bitness, family: "Windows", name: Number.isFinite(major) && major >= 13 ? "Windows 11" : "Windows 10", release: "10.0" };
  }
  if (system === "mac") {
    const release = version || (/Mac OS X (\d+[._]\d+)/.exec(navigator.userAgent)?.[1]?.replace("_", ".") ?? "");
    return { bitness, family: "macOS", name: `macOS ${release}`.trim(), release };
  }
  return { bitness, family: "Linux", name: "Linux", release: version };
}

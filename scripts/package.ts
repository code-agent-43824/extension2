// Packs the built extension into dist/<name>-<version>.zip for installing by hand: unzip, then
// chrome://extensions → developer mode → "Load unpacked" on the folder inside. A plain ZIP writer
// (deflate, no extras): the format needs nothing more, and it saves a dependency.
import { crc32, deflateRawSync } from "node:zlib";
import { readdirSync, readFileSync, writeFileSync } from "node:fs";
import { join, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { buildExtension, extensionDir, packageVersion } from "./build.ts";
import { repoRoot } from "./fetch-vendor.ts";

export const packageName = "cryptopro-via-rutoken";

export function packagePath(version = packageVersion()): string {
  return join(repoRoot, "dist", `${packageName}-${version}.zip`);
}

interface Entry {
  name: string;
  data: Buffer;
}

// The DOS date and time ZIP stores; a fixed one keeps the archive reproducible.
const DOS_TIME = 0;
const DOS_DATE = ((2026 - 1980) << 9) | (1 << 5) | 1;

export function zip(entries: Entry[]): Buffer {
  const locals: Buffer[] = [];
  const centrals: Buffer[] = [];
  let offset = 0;
  for (const { name, data } of entries) {
    const nameBytes = Buffer.from(name, "utf8");
    const packed = deflateRawSync(data, { level: 9 });
    const crc = crc32(data);
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4); // version needed
    local.writeUInt16LE(0x0800, 6); // UTF-8 names
    local.writeUInt16LE(8, 8); // deflate
    local.writeUInt16LE(DOS_TIME, 10);
    local.writeUInt16LE(DOS_DATE, 12);
    local.writeUInt32LE(crc, 14);
    local.writeUInt32LE(packed.length, 18);
    local.writeUInt32LE(data.length, 22);
    local.writeUInt16LE(nameBytes.length, 26);
    locals.push(local, nameBytes, packed);
    const central = Buffer.alloc(46);
    central.writeUInt32LE(0x02014b50, 0);
    central.writeUInt16LE(20, 4); // version made by
    central.writeUInt16LE(20, 6);
    central.writeUInt16LE(0x0800, 8);
    central.writeUInt16LE(8, 10);
    central.writeUInt16LE(DOS_TIME, 12);
    central.writeUInt16LE(DOS_DATE, 14);
    central.writeUInt32LE(crc, 16);
    central.writeUInt32LE(packed.length, 20);
    central.writeUInt32LE(data.length, 24);
    central.writeUInt16LE(nameBytes.length, 28);
    central.writeUInt32LE(offset, 42);
    centrals.push(central, nameBytes);
    offset += local.length + nameBytes.length + packed.length;
  }
  const directory = Buffer.concat(centrals);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(entries.length, 8);
  end.writeUInt16LE(entries.length, 10);
  end.writeUInt32LE(directory.length, 12);
  end.writeUInt32LE(offset, 16);
  return Buffer.concat([...locals, directory, end]);
}

// Every file under `dir`, sorted, named `folder/<path>` with forward slashes.
export function directoryEntries(dir: string, folder: string): Entry[] {
  return readdirSync(dir, { recursive: true, withFileTypes: true })
    .filter((entry) => entry.isFile())
    .map((entry) => join(entry.parentPath, entry.name))
    .sort()
    .map((path) => ({ name: `${folder}/${relative(dir, path).split(sep).join("/")}`, data: readFileSync(path) }));
}

export async function packageExtension(): Promise<string> {
  await buildExtension();
  const version = packageVersion();
  const target = packagePath(version);
  writeFileSync(target, zip(directoryEntries(extensionDir, `${packageName}-${version}`)));
  return target;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  console.log(`packed ${await packageExtension()}`);
}

// Talks to the real Kontur.Plugin host that scripts/setup-kontur.ts unpacked, over Native Messaging as its extension
// does: a little-endian length, then JSON; the request envelope is the page's (sessionId, commandId, type, the
// command's fields) with hostUri, the page's origin, added as the extension's content script adds it. Long answers
// come in chunks ({isChunked, id, data, isFinalChunk}) that are joined here, as the extension's background joins them.
// The host is a GTK program: it runs on the X display the stand starts (Xvfb).
import { spawn, type ChildProcess } from "node:child_process";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { kontur } from "../../scripts/setup-kontur.ts";
import { display, startDisplay } from "./gosplugins.ts";

export interface KonturAnswer {
  sessionId?: string;
  commandId?: number;
  result?: any;
  error?: { type?: string; code?: number; message?: string; [key: string]: unknown };
  [key: string]: unknown;
}

export interface KonturHost {
  // Sends one command and waits for its answer (by commandId).
  ask(type: string, fields?: Record<string, unknown>, options?: { hostUri?: string; timeoutMs?: number }): Promise<KonturAnswer>;
  close(): void;
}

// `home` is a copy of the stand HOME with its token: the one setup-kontur.ts made, or another one.
export function konturHost(sessionId = "s-stand", home = kontur.home): KonturHost {
  startDisplay();
  const child: ChildProcess = spawn(kontur.host, [kontur.origin], {
    env: { ...process.env, HOME: home, DISPLAY: display, LANG: "C.UTF-8" },
    stdio: ["pipe", "pipe", "ignore"],
  });
  let buffer = Buffer.alloc(0);
  const chunks = new Map<string, string>();
  const waiting = new Map<number, (answer: KonturAnswer) => void>();
  const deliver = (answer: KonturAnswer) => {
    const resolve = typeof answer.commandId === "number" ? waiting.get(answer.commandId) : undefined;
    if (resolve) {
      waiting.delete(answer.commandId!);
      resolve(answer);
    }
  };
  child.stdout!.on("data", (chunk: Buffer) => {
    buffer = Buffer.concat([buffer, chunk]);
    while (buffer.length >= 4 && buffer.length >= 4 + buffer.readUInt32LE(0)) {
      const length = buffer.readUInt32LE(0);
      const message = JSON.parse(new TextDecoder().decode(buffer.subarray(4, 4 + length)));
      buffer = buffer.subarray(4 + length);
      if (message.isChunked) {
        const joined = (chunks.get(message.id) ?? "") + message.data;
        if (!message.isFinalChunk) {
          chunks.set(message.id, joined);
          continue;
        }
        chunks.delete(message.id);
        deliver(JSON.parse(joined));
      } else {
        deliver(message);
      }
    }
  });
  let commandId = 0;
  return {
    ask(type, fields = {}, { hostUri = "https://extern.kontur.ru", timeoutMs = 60_000 } = {}) {
      const id = ++commandId;
      const body = Buffer.from(JSON.stringify({ sessionId, commandId: id, type, ...fields, hostUri }));
      const header = Buffer.alloc(4);
      header.writeUInt32LE(body.length);
      return new Promise((resolve, reject) => {
        const timer = setTimeout(() => {
          waiting.delete(id);
          reject(new Error(`no answer to ${type}`));
        }, timeoutMs);
        waiting.set(id, (answer) => {
          clearTimeout(timer);
          resolve(answer);
        });
        child.stdin!.write(Buffer.concat([header, body]));
      });
    },
    close() {
      child.stdin!.end();
      child.kill();
    },
  };
}

// An HTTP server for http.request: it answers with what it got (method, path, headers, body as Latin-1) as JSON, with
// CORS for any page; /missing is 404 "Not Here", /slow waits three seconds.
export async function echoServer(): Promise<{ url: string; close: () => Promise<void> }> {
  const server = createServer((request, response) => {
    const chunks: Buffer[] = [];
    request.on("data", (chunk: Buffer) => chunks.push(chunk));
    request.on("end", () => {
      const reply = () => {
        const body = JSON.stringify({ method: request.method, path: request.url, headers: request.headers, body: Buffer.concat(chunks).toString("latin1") });
        const missing = request.url?.startsWith("/missing");
        response.writeHead(missing ? 404 : 200, missing ? "Not Here" : "OK", {
          "Content-Type": "application/json",
          "X-Echo": "1",
          "Access-Control-Allow-Origin": String(request.headers.origin ?? "*"),
          "Access-Control-Allow-Credentials": "true",
          "Access-Control-Allow-Headers": "*",
          "Access-Control-Allow-Methods": "*",
          "Access-Control-Expose-Headers": "*",
        });
        response.end(request.method === "HEAD" ? undefined : body);
      };
      if (request.url?.startsWith("/slow")) setTimeout(reply, 3000);
      else reply();
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  return { url: `http://127.0.0.1:${(server.address() as AddressInfo).port}`, close: () => new Promise((resolve) => server.close(() => resolve())) };
}

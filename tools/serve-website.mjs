// Lokale Vorschau der Webseite ohne Docker – verhält sich wie der nginx-Container:
// gleiche Sicherheits-Header (CSP), /downloads/ kommt aus dist/ (nach .\publish.ps1).
//
//   node tools/serve-website.mjs [port]
import { createServer } from "node:http";
import { readFile, stat } from "node:fs/promises";
import { extname, join, normalize, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(fileURLToPath(new URL("..", import.meta.url)));
const site = join(root, "website");
const downloads = join(root, "dist");
const port = Number(process.argv[2] || process.env.PORT || 8085);

const types = {
  ".html": "text/html; charset=utf-8", ".css": "text/css; charset=utf-8", ".js": "application/javascript; charset=utf-8",
  ".json": "application/json", ".png": "image/png", ".ico": "image/x-icon", ".svg": "image/svg+xml",
  ".exe": "application/octet-stream", ".txt": "text/plain; charset=utf-8",
};
const security = {
  "Content-Security-Policy": "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "Referrer-Policy": "no-referrer",
};

/** Pfad sicher auflösen – kein Ausbruch aus dem Basisordner (../). */
function safeJoin(base, rel) {
  const p = normalize(join(base, decodeURIComponent(rel)));
  return p === base || p.startsWith(base + sep) ? p : null;
}

createServer(async (req, res) => {
  const url = new URL(req.url, "http://localhost");
  let file;
  if (url.pathname === "/healthz") { res.writeHead(200, security).end("ok\n"); return; }
  if (url.pathname.startsWith("/downloads/")) {
    const name = url.pathname.slice("/downloads/".length);
    file = name.startsWith(".") ? null : safeJoin(downloads, name);
  } else {
    file = safeJoin(site, url.pathname === "/" ? "index.html" : url.pathname.slice(1));
  }
  try {
    if (!file || !(await stat(file)).isFile()) throw new Error("404");
    const body = await readFile(file);
    const headers = { ...security, "Content-Type": types[extname(file).toLowerCase()] || "application/octet-stream" };
    if (file.endsWith("latest.json")) headers["Cache-Control"] = "no-store";
    res.writeHead(200, headers).end(body);
  } catch {
    res.writeHead(404, { ...security, "Content-Type": "text/plain; charset=utf-8" }).end("404 – nicht gefunden\n");
  }
  console.log(`${res.statusCode} ${req.method} ${url.pathname}`);
}).listen(port, "127.0.0.1", () => console.log(`ClipSec-Webseite: http://localhost:${port}/`));

// Minimal static server for the exported demo (tests and local preview). No dependencies.
import { createReadStream, existsSync, statSync } from "node:fs";
import { createServer } from "node:http";
import { extname, join, normalize } from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../out", import.meta.url));
const port = Number(process.env.PORT ?? 3001);
const types = { ".html": "text/html", ".js": "text/javascript", ".css": "text/css", ".wasm": "application/wasm", ".json": "application/json", ".woff2": "font/woff2", ".woff": "font/woff", ".svg": "image/svg+xml", ".txt": "text/plain" };
createServer((req, res) => {
  const url = decodeURIComponent((req.url ?? "/").split("?")[0]);
  let p = normalize(join(root, url));
  if (!p.startsWith(root)) return res.writeHead(403).end();
  if (existsSync(p) && statSync(p).isDirectory()) p = join(p, "index.html");
  if (!existsSync(p)) return res.writeHead(404).end("not found");
  res.writeHead(200, { "Content-Type": types[extname(p)] ?? "application/octet-stream" });
  createReadStream(p).pipe(res);
}).listen(port, () => console.log(`demo on http://localhost:${port}`));

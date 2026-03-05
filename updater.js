import https from "https";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { reloadDisposableDomains } from "./validator.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const BLOCKLIST_URL = "https://raw.githubusercontent.com/disposable-email-domains/disposable-email-domains/master/disposable_email_blocklist.conf";
const ALLOWLIST_URL = "https://raw.githubusercontent.com/disposable-email-domains/disposable-email-domains/master/allowlist.conf";
const DISPOSABLE_JSON_PATH = path.join(__dirname, "disposableDomains.json");

function fetchText(url) {
  return new Promise((resolve, reject) => {
    https.get(url, (res) => {
      if (res.statusCode !== 200) {
        return reject(new Error(`Failed to fetch ${url}: ${res.statusCode}`));
      }
      let data = "";
      res.on("data", (chunk) => (data += chunk));
      res.on("end", () => resolve(data));
    }).on("error", reject);
  });
}

function parseLines(text) {
  return text
    .split(/\r?\n/)
    .map((l) => l.trim().toLowerCase())
    .filter((l) => l && !l.startsWith("#"));
}

export async function updateDisposableDomains() {
  const [blockText, allowText] = await Promise.all([fetchText(BLOCKLIST_URL), fetchText(ALLOWLIST_URL)]);
  const blockSet = new Set(parseLines(blockText));
  const allowSet = new Set(parseLines(allowText));

  for (const d of allowSet) {
    blockSet.delete(d);
  }

  const list = Array.from(blockSet).sort();
  fs.writeFileSync(DISPOSABLE_JSON_PATH, JSON.stringify(list, null, 2), "utf-8");
  reloadDisposableDomains();
  return { updated: list.length };
}

export function scheduleDisposableDomainUpdates(intervalMs = 24 * 60 * 60 * 1000) {
  const timer = setInterval(() => {
    updateDisposableDomains().catch(() => {});
  }, intervalMs);
  return timer;
}

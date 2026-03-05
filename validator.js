import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const domainsPath = path.join(__dirname, "disposableDomains.json");
let domainSet = new Set(JSON.parse(fs.readFileSync(domainsPath, "utf-8")));

export function isBlacklisted(domain) {
  const parts = domain.toLowerCase().split(".");
  for (let i = 0; i < parts.length - 1; i++) {
    const candidate = parts.slice(i).join(".");
    if (domainSet.has(candidate)) return true;
  }
  return false;
}

export function reloadDisposableDomains() {
  try {
    const domains = JSON.parse(fs.readFileSync(domainsPath, "utf-8"));
    domainSet = new Set(domains);
    return true;
  } catch {
    return false;
  }
}

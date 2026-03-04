import fs from "fs";
import path from "path";

// Read JSON file synchronously
const domainsPath = path.resolve("./disposableDomains.json");
const domains = JSON.parse(fs.readFileSync(domainsPath, "utf-8"));

const domainSet = new Set(domains);

export function isBlacklisted(domain) {
  return domainSet.has(domain.toLowerCase());
}
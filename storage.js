import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { reloadDisposableDomains } from "./validator.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const flaggedPath = path.join(__dirname, "flaggedEmails.json");
const disposablePath = path.join(__dirname, "disposableDomains.json");

function readFlagged() {
  try {
    const txt = fs.readFileSync(flaggedPath, "utf-8");
    return JSON.parse(txt);
  } catch {
    return [];
  }
}

function writeFlagged(arr) {
  fs.writeFileSync(flaggedPath, JSON.stringify(arr, null, 2), "utf-8");
}

export function appendFlaggedEmail(email, domain, riskLevel) {
  try {
    const list = readFlagged();
    const exists = list.some(e => e.email === email);
    if (exists) return false;
    list.push({ email, domain, riskLevel, ts: Date.now() });
    writeFlagged(list);
    return true;
  } catch {
    return false;
  }
}

export function appendDisposableDomain(domain) {
  try {
    let candidate = (domain || "").toLowerCase().trim();
    if (candidate.includes("@")) {
      candidate = candidate.split("@").pop().trim();
    }
    candidate = candidate.replace(/^\.+|\.+$/g, "");
    if (!candidate) return false;
    if (!candidate.includes(".")) return false;
    const arr = JSON.parse(fs.readFileSync(disposablePath, "utf-8"));
    if (!Array.isArray(arr)) return false;
    if (arr.includes(candidate)) return false;
    arr.push(candidate);
    arr.sort();
    fs.writeFileSync(disposablePath, JSON.stringify(arr, null, 2), "utf-8");
    reloadDisposableDomains();
    return true;
  } catch {
    return false;
  }
}

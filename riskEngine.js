import { isBlacklisted } from "./validator.js";
import { SUSPICIOUS_TLDS } from "./suspiciousTlds.js";
import { calculateEntropy } from "./domainEntropy.js";
import { getDomainAgeInDays } from "./domainAge.js";
import dns from "dns/promises";
import { FREE_EMAIL_PROVIDERS } from "./freeProviders.js";

const mxCache = new Map();
const rateLimitCache = new Map();

async function hasMXRecord(domain) {
  if (mxCache.has(domain)) return mxCache.get(domain);

  try {
    const records = await dns.resolveMx(domain);
    const result = records.length > 0;
    mxCache.set(domain, result);
    return result;
  } catch {
    mxCache.set(domain, false);
    return false;
  }
}

async function isCatchAll(domain) {
  return false; // placeholder
}

export async function validateEmail(email, options = {}) {
  const domain = email.split("@")[1]?.toLowerCase();
  if (!domain) return { email, isDisposable: true, score: 100, reason: ["Invalid email format"], riskLevel: "high" };

  if (options.customWhitelist?.includes(domain)) {
    return { email, isDisposable: false, score: 0, reason: ["Domain in whitelist"], riskLevel: "low" };
  }

  const now = Date.now();
  const lastCall = rateLimitCache.get(domain) || 0;
  if (now - lastCall < 1000) throw new Error(`Rate limit exceeded for ${domain}`);
  rateLimitCache.set(domain, now);

  let score = 0;
  const reasons = [];
  const w = { disposable: 80, customBlacklist: 90, mx: 50, tld: 25, entropy: 30, age30: 40, age90: 20, freeProvider: 15, educational: -20, ...options.signalWeights };

  if (isBlacklisted(domain)) { score += w.disposable; reasons.push("Disposable domain detected"); }
  if (options.customBlacklist?.includes(domain)) { score += w.customBlacklist; reasons.push("Custom blacklist domain"); }

  const mxExists = await hasMXRecord(domain);
  if (!mxExists) { score += w.mx; reasons.push("No MX record found"); }

  let tldSuspicious = false;
  for (const tld of SUSPICIOUS_TLDS) {
    if (domain.endsWith(tld)) { score += w.tld; tldSuspicious = true; reasons.push("Suspicious TLD detected"); break; }
  }

  const domainName = domain.split(".")[0];
  const entropy = calculateEntropy(domainName);
  if (domainName.length > 8 && entropy > 3.5) { score += w.entropy; reasons.push("Random-looking domain"); }

  const ageInDays = await getDomainAgeInDays(domain);
  if (ageInDays !== null) {
    if (ageInDays < 30) { score += w.age30; reasons.push("Very new domain (<30 days)"); }
    else if (ageInDays < 90) { score += w.age90; reasons.push("New domain (<90 days)"); }
  }

  if (domain.endsWith(".edu") || domain.endsWith(".edu.in") || domain.endsWith(".ac.in")) { score += w.educational; reasons.push("Educational domain trust boost"); }

  const isFreeProvider = FREE_EMAIL_PROVIDERS.has(domain);
  if (isFreeProvider) { score += w.freeProvider; reasons.push("Free email provider"); }

  let catchAll = false;
  if (options.enableCatchAllCheck) { catchAll = await isCatchAll(domain); if (catchAll) { score += 50; reasons.push("Catch-all domain"); } }

  let riskLevel;
  if (score >= 60) riskLevel = "high";
  else if (score >= 25) riskLevel = "medium";
  else riskLevel = "low";

  return { email, isDisposable: score >= 60, score, riskLevel, reason: reasons, mxExists, entropy, ageInDays, isFreeProvider, tldSuspicious, catchAll };
}

export async function validateEmailsBatch(emails, options = {}) {
  return Promise.all(emails.map(email => validateEmail(email, options)));
}
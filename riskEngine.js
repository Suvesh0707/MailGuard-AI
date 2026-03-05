import { isBlacklisted } from "./validator.js";
import { SUSPICIOUS_TLDS } from "./suspiciousTlds.js";
import { calculateEntropy } from "./domainEntropy.js";
import { getDomainAgeInDays } from "./domainAge.js";
import dns from "dns/promises";
import { FREE_EMAIL_PROVIDERS } from "./freeProviders.js";
import { appendFlaggedEmail, appendDisposableDomain } from "./storage.js";

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
  const atIndex = email.indexOf("@");
  const local = atIndex > 0 ? email.slice(0, atIndex) : "";
  const domain = atIndex > 0 ? email.slice(atIndex + 1).toLowerCase() : "";
  const syntaxValid = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) && local.length <= 64 && domain.length > 0;
  if (!syntaxValid) {
    const score = 100;
    const riskLevel = "high";
    const reasons = ["Syntax validation failed"];
    const candidateDomain = domain || (email.includes("@") ? email.split("@")[1] : email);
    const addedToFlaggedList = appendFlaggedEmail(email, domain || "", "high");
    const addedToDisposableDomains = appendDisposableDomain(candidateDomain);
    const checks = {
      syntaxValidation: false,
      domainExtraction: { local, domain },
      globalBlacklist: false,
      customBlacklist: false,
      disposableProvider: false,
      mxRecord: null,
      suspiciousTLD: false,
      domainEntropy: "normal",
      domainAge: "unknown",
      domainReputation: false,
      roleBased: false,
      usernamePattern: "normal",
      emailLengthStructure: true,
      subdomainAbuse: false,
      homographRisk: false,
      catchAllDomain: null,
      educationalDomainTrust: false,
      governmentDomainTrust: false,
      corporateDomainTrust: false,
      disposableDomainPattern: false,
      smtpMailboxVerification: null,
      ipReputation: null,
      botRegistrationBehavior: null,
      emailFrequency: null,
      riskScoringEngine: "active",
      addedToFlaggedList,
      addedToDisposableDomains,
      mediumQueuedForReview: false
    };
    return {
      email,
      isDisposable: true,
      score,
      riskScore: score,
      riskLevel,
      reason: reasons,
      checks
    };
  }

  if (options.customWhitelist?.includes(domain)) {
    return { email, isDisposable: false, score: 0, reason: ["Domain in whitelist"], riskLevel: "low" };
  }

  const now = Date.now();
  const lastCall = rateLimitCache.get(domain) || 0;
  if (now - lastCall < 1000) throw new Error(`Rate limit exceeded for ${domain}`);
  rateLimitCache.set(domain, now);

  let score = 0;
  const reasons = [];
  const w = {
    disposable: 80,
    customBlacklist: 90,
    mx: 50,
    tld: 25,
    entropy: 30,
    age30: 40,
    age90: 20,
    freeProvider: 15,
    educational: -20,
    governmentTrust: -25,
    corporateTrust: -15,
    roleBased: 5,
    usernamePattern: 10,
    lengthStructure: 10,
    subdomainAbuse: 15,
    homograph: 25,
    disposablePattern: 40,
    domainReputation: 15,
    ...options.signalWeights
  };

  const blacklisted = isBlacklisted(domain);
  if (blacklisted) { score += w.disposable; reasons.push("Disposable domain detected"); }
  const customBlacklisted = options.customBlacklist?.includes(domain);
  if (customBlacklisted) { score += w.customBlacklist; reasons.push("Custom blacklist domain"); }

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

  let educationalTrustApplied = false;
  let governmentTrustApplied = false;
  let corporateTrustApplied = false;
  if (domain.endsWith(".edu") || domain.endsWith(".edu.in") || domain.endsWith(".ac.in")) { score += w.educational; reasons.push("Educational domain trust boost"); educationalTrustApplied = true; }
  if (domain.endsWith(".gov") || domain.endsWith(".gov.in")) { score += w.governmentTrust; reasons.push("Government domain trust boost"); governmentTrustApplied = true; }
  if (options.corporateWhitelist?.includes(domain)) { score += w.corporateTrust; reasons.push("Corporate domain trust boost"); corporateTrustApplied = true; }

  const isFreeProvider = FREE_EMAIL_PROVIDERS.has(domain);
  if (isFreeProvider) { score += w.freeProvider; reasons.push("Free email provider"); }

  const roleSet = new Set(["admin","support","info","sales","contact","billing","noreply","no-reply","helpdesk","hr"]);
  const isRoleBased = roleSet.has(local.toLowerCase());
  if (isRoleBased) { score += w.roleBased; reasons.push("Role-based email address"); }

  const localEntropy = calculateEntropy(local.replace(/[^a-z0-9]/gi, ""));
  if (local.length > 10 && localEntropy > 3.5) { score += w.usernamePattern; reasons.push("Random-looking username"); }

  let lengthStructureIssues = false;
  if (email.length > 254 || local.length === 0 || domain.length === 0) lengthStructureIssues = true;
  if (/\.\./.test(email) || local.startsWith(".") || local.endsWith(".") || domain.startsWith("-") || domain.endsWith("-")) lengthStructureIssues = true;
  if (lengthStructureIssues) { score += w.lengthStructure; reasons.push("Length/structure anomalies"); }

  const labels = domain.split(".");
  const subdomainAbuse = labels.length > 3;
  if (subdomainAbuse) { score += w.subdomainAbuse; reasons.push("Excessive subdomains"); }

  const hasUnicode = /[^\x00-\x7F]/.test(domain) || domain.startsWith("xn--");
  const mixedScripts = /[А-яЁё]/.test(domain) && /[A-Za-z]/.test(domain);
  const homograph = hasUnicode || mixedScripts;
  if (homograph) { score += w.homograph; reasons.push("Homograph/Unicode risk"); }

  const disposablePatterns = [
    "mailinator",
    "tempmail",
    "throwaway",
    "10minutemail",
    "guerrillamail",
    "trashmail",
    "yopmail",
    "fakeinbox",
    "spambox",
    "hidingmail",
    "getnada",
    "sharklasers",
    "maildrop",
    "dispostable",
    "burnermail",
    "moakt",
    "dropmail",
    "mail.tm",
    "linshi",
    "luxusmail",
    "temporarymail",
    "emailondeck",
    "mytemp",
    "mintemail",
    "spamgourmet"
  ];
  let disposablePatternHit = false;
  for (const p of disposablePatterns) { if (domain.includes(p)) { disposablePatternHit = true; break; } }
  if (disposablePatternHit) { score += w.disposablePattern; reasons.push("Disposable-like domain pattern"); }

  let domainReputationFlag = false;
  try {
    const mx = await dns.resolveMx(domain);
    const hosts = mx.map(r => r.exchange.toLowerCase());
    const repBadPatterns = ["mailinator","guerrillamail","tempmail"];
    domainReputationFlag = hosts.some(h => repBadPatterns.some(p => h.includes(p)));
    if (domainReputationFlag) { score += w.domainReputation; reasons.push("MX reputation concern"); }
  } catch {}

  let catchAll = false;
  if (options.enableCatchAllCheck) { catchAll = await isCatchAll(domain); if (catchAll) { score += 50; reasons.push("Catch-all domain"); } }

  let riskLevel;
  if (score >= 60) riskLevel = "high";
  else if (score >= 25) riskLevel = "medium";
  else riskLevel = "low";

  let addedToFlaggedList = false;
  let mediumQueuedForReview = false;
  if (riskLevel === "high") {
    addedToFlaggedList = appendFlaggedEmail(email, domain, "high");
    appendDisposableDomain(domain);
  } else if (riskLevel === "medium") {
    mediumQueuedForReview = appendFlaggedEmail(email, domain, "medium");
  }

  const checks = {
    syntaxValidation: syntaxValid,
    domainExtraction: { local, domain },
    globalBlacklist: !!blacklisted,
    customBlacklist: !!customBlacklisted,
    disposableProvider: !!isFreeProvider,
    mxRecord: !!mxExists,
    suspiciousTLD: !!tldSuspicious,
    domainEntropy: domainName.length > 8 && entropy > 3.5 ? "high" : "normal",
    domainAge: ageInDays !== null ? `${ageInDays} days` : "unknown",
    domainReputation: !!domainReputationFlag,
    roleBased: !!isRoleBased,
    usernamePattern: local.length > 10 && localEntropy > 3.5 ? "high" : "normal",
    emailLengthStructure: !!lengthStructureIssues,
    subdomainAbuse: !!subdomainAbuse,
    homographRisk: !!homograph,
    catchAllDomain: options.enableCatchAllCheck ? !!catchAll : null,
    educationalDomainTrust: !!educationalTrustApplied,
    governmentDomainTrust: !!governmentTrustApplied,
    corporateDomainTrust: !!corporateTrustApplied,
    disposableDomainPattern: !!disposablePatternHit,
    smtpMailboxVerification: null,
    ipReputation: null,
    botRegistrationBehavior: null,
    emailFrequency: null,
    riskScoringEngine: "active",
    addedToFlaggedList: !!addedToFlaggedList,
    mediumQueuedForReview: !!mediumQueuedForReview
  };

  return {
    email,
    isDisposable: score >= 60,
    score,
    riskScore: score,
    riskLevel,
    reason: reasons,
    mxExists,
    entropy,
    ageInDays,
    isFreeProvider,
    tldSuspicious,
    catchAll,
    syntaxValid,
    isRoleBased,
    localEntropy,
    lengthStructureIssues,
    subdomainAbuse,
    homograph,
    disposablePatternHit,
    domainReputationFlag,
    checks
  };
}

export async function validateEmailsBatch(emails, options = {}) {
  return Promise.all(emails.map(email => validateEmail(email, options)));
}

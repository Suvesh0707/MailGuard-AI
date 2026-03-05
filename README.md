# suvesh-mail-guard

Author: Suvesh Pagam

Smart disposable email and risk detection engine with daily blocklist updates. Supports both ES Modules and CommonJS consumers.

## Features
- Disposable email detection using an updated upstream blocklist
- Risk scoring with multiple signals (MX records, TLD, entropy, domain age, free providers, educational domains, optional catch-all)
- Works in both ESM and CJS environments
- Batch validation for lists of emails
- Custom whitelist/blacklist and adjustable signal weights
- Daily auto-update of blocklist from the community-maintained repository

## Installation
```bash
npm install suvesh-mail-guard
```
Then import and use it as shown below for your module system.

## Usage (ESM)
```js
import {
  validateEmail,
  validateEmailsBatch,
  scheduleDisposableDomainUpdates,
} from "suvesh-mail-guard";

scheduleDisposableDomainUpdates();

const result = await validateEmail("user@example.com");
console.log(result);
```

**Validate Batch (ESM)**
```js
import { validateEmailsBatch } from "suvesh-mail-guard";

const results = await validateEmailsBatch(["a@b.com", "c@d.com"]);
console.log(results);
```

## Usage (CommonJS)
```js
const guard = require("suvesh-mail-guard");

(async () => {
  await guard.scheduleDisposableDomainUpdates();
  const result = await guard.validateEmail("user@example.com");
  console.log(result);
})();
```

**Validate Batch (CJS)**
```js
const guard = require("suvesh-mail-guard");

(async () => {
  const results = await guard.validateEmailsBatch(["a@b.com", "c@d.com"]);
  console.log(results);
})();
```

## API
- `validateEmail(email, options?)`
  - Returns core fields:
    - `email`, `isDisposable`, `score` (alias: `riskScore`), `riskLevel`, `reason`
    - `mxExists`, `entropy`, `ageInDays`, `isFreeProvider`, `tldSuspicious`, `catchAll`
  - Also returns a `checks` object that summarizes all layers:
    - `syntaxValidation`: boolean
    - `domainExtraction`: `{ local, domain }`
    - `globalBlacklist`: boolean
    - `customBlacklist`: boolean
    - `disposableProvider`: boolean
    - `mxRecord`: boolean
    - `suspiciousTLD`: boolean
    - `domainEntropy`: `"high" | "normal"`
    - `domainAge`: `"<N> days" | "unknown"`
    - `domainReputation`: boolean
    - `roleBased`: boolean
    - `usernamePattern`: `"high" | "normal"`
    - `emailLengthStructure`: boolean
    - `subdomainAbuse`: boolean
    - `homographRisk`: boolean
    - `catchAllDomain`: boolean | null (null when disabled)
    - `educationalDomainTrust`: boolean
    - `governmentDomainTrust`: boolean
    - `corporateDomainTrust`: boolean
    - `disposableDomainPattern`: boolean
    - `smtpMailboxVerification`: null
    - `ipReputation`: null
    - `botRegistrationBehavior`: null
    - `emailFrequency`: null
    - `riskScoringEngine`: `"active"`
    - `addedToFlaggedList`: boolean
    - `mediumQueuedForReview`: boolean
- `validateEmailsBatch(emails, options?)`
  - Promise of `validateEmail` results for each email
- `updateDisposableDomains()`
  - Downloads upstream lists, updates `disposableDomains.json`, hot-reloads in memory
- `scheduleDisposableDomainUpdates(intervalMs = 24 * 60 * 60 * 1000)`
  - Starts a timer to call `updateDisposableDomains()` at the given interval

### Options
- `customWhitelist?: string[]`
- `customBlacklist?: string[]`
- `enableCatchAllCheck?: boolean`
- `signalWeights?: Partial<{ disposable; customBlacklist; mx; tld; entropy; age30; age90; freeProvider; educational; }>`

## Auto‑Flagging and Storage
- High risk results automatically append the domain to `disposableDomains.json` and add the email to `flaggedEmails.json`.
- Medium risk results add the email to `flaggedEmails.json` for review (blocklist is not modified).
- Files are stored in the package directory and hot‑reloaded by the validator.

Example:
```js
const r = await validateEmail("user@hidingmail.com");
console.log(r.riskLevel);       // "high"
console.log(r.checks.addedToFlaggedList);        // true
console.log(r.checks.disposableDomainPattern);   // true
```

## Data Source and Update Strategy
Source: https://github.com/disposable-email-domains/disposable-email-domains
- Blocklist: `disposable_email_blocklist.conf`
- Allowlist: `allowlist.conf`
- Second-level domains are stored; parent domain matching is applied
- Allowlisted domains are removed from the final JSON

Manual update:
```bash
npm run update:domains
```

## Notes
- Requires Node.js 18+
- DNS lookups rely on system DNS and may be affected by transient errors
- Per-domain rate limiting avoids excessive network calls
 - WHOIS (port 43) is used to compute `domainAge`; if unreachable or unsupported, age will be `unknown`.

## License
ISC


## Contributors
AI Assistant support provided during development

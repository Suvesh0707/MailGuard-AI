const importRiskEngine = () => import("./riskEngine.js");
const importUpdater = () => import("./updater.js");

module.exports.validateEmail = async function validateEmail(email, options = {}) {
  const m = await importRiskEngine();
  return m.validateEmail(email, options);
};

module.exports.validateEmailsBatch = async function validateEmailsBatch(emails, options = {}) {
  const m = await importRiskEngine();
  return m.validateEmailsBatch(emails, options);
};

module.exports.updateDisposableDomains = async function updateDisposableDomains() {
  const u = await importUpdater();
  return u.updateDisposableDomains();
};

module.exports.scheduleDisposableDomainUpdates = async function scheduleDisposableDomainUpdates(intervalMs) {
  const u = await importUpdater();
  return u.scheduleDisposableDomainUpdates(intervalMs);
};

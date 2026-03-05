import net from "net";

const ageCache = new Map();

function parseCreationDate(whoisText) {
  const patterns = [
    /Creation Date:\s*([^\r\n]+)/i,
    /Created On:\s*([^\r\n]+)/i,
    /Domain Registration Date:\s*([^\r\n]+)/i,
    /Registered:\s*([^\r\n]+)/i,
    /created:\s*([^\r\n]+)/i,
    /Create Date:\s*([^\r\n]+)/i,
    /Registration Time:\s*([^\r\n]+)/i
  ];
  for (const re of patterns) {
    const m = whoisText.match(re);
    if (m) return new Date(m[1].trim());
  }
  return null;
}

function parseReferralServer(whoisText) {
  const m =
    whoisText.match(/Registrar WHOIS Server:\s*([^\r\n]+)/i) ||
    whoisText.match(/Whois Server:\s*([^\r\n]+)/i);
  if (m) return m[1].trim();
  return null;
}

function whoisServerForTld(tld) {
  const map = {
    com: "whois.verisign-grs.com",
    net: "whois.verisign-grs.com",
    org: "whois.pir.org",
    io: "whois.nic.io",
    ai: "whois.ai",
    in: "whois.registry.in",
    dev: "whois.google"
  };
  return map[tld] || `${tld}.whois-servers.net`;
}

function whoisQuery(server, query) {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection(43, server);
    let data = "";
    socket.setTimeout(5000);
    socket.on("connect", () => socket.write(query + "\r\n"));
    socket.on("data", (chunk) => (data += chunk.toString("utf-8")));
    socket.on("timeout", () => { socket.destroy(); reject(new Error("WHOIS timeout")); });
    socket.on("error", (err) => reject(err));
    socket.on("end", () => resolve(data));
  });
}

export async function getDomainAgeInDays(domain) {
  if (ageCache.has(domain)) return ageCache.get(domain);
  try {
    const tld = domain.split(".").pop();
    const server = whoisServerForTld(tld);
    let text = await whoisQuery(server, domain);
    let created = parseCreationDate(text);
    if (!created) {
      const referral = parseReferralServer(text);
      if (referral) {
        try {
          text = await whoisQuery(referral, domain);
          created = parseCreationDate(text);
        } catch {}
      }
    }
    if (!created || isNaN(created.getTime())) {
      ageCache.set(domain, null);
      return null;
    }
    const days = Math.floor((Date.now() - created.getTime()) / (1000 * 60 * 60 * 24));
    ageCache.set(domain, days);
    return days;
  } catch {
    ageCache.set(domain, null);
    return null;
  }
}

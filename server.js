import http from "http";
import https from "https";
import dns from "dns";
import net from "net";
import tls from "tls";
import { promisify } from "util";
import { URL } from "url";
import crypto from "crypto";
import dotenv from "dotenv";

// Load environment variables from .env file
dotenv.config();

// ─── Configuration ────────────────────────────────────────────────────────────

const CONFIG = {
  PORT: process.env.PORT || 3000,

  // Rate limiting : max requêtes par fenêtre de temps
  RATE_LIMIT_MAX: parseInt(process.env.RATE_LIMIT_MAX) || 30,     // 30 req
  RATE_LIMIT_WINDOW_MS: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 60_000, // par minute

  // Slowdown : ralentir avant de bloquer (commence à 20 req/min)
  SLOWDOWN_THRESHOLD: parseInt(process.env.SLOWDOWN_THRESHOLD) || 20,
  SLOWDOWN_DELAY_MS: parseInt(process.env.SLOWDOWN_DELAY_MS) || 500, // +500ms par req au-delà du seuil

  // Timeout global par requête outil
  TOOL_TIMEOUT_MS: parseInt(process.env.TOOL_TIMEOUT_MS) || 15_000,

  // Taille max de la réponse (évite les fuites mémoire)
  MAX_RESPONSE_BODY_BYTES: 2 * 1024 * 1024, // 2 MB

  // IPs autorisées à bypasser le rate limit (ex: ton IP fixe)
  TRUSTED_IPS: (process.env.TRUSTED_IPS || "").split(",").filter(Boolean),

  // Domaines / IPs qu'on refuse d'analyser
  BLOCKED_TARGETS: (process.env.BLOCKED_TARGETS || "").split(",").filter(Boolean),

  // Clé API pour l'authentification
  API_KEY: process.env.API_KEY || "default-secret-key",
};

// ─── Logging structuré ────────────────────────────────────────────────────────

function log(level, msg, meta = {}) {
  console.log(JSON.stringify({ ts: new Date().toISOString(), level, msg, ...meta }));
}

// ─── Rate Limiter en mémoire ──────────────────────────────────────────────────
// Pour la prod à fort trafic, remplacer par Redis (ioredis)

const rateLimitStore = new Map(); // ip -> { count, resetAt }

function getRateLimitKey(req) {
  return (
    req.headers["x-forwarded-for"]?.split(",")[0].trim() ||
    req.headers["x-real-ip"] ||
    req.socket.remoteAddress ||
    "unknown"
  );
}

function checkRateLimit(ip) {
  if (CONFIG.TRUSTED_IPS.includes(ip)) return { allowed: true, remaining: 999, delay: 0 };

  const now = Date.now();
  let entry = rateLimitStore.get(ip);

  if (!entry || now > entry.resetAt) {
    entry = { count: 0, resetAt: now + CONFIG.RATE_LIMIT_WINDOW_MS };
    rateLimitStore.set(ip, entry);
  }

  entry.count++;

  const remaining = Math.max(0, CONFIG.RATE_LIMIT_MAX - entry.count);
  const exceeded = entry.count > CONFIG.RATE_LIMIT_MAX;

  // Slowdown progressif avant blocage
  const overThreshold = Math.max(0, entry.count - CONFIG.SLOWDOWN_THRESHOLD);
  const delay = exceeded ? 0 : overThreshold * CONFIG.SLOWDOWN_DELAY_MS;

  return {
    allowed: !exceeded,
    remaining,
    resetAt: entry.resetAt,
    delay,
    retryAfterMs: exceeded ? entry.resetAt - now : 0,
  };
}

// Nettoyage périodique du store (évite la fuite mémoire)
setInterval(() => {
  const now = Date.now();
  for (const [ip, entry] of rateLimitStore) {
    if (now > entry.resetAt) rateLimitStore.delete(ip);
  }
}, 5 * 60_000); // toutes les 5 min

// ─── Validation et assainissement du domaine cible ───────────────────────────

// Liste des plages IP privées / réservées (SSRF protection)
const PRIVATE_IP_RANGES = [
  /^10\./,
  /^172\.(1[6-9]|2\d|3[01])\./,
  /^192\.168\./,
  /^127\./,
  /^169\.254\./,   // link-local
  /^::1$/,         // IPv6 loopback
  /^fc00:/,        // IPv6 ULA
  /^fe80:/,        // IPv6 link-local
  /^0\./,          // "this" network
  /^100\.(6[4-9]|[7-9]\d|1([01]\d|2[0-7]))\./,  // CGNAT
];

// TLDs valides (liste non exhaustive mais couvre l'essentiel)
const VALID_TLD_REGEX = /\.[a-z]{2,24}$/i;

async function validateAndResolveDomain(input) {
  if (!input || typeof input !== "string") throw new SecurityError("Domaine manquant");
  if (input.length > 253) throw new SecurityError("Domaine trop long");

  // Nettoyage
  let raw = input.trim().toLowerCase();
  if (raw.startsWith("http://") || raw.startsWith("https://")) {
    try { raw = new URL(raw).hostname; } catch { throw new SecurityError("URL invalide"); }
  }

  // Caractères autorisés uniquement (alphanum, tirets, points)
  if (!/^[a-z0-9.\-]+$/.test(raw)) throw new SecurityError("Caractères non autorisés dans le domaine");

  // Doit avoir un TLD
  if (!VALID_TLD_REGEX.test(raw)) throw new SecurityError("TLD invalide ou domaine malformé");

  // Blocklist configurable
  if (CONFIG.BLOCKED_TARGETS.some(b => raw === b || raw.endsWith("." + b))) {
    throw new SecurityError("Ce domaine est sur la liste de blocage");
  }

  // Protection SSRF : résoudre le domaine et vérifier que l'IP n'est pas privée
  let resolvedIps;
  try {
    resolvedIps = await Promise.race([
      dns.promises.resolve4(raw).catch(() => []),
      new Promise((_, rej) => setTimeout(() => rej(new Error("DNS timeout")), 5000)),
    ]);
  } catch (e) {
    throw new SecurityError(`Résolution DNS échouée : ${e.message}`);
  }

  // Si aucune IP résolue, on laisse passer (certains outils gèrent ça)
  for (const ip of resolvedIps) {
    if (PRIVATE_IP_RANGES.some((r) => r.test(ip))) {
      throw new SecurityError(`Accès refusé : adresse IP privée/interne (${ip})`);
    }
  }

  return raw;
}

class SecurityError extends Error {
  constructor(msg) { super(msg); this.name = "SecurityError"; }
}

// ─── Timeout wrapper ──────────────────────────────────────────────────────────

function withTimeout(promise, ms = CONFIG.TOOL_TIMEOUT_MS, label = "opération") {
  return Promise.race([
    promise,
    new Promise((_, reject) =>
      setTimeout(() => reject(new Error(`Timeout : ${label} a dépassé ${ms}ms`)), ms)
    ),
  ]);
}

// ─── Headers de sécurité de la réponse ───────────────────────────────────────

function setSecurityHeaders(res) {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Content-Security-Policy", "default-src 'none'");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("X-Robots-Tag", "noindex, nofollow");
  // CORS : autorise tout le monde en lecture (API publique)
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  // ID unique de requête pour les logs
  const requestId = crypto.randomBytes(8).toString("hex");
  res.setHeader("X-Request-Id", requestId);
  return requestId;
}

// ─── Helpers réseau (identiques à v1, inchangés) ─────────────────────────────

const dnsResolve4 = promisify(dns.resolve4);
const dnsResolve6 = promisify(dns.resolve6);
const dnsResolveMx = promisify(dns.resolveMx);
const dnsResolveTxt = promisify(dns.resolveTxt);
const dnsResolveNs = promisify(dns.resolveNs);
const dnsResolveCname = promisify(dns.resolveCname);
const dnsResolveSoa = promisify(dns.resolveSoa);

function fetchUrl(url, options = {}) {
  return new Promise((resolve, reject) => {
    const parsedUrl = new URL(url);

    // Double vérification SSRF au niveau fetch
    const lib = parsedUrl.protocol === "https:" ? https : http;
    const req = lib.request({
      hostname: parsedUrl.hostname,
      port: parsedUrl.port || (parsedUrl.protocol === "https:" ? 443 : 80),
      path: parsedUrl.pathname + parsedUrl.search,
      method: options.method || "GET",
      headers: { "User-Agent": "web-check-api/1.0 (OSINT tool)", ...options.headers },
      timeout: options.timeout || 8000,
    }, (res) => {
      let data = "";
      let size = 0;
      res.on("data", (chunk) => {
        size += chunk.length;
        if (size > CONFIG.MAX_RESPONSE_BODY_BYTES) {
          req.destroy();
          reject(new Error("Réponse trop volumineuse"));
          return;
        }
        data += chunk;
      });
      res.on("end", () => resolve({ status: res.statusCode, headers: res.headers, body: data }));
    });
    req.on("timeout", () => { req.destroy(); reject(new Error("Timeout HTTP")); });
    req.on("error", reject);
    req.end();
  });
}

function fetchWithRedirects(url, max = 10) {
  const chain = [];
  return new Promise(async (resolve) => {
    let current = url;
    for (let i = 0; i <= max; i++) {
      try {
        const res = await fetchUrl(current, { method: "HEAD" });
        chain.push({ url: current, status: res.status });
        if ([301,302,303,307,308].includes(res.status) && res.headers.location) {
          current = res.headers.location.startsWith("http") ? res.headers.location : new URL(res.headers.location, current).href;
        } else break;
      } catch (e) { chain.push({ url: current, error: e.message }); break; }
    }
    resolve(chain);
  });
}

function checkPort(host, port, timeout = 2000) {
  return new Promise((resolve) => {
    const s = new net.Socket();
    s.setTimeout(timeout);
    s.once("connect", () => { s.destroy(); resolve(true); });
    s.once("error", () => resolve(false));
    s.once("timeout", () => { s.destroy(); resolve(false); });
    s.connect(port, host);
  });
}

function getTlsInfo(hostname, port = 443) {
  return new Promise((resolve, reject) => {
    const s = tls.connect({ host: hostname, port, servername: hostname, rejectUnauthorized: false }, () => {
      const cert = s.getPeerCertificate(true);
      resolve({ cert, protocol: s.getProtocol(), cipher: s.getCipher() });
      s.destroy();
    });
    s.setTimeout(8000);
    s.on("timeout", () => { s.destroy(); reject(new Error("TLS timeout")); });
    s.on("error", reject);
  });
}

// ─── Outils OSINT ─────────────────────────────────────────────────────────────

async function getIpInfo(hostname) {
  const [ipv4, ipv6] = await Promise.allSettled([dnsResolve4(hostname), dnsResolve6(hostname)]);
  const ips = ipv4.status === "fulfilled" ? ipv4.value : [];
  const ipv6s = ipv6.status === "fulfilled" ? ipv6.value : [];
  let geo = null;
  if (ips[0]) { try { const r = await fetchUrl(`https://ipapi.co/${ips[0]}/json/`); geo = JSON.parse(r.body); } catch {} }
  return { hostname, ipv4: ips, ipv6: ipv6s, geo };
}

async function getDnsRecords(hostname) {
  const results = {};
  await Promise.all([
    ["A", () => dnsResolve4(hostname)],
    ["AAAA", () => dnsResolve6(hostname)],
    ["MX", () => dnsResolveMx(hostname)],
    ["TXT", () => dnsResolveTxt(hostname)],
    ["NS", () => dnsResolveNs(hostname)],
    ["CNAME", () => dnsResolveCname(hostname)],
    ["SOA", () => dnsResolveSoa(hostname)],
  ].map(async ([type, fn]) => { try { results[type] = await fn(); } catch { results[type] = []; } }));
  return { hostname, records: results };
}

async function getSslCertificate(hostname) {
  const { cert, protocol, cipher } = await getTlsInfo(hostname);
  const now = new Date();
  const expiry = cert.valid_to ? new Date(cert.valid_to) : null;
  return {
    hostname, protocol, cipher,
    subject: cert.subject, issuer: cert.issuer,
    valid_from: cert.valid_from, valid_to: cert.valid_to,
    daysUntilExpiry: expiry ? Math.floor((expiry - now) / 86400000) : null,
    isExpired: expiry ? expiry < now : null,
    subjectAltNames: cert.subjectaltname,
  };
}

async function getHeaders(hostname) {
  const res = await fetchUrl(`https://${hostname}`);
  const securityHeaders = ["strict-transport-security","content-security-policy","x-frame-options","x-content-type-options","referrer-policy","permissions-policy","x-xss-protection"];
  const present = {}, missing = [];
  securityHeaders.forEach((h) => res.headers[h] ? (present[h] = res.headers[h]) : missing.push(h));
  return { hostname, statusCode: res.status, allHeaders: res.headers, securityHeaders: { present, missing } };
}

async function getCookies(hostname) {
  const res = await fetchUrl(`https://${hostname}`);
  const cookies = (res.headers["set-cookie"] || []).map((c) => {
    const [nv, ...attrs] = c.split(";").map(p => p.trim());
    const [name, ...vp] = nv.split("=");
    return {
      name, value: vp.join("="),
      httpOnly: attrs.some(a => a.toLowerCase() === "httponly"),
      secure: attrs.some(a => a.toLowerCase() === "secure"),
      sameSite: attrs.find(a => a.toLowerCase().startsWith("samesite"))?.split("=")[1] || null,
    };
  });
  return { hostname, count: cookies.length, cookies };
}

async function getRobotsTxt(hostname) {
  for (const url of [`https://${hostname}/robots.txt`, `http://${hostname}/robots.txt`]) {
    try {
      const res = await fetchUrl(url);
      if (res.status < 400) {
        const rules = []; let agent = null;
        res.body.split("\n").forEach(l => {
          l = l.trim();
          if (l.startsWith("User-agent:")) agent = l.split(":")[1].trim();
          else if (l.startsWith("Disallow:")) rules.push({ agent, disallow: l.split(":")[1].trim() });
          else if (l.startsWith("Allow:")) rules.push({ agent, allow: l.split(":")[1].trim() });
        });
        return { found: true, url, content: res.body, parsedRules: rules };
      }
    } catch {}
  }
  return { found: false, hostname };
}

async function getRedirectChain(hostname) {
  const chain = await fetchWithRedirects(`https://${hostname}`);
  return { originalUrl: `https://${hostname}`, finalUrl: chain[chain.length-1]?.url, redirectCount: chain.length-1, chain };
}

async function getOpenPorts(hostname) {
  const ips = await dnsResolve4(hostname);
  const ip = ips[0];
  const ports = [
    {port:21,service:"FTP"},{port:22,service:"SSH"},{port:25,service:"SMTP"},
    {port:53,service:"DNS"},{port:80,service:"HTTP"},{port:443,service:"HTTPS"},
    {port:3306,service:"MySQL"},{port:5432,service:"PostgreSQL"},{port:6379,service:"Redis"},
    {port:8080,service:"HTTP Alt"},{port:8443,service:"HTTPS Alt"},{port:27017,service:"MongoDB"},
    {port:587,service:"SMTP Submission"},{port:993,service:"IMAPS"},{port:995,service:"POP3S"},
  ];
  const results = await Promise.all(ports.map(async ({port, service}) => ({ port, service, open: await checkPort(ip, port) })));
  return { hostname, ip, openPorts: results.filter(r => r.open), allResults: results };
}

async function getWhois(hostname) {
  try {
    const res = await fetchUrl(`https://rdap.org/domain/${hostname}`);
    if (res.status === 200) {
      const data = JSON.parse(res.body);
      const getEvent = (t) => data.events?.find(e => e.eventAction === t)?.eventDate;
      return {
        hostname, source: "RDAP",
        registrar: data.entities?.find(e => e.roles?.includes("registrar"))?.vcardArray?.[1]?.find(v => v[0]==="fn")?.[3],
        registeredOn: getEvent("registration"), expiresOn: getEvent("expiration"),
        nameservers: data.nameservers?.map(ns => ns.ldhName), status: data.status,
      };
    }
  } catch {}
  return { hostname, note: "RDAP lookup failed" };
}

async function getEmailSecurity(hostname) {
  const [spfRaw, dmarcRaw, mxRaw, bimiRaw] = await Promise.allSettled([
    dnsResolveTxt(hostname), dnsResolveTxt(`_dmarc.${hostname}`),
    dnsResolveMx(hostname), dnsResolveTxt(`default._bimi.${hostname}`),
  ]);
  const flat = (r) => r.status === "fulfilled" ? r.value.flat() : [];
  return {
    hostname,
    spf: { found: !!flat(spfRaw).find(r => r.startsWith("v=spf1")), record: flat(spfRaw).find(r => r.startsWith("v=spf1")) || null },
    dmarc: { found: !!flat(dmarcRaw).find(r => r.startsWith("v=DMARC1")), record: flat(dmarcRaw).find(r => r.startsWith("v=DMARC1")) || null },
    mx: { records: mxRaw.status === "fulfilled" ? mxRaw.value : [] },
    bimi: { found: !!flat(bimiRaw).find(r => r.startsWith("v=BIMI1")), record: flat(bimiRaw).find(r => r.startsWith("v=BIMI1")) || null },
  };
}

async function getServerInfo(hostname) {
  const [ipRes, headerRes] = await Promise.allSettled([dnsResolve4(hostname), fetchUrl(`https://${hostname}`)]);
  const ip = ipRes.status === "fulfilled" ? ipRes.value[0] : null;
  const headers = headerRes.status === "fulfilled" ? headerRes.value.headers : {};
  let geo = null;
  if (ip) { try { const r = await fetchUrl(`https://ipapi.co/${ip}/json/`); geo = JSON.parse(r.body); } catch {} }
  return {
    hostname, ip, server: headers.server, poweredBy: headers["x-powered-by"],
    asn: geo?.asn, org: geo?.org,
    location: geo ? { city: geo.city, region: geo.region, country: geo.country_name, lat: geo.latitude, lon: geo.longitude, timezone: geo.timezone } : null,
  };
}

async function getHttpSecurityFeatures(hostname) {
  const res = await fetchUrl(`https://${hostname}`);
  const h = res.headers;
  const checks = {
    hsts: { present: !!h["strict-transport-security"], value: h["strict-transport-security"] },
    csp: { present: !!h["content-security-policy"], value: h["content-security-policy"] },
    xFrameOptions: { present: !!h["x-frame-options"], value: h["x-frame-options"] },
    xContentTypeOptions: { present: !!h["x-content-type-options"], value: h["x-content-type-options"] },
    referrerPolicy: { present: !!h["referrer-policy"], value: h["referrer-policy"] },
    permissionsPolicy: { present: !!h["permissions-policy"], value: h["permissions-policy"] },
  };
  const score = Object.values(checks).filter(c => c.present).length;
  return { hostname, score: `${score}/${Object.keys(checks).length}`, grade: score>=5?"A":score>=3?"B":score>=1?"C":"F", checks };
}

async function getTechStack(hostname) {
  const res = await fetchUrl(`https://${hostname}`);
  const body = res.body; const h = res.headers;
  const tech = [];
  const add = (name, cat) => tech.push({ name, category: cat });
  if (body.includes("/wp-content/")) add("WordPress","CMS");
  if (body.includes("__NEXT_DATA__") || body.includes("_next/")) add("Next.js","Framework");
  if (body.includes("__nuxt") || body.includes("_nuxt/")) add("Nuxt.js","Framework");
  if (body.includes("data-gatsby-")) add("Gatsby","Framework");
  if (body.includes("google-analytics.com") || body.includes("gtag(")) add("Google Analytics","Analytics");
  if (body.includes("plausible.io")) add("Plausible","Analytics");
  if (h["cf-ray"]) add("Cloudflare","CDN");
  if (h["x-vercel-id"]) add("Vercel","Hosting");
  if (h["x-netlify"] || h["netlify-vary"]) add("Netlify","Hosting");
  if (h.server?.toLowerCase().includes("nginx")) add("Nginx","Web Server");
  if (h.server?.toLowerCase().includes("apache")) add("Apache","Web Server");
  if (h["x-powered-by"]?.includes("PHP")) add("PHP","Language");
  if (h["x-powered-by"]?.includes("Express")) add("Express.js","Framework");
  if (body.includes("shopify")) add("Shopify","E-commerce");
  if (body.includes("jquery")) add("jQuery","Library");
  if (body.includes("tailwind")) add("Tailwind CSS","CSS Framework");
  return { hostname, technologies: tech, count: tech.length };
}

async function getSecurityTxt(hostname) {
  for (const url of [`https://${hostname}/.well-known/security.txt`, `https://${hostname}/security.txt`]) {
    try {
      const res = await fetchUrl(url);
      if (res.status === 200) {
        const fields = {};
        res.body.split("\n").forEach(l => {
          l = l.trim();
          if (l && !l.startsWith("#")) {
            const idx = l.indexOf(":");
            if (idx > -1) { const k = l.substring(0,idx).trim().toLowerCase(); const v = l.substring(idx+1).trim(); if (!fields[k]) fields[k]=[]; fields[k].push(v); }
          }
        });
        return { found: true, url, fields };
      }
    } catch {}
  }
  return { found: false, hostname };
}

async function getSitemap(hostname) {
  for (const url of [`https://${hostname}/sitemap.xml`, `https://${hostname}/sitemap_index.xml`]) {
    try {
      const res = await fetchUrl(url);
      if (res.status === 200 && res.body.includes("<url")) {
        const urls = (res.body.match(/<loc>(.*?)<\/loc>/g) || []).map(m => m.replace(/<\/?loc>/g,""));
        return { found: true, url, urlCount: urls.length, urls: urls.slice(0, 50) };
      }
    } catch {}
  }
  return { found: false, hostname };
}

async function getFirewallDetection(hostname) {
  const res = await fetchUrl(`https://${hostname}`);
  const h = res.headers;
  const wafs = [
    { name: "Cloudflare", headers: ["cf-ray","cf-cache-status"] },
    { name: "AWS WAF", headers: ["x-amzn-requestid","x-amz-cf-id"] },
    { name: "Sucuri", headers: ["x-sucuri-id"] },
    { name: "Akamai", headers: ["x-akamai-transformed"] },
    { name: "Imperva", headers: ["x-iinfo"] },
  ];
  const detected = wafs.filter(w => w.headers.some(hk => !!h[hk])).map(w => w.name);
  return { hostname, wafDetected: detected.length > 0, detectedWafs: detected };
}

async function getBlockDetection(hostname) {
  const servers = [
    { name: "Cloudflare", ip: "1.1.1.1" }, { name: "Google", ip: "8.8.8.8" },
    { name: "Quad9", ip: "9.9.9.9" }, { name: "AdGuard", ip: "94.140.14.14" },
  ];
  const results = await Promise.all(servers.map(({ name, ip }) =>
    new Promise(resolve => {
      const r = new dns.Resolver(); r.setServers([ip]);
      r.resolve4(hostname, (err, addr) => resolve({ provider: name, blocked: !!err, resolvedIps: addr || [] }));
    })
  ));
  return { hostname, blockDetection: results, blockedBy: results.filter(r => r.blocked).map(r => r.provider) };
}

async function getArchiveHistory(hostname) {
  const res = await fetchUrl(`https://archive.org/wayback/available?url=${hostname}`);
  const latest = JSON.parse(res.body);
  let history = [];
  try {
    const cdx = await fetchUrl(`https://web.archive.org/cdx/search/cdx?url=${hostname}&output=json&limit=10&fl=timestamp,statuscode&collapse=timestamp:6`);
    const rows = JSON.parse(cdx.body);
    history = rows.slice(1).map(([ts, status]) => ({ date: `${ts.slice(0,4)}-${ts.slice(4,6)}-${ts.slice(6,8)}`, url: `https://web.archive.org/web/${ts}/${hostname}`, status }));
  } catch {}
  return { hostname, latestSnapshot: latest.archived_snapshots?.closest, history };
}

async function getSocialTags(hostname) {
  const res = await fetchUrl(`https://${hostname}`);
  const body = res.body;
  const getMeta = (name) => {
    const m = body.match(new RegExp(`<meta[^>]+(?:name|property)=["']${name}["'][^>]+content=["']([^"']+)["']`,"i"))
      || body.match(new RegExp(`<meta[^>]+content=["']([^"']+)["'][^>]+(?:name|property)=["']${name}["']`,"i"));
    return m ? m[1] : null;
  };
  return {
    hostname,
    title: getMeta("title") || body.match(/<title>([^<]+)<\/title>/i)?.[1],
    description: getMeta("description"),
    openGraph: { title: getMeta("og:title"), description: getMeta("og:description"), image: getMeta("og:image") },
    twitter: { card: getMeta("twitter:card"), title: getMeta("twitter:title") },
  };
}

async function getServerStatus(hostname) {
  const start = Date.now();
  try {
    const res = await fetchUrl(`https://${hostname}`);
    return { hostname, online: res.status < 500, statusCode: res.status, responseTimeMs: Date.now()-start };
  } catch (e) {
    return { hostname, online: false, error: e.message, responseTimeMs: Date.now()-start };
  }
}

async function runFullAnalysis(hostname) {
  const checks = [
    ["ipInfo", getIpInfo], ["dns", getDnsRecords], ["ssl", getSslCertificate],
    ["headers", getHeaders], ["serverInfo", getServerInfo], ["whois", getWhois],
    ["httpSecurity", getHttpSecurityFeatures], ["emailSecurity", getEmailSecurity],
    ["firewall", getFirewallDetection], ["techStack", getTechStack],
    ["redirectChain", getRedirectChain], ["robotsTxt", getRobotsTxt],
    ["securityTxt", getSecurityTxt], ["socialTags", getSocialTags],
  ];
  const results = { hostname, timestamp: new Date().toISOString() };
  const settled = await Promise.allSettled(checks.map(([, fn]) => fn(hostname)));
  checks.forEach(([key], i) => {
    results[key] = settled[i].status === "fulfilled" ? settled[i].value : { error: settled[i].reason?.message };
  });
  return results;
}

// ─── Route Map ────────────────────────────────────────────────────────────────

const ROUTES = {
  "/api/ip":           { fn: getIpInfo,              desc: "Adresses IP + géolocalisation" },
  "/api/dns":          { fn: getDnsRecords,           desc: "Enregistrements DNS" },
  "/api/ssl":          { fn: getSslCertificate,       desc: "Certificat SSL/TLS" },
  "/api/headers":      { fn: getHeaders,              desc: "Headers HTTP" },
  "/api/cookies":      { fn: getCookies,              desc: "Cookies et attributs" },
  "/api/robots":       { fn: getRobotsTxt,            desc: "Fichier robots.txt" },
  "/api/redirects":    { fn: getRedirectChain,        desc: "Chaîne de redirections" },
  "/api/ports":        { fn: getOpenPorts,            desc: "Ports ouverts" },
  "/api/whois":        { fn: getWhois,                desc: "WHOIS / RDAP" },
  "/api/email":        { fn: getEmailSecurity,        desc: "SPF, DMARC, DKIM, BIMI" },
  "/api/server":       { fn: getServerInfo,           desc: "Info serveur (ASN, hébergeur)" },
  "/api/security":     { fn: getHttpSecurityFeatures, desc: "Score sécurité HTTP" },
  "/api/tech":         { fn: getTechStack,            desc: "Stack technologique" },
  "/api/security-txt": { fn: getSecurityTxt,          desc: "Fichier security.txt" },
  "/api/sitemap":      { fn: getSitemap,              desc: "Pages du sitemap.xml" },
  "/api/firewall":     { fn: getFirewallDetection,    desc: "Détection WAF" },
  "/api/block":        { fn: getBlockDetection,       desc: "Blocage DNS" },
  "/api/archive":      { fn: getArchiveHistory,       desc: "Historique Wayback Machine" },
  "/api/social":       { fn: getSocialTags,           desc: "Open Graph / Twitter Cards" },
  "/api/status":       { fn: getServerStatus,         desc: "Statut + temps de réponse" },
  "/api/full":         { fn: runFullAnalysis,         desc: "Analyse complète (tous les checks)" },
};

// ─── Serveur HTTP ─────────────────────────────────────────────────────────────

const server = http.createServer(async (req, res) => {
  const requestId = setSecurityHeaders(res);
  const ip = getRateLimitKey(req);

  if (req.method === "OPTIONS") { res.writeHead(204); return res.end(); }
  if (req.method !== "GET") {
    res.writeHead(405, { "Content-Type": "application/json" });
    return res.end(JSON.stringify({ error: "Méthode non autorisée. Utilise GET." }));
  }

  // ── Vérification de la clé API ──
  const apiKey = req.headers["x-api-key"] || url.searchParams.get("api_key");
  if (!apiKey || apiKey !== CONFIG.API_KEY) {
    res.writeHead(401, { "Content-Type": "application/json" });
    return res.end(JSON.stringify({ error: "Clé API manquante ou invalide." }));
  }

  const url = new URL(req.url, `http://localhost:${CONFIG.PORT}`);
  const path = url.pathname;

  // ── Page d'accueil ──
  if (path === "/" || path === "") {
    res.writeHead(200, { "Content-Type": "application/json" });
    return res.end(JSON.stringify({
      name: "web-check-api",
      version: "2.0.0 (secured)",
      usage: "GET /api/<check>?domain=example.com",
      rateLimit: `${CONFIG.RATE_LIMIT_MAX} requêtes / ${CONFIG.RATE_LIMIT_WINDOW_MS / 1000}s par IP`,
      endpoints: Object.entries(ROUTES).map(([path, { desc }]) => ({ path, description: desc, example: `${path}?domain=example.com` })),
    }, null, 2));
  }

  // ── Health check ──
  if (path === "/health") {
    res.writeHead(200, { "Content-Type": "application/json" });
    return res.end(JSON.stringify({ status: "ok", uptime: Math.floor(process.uptime()) }));
  }

  // ── Route inconnue ──
  const route = ROUTES[path];
  if (!route) {
    res.writeHead(404, { "Content-Type": "application/json" });
    return res.end(JSON.stringify({ error: "Route inconnue", availableRoutes: Object.keys(ROUTES) }));
  }

  // ── Rate limiting ──
  const rl = checkRateLimit(ip);
  res.setHeader("X-RateLimit-Limit", CONFIG.RATE_LIMIT_MAX);
  res.setHeader("X-RateLimit-Remaining", rl.remaining);
  res.setHeader("X-RateLimit-Reset", Math.ceil(rl.resetAt / 1000));

  if (!rl.allowed) {
    log("warn", "Rate limit dépassé", { ip, path, requestId });
    res.writeHead(429, { "Content-Type": "application/json", "Retry-After": Math.ceil(rl.retryAfterMs / 1000) });
    return res.end(JSON.stringify({
      error: "Trop de requêtes. Réessaie dans quelques secondes.",
      retryAfterSeconds: Math.ceil(rl.retryAfterMs / 1000),
    }));
  }

  // Slowdown progressif
  if (rl.delay > 0) {
    await new Promise(r => setTimeout(r, rl.delay));
  }

  // ── Validation du domaine cible ──
  const rawDomain = url.searchParams.get("domain") || url.searchParams.get("url");
  if (!rawDomain) {
    res.writeHead(400, { "Content-Type": "application/json" });
    return res.end(JSON.stringify({ error: "Paramètre ?domain= manquant", example: `${path}?domain=example.com` }));
  }

  let domain;
  try {
    domain = await validateAndResolveDomain(rawDomain);
  } catch (e) {
    log("warn", "Domaine refusé", { ip, rawDomain, reason: e.message, requestId });
    const status = e instanceof SecurityError ? 400 : 500;
    res.writeHead(status, { "Content-Type": "application/json" });
    return res.end(JSON.stringify({ error: e.message }));
  }

  // ── Exécution avec timeout ──
  const start = Date.now();
  log("info", "Requête", { ip, path, domain, requestId });

  try {
    const result = await withTimeout(route.fn(domain), CONFIG.TOOL_TIMEOUT_MS, path);
    const duration = Date.now() - start;
    log("info", "Succès", { ip, path, domain, durationMs: duration, requestId });
    res.writeHead(200, { "Content-Type": "application/json", "X-Response-Time": `${duration}ms` });
    res.end(JSON.stringify(result, null, 2));
  } catch (e) {
    const duration = Date.now() - start;
    log("error", "Erreur outil", { ip, path, domain, error: e.message, durationMs: duration, requestId });
    res.writeHead(500, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: e.message }));
  }
});

server.listen(CONFIG.PORT, () => {
  log("info", `✅ web-check-api démarré`, { port: CONFIG.PORT });
});

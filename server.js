import http from "http";
import https from "https";
import dns from "dns";
import net from "net";
import tls from "tls";
import { promisify } from "util";
import { URL } from "url";

const dnsResolve4 = promisify(dns.resolve4);
const dnsResolve6 = promisify(dns.resolve6);
const dnsResolveMx = promisify(dns.resolveMx);
const dnsResolveTxt = promisify(dns.resolveTxt);
const dnsResolveNs = promisify(dns.resolveNs);
const dnsResolveCname = promisify(dns.resolveCname);
const dnsResolveSoa = promisify(dns.resolveSoa);

// ─── Helpers ──────────────────────────────────────────────────────────────────

function extractHostname(url) {
  try {
    if (!url.startsWith("http://") && !url.startsWith("https://")) url = "https://" + url;
    return new URL(url).hostname;
  } catch { return url; }
}

function fetchUrl(url, options = {}) {
  return new Promise((resolve, reject) => {
    const parsedUrl = new URL(url);
    const lib = parsedUrl.protocol === "https:" ? https : http;
    const req = lib.request({
      hostname: parsedUrl.hostname,
      port: parsedUrl.port || (parsedUrl.protocol === "https:" ? 443 : 80),
      path: parsedUrl.pathname + parsedUrl.search,
      method: options.method || "GET",
      headers: { "User-Agent": "web-check-mcp/1.0", ...options.headers },
      timeout: options.timeout || 10000,
    }, (res) => {
      let data = "";
      res.on("data", (chunk) => (data += chunk));
      res.on("end", () => resolve({ status: res.statusCode, headers: res.headers, body: data }));
    });
    req.on("timeout", () => { req.destroy(); reject(new Error("Timeout")); });
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
        chain.push({ url: current, status: res.status, headers: res.headers });
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
      const protocol = s.getProtocol();
      const cipher = s.getCipher();
      s.destroy();
      resolve({ cert, protocol, cipher });
    });
    s.setTimeout(8000);
    s.on("timeout", () => { s.destroy(); reject(new Error("TLS timeout")); });
    s.on("error", reject);
  });
}

// ─── Tool Implementations ─────────────────────────────────────────────────────

async function getIpInfo(domain) {
  const hostname = extractHostname(domain);
  const [ipv4, ipv6] = await Promise.allSettled([dnsResolve4(hostname), dnsResolve6(hostname)]);
  const ips = ipv4.status === "fulfilled" ? ipv4.value : [];
  const ipv6s = ipv6.status === "fulfilled" ? ipv6.value : [];
  let geo = null;
  if (ips[0]) { try { const r = await fetchUrl(`https://ipapi.co/${ips[0]}/json/`); geo = JSON.parse(r.body); } catch {} }
  return { hostname, ipv4: ips, ipv6: ipv6s, geo };
}

async function getDnsRecords(domain) {
  const hostname = extractHostname(domain);
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

async function getSslCertificate(domain) {
  const hostname = extractHostname(domain);
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
    fingerprint: cert.fingerprint,
  };
}

async function getHeaders(domain) {
  let url = domain.startsWith("http") ? domain : "https://" + domain;
  const res = await fetchUrl(url);
  const securityHeaders = ["strict-transport-security","content-security-policy","x-frame-options","x-content-type-options","referrer-policy","permissions-policy","x-xss-protection"];
  const present = {}, missing = [];
  securityHeaders.forEach((h) => res.headers[h] ? (present[h] = res.headers[h]) : missing.push(h));
  return { url, statusCode: res.status, allHeaders: res.headers, securityHeaders: { present, missing } };
}

async function getCookies(domain) {
  let url = domain.startsWith("http") ? domain : "https://" + domain;
  const res = await fetchUrl(url);
  const raw = res.headers["set-cookie"] || [];
  const cookies = raw.map((c) => {
    const [nv, ...attrs] = c.split(";").map(p => p.trim());
    const [name, ...vp] = nv.split("=");
    return {
      name, value: vp.join("="),
      httpOnly: attrs.some(a => a.toLowerCase() === "httponly"),
      secure: attrs.some(a => a.toLowerCase() === "secure"),
      sameSite: attrs.find(a => a.toLowerCase().startsWith("samesite"))?.split("=")[1] || null,
    };
  });
  return { url, count: cookies.length, cookies };
}

async function getRobotsTxt(domain) {
  const hostname = extractHostname(domain);
  for (const url of [`https://${hostname}/robots.txt`, `http://${hostname}/robots.txt`]) {
    try {
      const res = await fetchUrl(url);
      if (res.status < 400) {
        const lines = res.body.split("\n");
        const rules = []; let agent = null;
        lines.forEach(l => {
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

async function getRedirectChain(domain) {
  let url = domain.startsWith("http") ? domain : "https://" + domain;
  const chain = await fetchWithRedirects(url);
  return { originalUrl: url, finalUrl: chain[chain.length-1]?.url, redirectCount: chain.length-1, chain };
}

async function getOpenPorts(domain) {
  const hostname = extractHostname(domain);
  const ips = await dnsResolve4(hostname);
  const ip = ips[0];
  const ports = [
    {port:21,service:"FTP"},{port:22,service:"SSH"},{port:23,service:"Telnet"},
    {port:25,service:"SMTP"},{port:53,service:"DNS"},{port:80,service:"HTTP"},
    {port:443,service:"HTTPS"},{port:3306,service:"MySQL"},{port:5432,service:"PostgreSQL"},
    {port:6379,service:"Redis"},{port:8080,service:"HTTP Alt"},{port:8443,service:"HTTPS Alt"},
    {port:27017,service:"MongoDB"},{port:587,service:"SMTP Submission"},{port:993,service:"IMAPS"},
  ];
  const results = await Promise.all(ports.map(async ({port, service}) => ({ port, service, open: await checkPort(ip, port) })));
  return { hostname, ip, openPorts: results.filter(r => r.open), allResults: results };
}

async function getWhois(domain) {
  const hostname = extractHostname(domain);
  try {
    const res = await fetchUrl(`https://rdap.org/domain/${hostname}`);
    if (res.status === 200) {
      const data = JSON.parse(res.body);
      const getEvent = (t) => data.events?.find(e => e.eventAction === t)?.eventDate;
      return {
        hostname, source: "RDAP",
        registrar: data.entities?.find(e => e.roles?.includes("registrar"))?.vcardArray?.[1]?.find(v => v[0]==="fn")?.[3],
        registeredOn: getEvent("registration"), expiresOn: getEvent("expiration"), updatedOn: getEvent("last changed"),
        nameservers: data.nameservers?.map(ns => ns.ldhName), status: data.status,
      };
    }
  } catch {}
  return { hostname, note: "RDAP lookup failed" };
}

async function getEmailSecurity(domain) {
  const hostname = extractHostname(domain);
  const [spfRaw, dmarcRaw, mxRaw, bimiRaw] = await Promise.allSettled([
    dnsResolveTxt(hostname), dnsResolveTxt(`_dmarc.${hostname}`),
    dnsResolveMx(hostname), dnsResolveTxt(`default._bimi.${hostname}`),
  ]);
  const flat = (r) => r.status === "fulfilled" ? r.value.flat() : [];
  return {
    hostname,
    spf: { found: !!flat(spfRaw).find(r => r.startsWith("v=spf1")), record: flat(spfRaw).find(r => r.startsWith("v=spf1")) || null },
    dmarc: { found: !!flat(dmarcRaw).find(r => r.startsWith("v=DMARC1")), record: flat(dmarcRaw).find(r => r.startsWith("v=DMARC1")) || null },
    mx: { records: dmarcRaw.status === "fulfilled" ? (mxRaw.status === "fulfilled" ? mxRaw.value : []) : [] },
    bimi: { found: !!flat(bimiRaw).find(r => r.startsWith("v=BIMI1")), record: flat(bimiRaw).find(r => r.startsWith("v=BIMI1")) || null },
  };
}

async function getServerInfo(domain) {
  const hostname = extractHostname(domain);
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

async function getHttpSecurityFeatures(domain) {
  let url = domain.startsWith("http") ? domain : "https://" + domain;
  const res = await fetchUrl(url);
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
  return { url, score: `${score}/${Object.keys(checks).length}`, grade: score>=5?"A":score>=3?"B":score>=1?"C":"F", checks };
}

async function getTechStack(domain) {
  let url = domain.startsWith("http") ? domain : "https://" + domain;
  const res = await fetchUrl(url);
  const body = res.body; const h = res.headers;
  const tech = [];
  const add = (name, cat, conf) => tech.push({ name, category: cat, confidence: conf });
  if (body.includes("/wp-content/")) add("WordPress","CMS","high");
  if (body.includes("__NEXT_DATA__") || body.includes("_next/")) add("Next.js","Framework","high");
  if (body.includes("__nuxt") || body.includes("_nuxt/")) add("Nuxt.js","Framework","high");
  if (body.includes("data-gatsby-")) add("Gatsby","Framework","high");
  if (body.includes("ng-version=")) add("Angular","Framework","high");
  if (body.includes("google-analytics.com") || body.includes("gtag(")) add("Google Analytics","Analytics","high");
  if (body.includes("plausible.io")) add("Plausible","Analytics","high");
  if (body.includes("hotjar.com")) add("Hotjar","Analytics","high");
  if (h["cf-ray"]) add("Cloudflare","CDN","high");
  if (h["x-vercel-id"]) add("Vercel","Hosting","high");
  if (h["x-netlify"] || h["netlify-vary"]) add("Netlify","Hosting","high");
  if (h.server?.toLowerCase().includes("nginx")) add("Nginx","Web Server","high");
  if (h.server?.toLowerCase().includes("apache")) add("Apache","Web Server","high");
  if (h["x-powered-by"]?.includes("PHP")) add("PHP","Language","high");
  if (h["x-powered-by"]?.includes("Express")) add("Express.js","Framework","high");
  if (body.includes("shopify")) add("Shopify","E-commerce","medium");
  if (body.includes("jquery")) add("jQuery","Library","high");
  if (body.includes("bootstrap")) add("Bootstrap","CSS Framework","medium");
  if (body.includes("tailwind")) add("Tailwind CSS","CSS Framework","medium");
  return { url, technologies: tech, count: tech.length, server: h.server };
}

async function getSecurityTxt(domain) {
  const hostname = extractHostname(domain);
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

async function getSitemap(domain) {
  const hostname = extractHostname(domain);
  for (const url of [`https://${hostname}/sitemap.xml`, `https://${hostname}/sitemap_index.xml`]) {
    try {
      const res = await fetchUrl(url);
      if (res.status === 200 && res.body.includes("<url")) {
        const urls = (res.body.match(/<loc>(.*?)<\/loc>/g) || []).map(m => m.replace(/<\/?loc>/g,""));
        return { found: true, url, urlCount: urls.length, urls: urls.slice(0,50) };
      }
    } catch {}
  }
  return { found: false, hostname };
}

async function getFirewallDetection(domain) {
  const hostname = extractHostname(domain);
  const res = await fetchUrl(`https://${hostname}`);
  const h = res.headers; const body = res.body.toLowerCase();
  const wafs = [
    { name: "Cloudflare", headers: ["cf-ray","cf-cache-status"] },
    { name: "AWS WAF", headers: ["x-amzn-requestid","x-amz-cf-id"] },
    { name: "Sucuri", headers: ["x-sucuri-id"] },
    { name: "Akamai", headers: ["x-akamai-transformed"] },
    { name: "Imperva", headers: ["x-iinfo"] },
  ];
  const detected = wafs.filter(w => w.headers.some(h2 => !!h[h2])).map(w => w.name);
  return { hostname, wafDetected: detected.length > 0, detectedWafs: detected, server: h.server };
}

async function getBlockDetection(domain) {
  const hostname = extractHostname(domain);
  const servers = [
    { name: "Cloudflare", ip: "1.1.1.1" }, { name: "Google", ip: "8.8.8.8" },
    { name: "Quad9", ip: "9.9.9.9" }, { name: "AdGuard", ip: "94.140.14.14" },
  ];
  const results = await Promise.all(servers.map(({ name, ip }) =>
    new Promise(resolve => {
      const r = new dns.Resolver(); r.setServers([ip]);
      r.resolve4(hostname, (err, addr) => resolve({ provider: name, blocked: !!err, resolvedIps: addr || [], error: err?.code }));
    })
  ));
  return { hostname, blockDetection: results, blockedBy: results.filter(r => r.blocked).map(r => r.provider) };
}

async function getArchiveHistory(domain) {
  const hostname = extractHostname(domain);
  const res = await fetchUrl(`https://archive.org/wayback/available?url=${hostname}`);
  const latest = JSON.parse(res.body);
  let history = [];
  try {
    const cdx = await fetchUrl(`https://web.archive.org/cdx/search/cdx?url=${hostname}&output=json&limit=10&fl=timestamp,statuscode&collapse=timestamp:6`);
    const rows = JSON.parse(cdx.body);
    history = rows.slice(1).map(([ts, status]) => ({ date: `${ts.slice(0,4)}-${ts.slice(4,6)}-${ts.slice(6,8)}`, url: `https://web.archive.org/web/${ts}/${hostname}`, status }));
  } catch {}
  return { hostname, latestSnapshot: latest.archived_snapshots?.closest, history, waybackUrl: `https://web.archive.org/web/*/${hostname}` };
}

async function getSocialTags(domain) {
  let url = domain.startsWith("http") ? domain : "https://" + domain;
  const res = await fetchUrl(url);
  const body = res.body;
  const getMeta = (name) => {
    const m = body.match(new RegExp(`<meta[^>]+(?:name|property)=["']${name}["'][^>]+content=["']([^"']+)["']`,"i"))
      || body.match(new RegExp(`<meta[^>]+content=["']([^"']+)["'][^>]+(?:name|property)=["']${name}["']`,"i"));
    return m ? m[1] : null;
  };
  return {
    url,
    title: getMeta("title") || body.match(/<title>([^<]+)<\/title>/i)?.[1],
    description: getMeta("description"),
    openGraph: { title: getMeta("og:title"), description: getMeta("og:description"), image: getMeta("og:image"), type: getMeta("og:type") },
    twitter: { card: getMeta("twitter:card"), title: getMeta("twitter:title"), image: getMeta("twitter:image") },
  };
}

async function getServerStatus(domain) {
  let url = domain.startsWith("http") ? domain : "https://" + domain;
  const start = Date.now();
  try {
    const res = await fetchUrl(url);
    return { url, online: res.status < 500, statusCode: res.status, responseTimeMs: Date.now()-start, server: res.headers.server };
  } catch (e) {
    return { url, online: false, error: e.message, responseTimeMs: Date.now()-start };
  }
}

async function runFullAnalysis(domain) {
  const checks = [
    ["ipInfo", getIpInfo], ["dns", getDnsRecords], ["ssl", getSslCertificate],
    ["headers", getHeaders], ["serverInfo", getServerInfo], ["whois", getWhois],
    ["httpSecurity", getHttpSecurityFeatures], ["emailSecurity", getEmailSecurity],
    ["firewall", getFirewallDetection], ["techStack", getTechStack],
    ["redirectChain", getRedirectChain], ["robotsTxt", getRobotsTxt],
    ["securityTxt", getSecurityTxt], ["socialTags", getSocialTags],
  ];
  const results = { hostname: extractHostname(domain), timestamp: new Date().toISOString() };
  const settled = await Promise.allSettled(checks.map(([, fn]) => fn(domain)));
  checks.forEach(([key], i) => {
    results[key] = settled[i].status === "fulfilled" ? settled[i].value : { error: settled[i].reason?.message };
  });
  return results;
}

// ─── Route Map ────────────────────────────────────────────────────────────────

const ROUTES = {
  "/api/ip": getIpInfo,
  "/api/dns": getDnsRecords,
  "/api/ssl": getSslCertificate,
  "/api/headers": getHeaders,
  "/api/cookies": getCookies,
  "/api/robots": getRobotsTxt,
  "/api/redirects": getRedirectChain,
  "/api/ports": getOpenPorts,
  "/api/whois": getWhois,
  "/api/email": getEmailSecurity,
  "/api/server": getServerInfo,
  "/api/security": getHttpSecurityFeatures,
  "/api/tech": getTechStack,
  "/api/security-txt": getSecurityTxt,
  "/api/sitemap": getSitemap,
  "/api/firewall": getFirewallDetection,
  "/api/block": getBlockDetection,
  "/api/archive": getArchiveHistory,
  "/api/social": getSocialTags,
  "/api/status": getServerStatus,
  "/api/full": runFullAnalysis,
};

// ─── HTTP Server ──────────────────────────────────────────────────────────────

const PORT = process.env.PORT || 3000;

const server = http.createServer(async (req, res) => {
  // CORS
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");

  if (req.method === "OPTIONS") { res.writeHead(204); return res.end(); }

  const url = new URL(req.url, `http://localhost:${PORT}`);
  const path = url.pathname;

  // Homepage
  if (path === "/" || path === "") {
    res.writeHead(200, { "Content-Type": "application/json" });
    return res.end(JSON.stringify({
      name: "web-check-mcp API",
      version: "1.0.0",
      description: "OSINT API for analysing any website",
      usage: "GET /api/<check>?domain=example.com",
      endpoints: Object.keys(ROUTES).map(r => ({
        path: r,
        example: `${r}?domain=example.com`,
      })),
    }, null, 2));
  }

  // Health check
  if (path === "/health") {
    res.writeHead(200, { "Content-Type": "application/json" });
    return res.end(JSON.stringify({ status: "ok", uptime: process.uptime() }));
  }

  const handler = ROUTES[path];
  if (!handler) {
    res.writeHead(404, { "Content-Type": "application/json" });
    return res.end(JSON.stringify({ error: "Route not found", availableRoutes: Object.keys(ROUTES) }));
  }

  const domain = url.searchParams.get("domain") || url.searchParams.get("url");
  if (!domain) {
    res.writeHead(400, { "Content-Type": "application/json" });
    return res.end(JSON.stringify({ error: "Missing ?domain= parameter", example: `${path}?domain=example.com` }));
  }

  try {
    const result = await handler(domain);
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify(result, null, 2));
  } catch (e) {
    res.writeHead(500, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: e.message }));
  }
});

server.listen(PORT, () => {
  console.log(`✅ web-check-mcp API running on port ${PORT}`);
  console.log(`📖 Docs: http://localhost:${PORT}/`);
});

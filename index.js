#!/usr/bin/env node
/**
 * web-check-mcp - MCP Server
 * Equivalent of https://github.com/Lissy93/web-check
 * All-in-one OSINT tool for analysing any website
 */

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import https from "https";
import http from "http";
import dns from "dns";
import net from "net";
import { promisify } from "util";
import { URL } from "url";
import tls from "tls";

const dnsResolve = promisify(dns.resolve);
const dnsResolve4 = promisify(dns.resolve4);
const dnsResolve6 = promisify(dns.resolve6);
const dnsResolveMx = promisify(dns.resolveMx);
const dnsResolveTxt = promisify(dns.resolveTxt);
const dnsResolveNs = promisify(dns.resolveNs);
const dnsResolveCname = promisify(dns.resolveCname);
const dnsResolveSoa = promisify(dns.resolveSoa);
const dnsReverse = promisify(dns.reverse);

// ─── Helpers ──────────────────────────────────────────────────────────────────

function extractHostname(url) {
  try {
    if (!url.startsWith("http://") && !url.startsWith("https://")) {
      url = "https://" + url;
    }
    return new URL(url).hostname;
  } catch {
    return url;
  }
}

function fetchUrl(url, options = {}) {
  return new Promise((resolve, reject) => {
    const parsedUrl = new URL(url);
    const lib = parsedUrl.protocol === "https:" ? https : http;
    const reqOptions = {
      hostname: parsedUrl.hostname,
      port: parsedUrl.port || (parsedUrl.protocol === "https:" ? 443 : 80),
      path: parsedUrl.pathname + parsedUrl.search,
      method: options.method || "GET",
      headers: {
        "User-Agent":
          "Mozilla/5.0 (compatible; web-check-mcp/1.0; +https://github.com/web-check-mcp)",
        ...options.headers,
      },
      timeout: options.timeout || 10000,
    };

    const req = lib.request(reqOptions, (res) => {
      let data = "";
      res.on("data", (chunk) => (data += chunk));
      res.on("end", () =>
        resolve({ status: res.statusCode, headers: res.headers, body: data })
      );
    });

    req.on("timeout", () => {
      req.destroy();
      reject(new Error("Request timed out"));
    });
    req.on("error", reject);
    req.end();
  });
}

function fetchWithRedirects(url, maxRedirects = 10) {
  const chain = [];
  return new Promise(async (resolve, reject) => {
    let current = url;
    for (let i = 0; i <= maxRedirects; i++) {
      try {
        const res = await fetchUrl(current, { method: "HEAD" });
        chain.push({ url: current, status: res.status, headers: res.headers });
        if ([301, 302, 303, 307, 308].includes(res.status) && res.headers.location) {
          const next = res.headers.location.startsWith("http")
            ? res.headers.location
            : new URL(res.headers.location, current).href;
          current = next;
        } else {
          break;
        }
      } catch (e) {
        chain.push({ url: current, error: e.message });
        break;
      }
    }
    resolve(chain);
  });
}

function checkPort(host, port, timeout = 3000) {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    socket.setTimeout(timeout);
    socket.once("connect", () => {
      socket.destroy();
      resolve(true);
    });
    socket.once("error", () => resolve(false));
    socket.once("timeout", () => {
      socket.destroy();
      resolve(false);
    });
    socket.connect(port, host);
  });
}

function getTlsInfo(hostname, port = 443) {
  return new Promise((resolve, reject) => {
    const socket = tls.connect(
      { host: hostname, port, servername: hostname, rejectUnauthorized: false },
      () => {
        const cert = socket.getPeerCertificate(true);
        const protocol = socket.getProtocol();
        const cipher = socket.getCipher();
        socket.destroy();
        resolve({ cert, protocol, cipher });
      }
    );
    socket.setTimeout(8000);
    socket.on("timeout", () => {
      socket.destroy();
      reject(new Error("TLS connection timed out"));
    });
    socket.on("error", reject);
  });
}

// ─── Tool Implementations ─────────────────────────────────────────────────────

async function getIpInfo(domain) {
  const hostname = extractHostname(domain);
  try {
    const [ipv4, ipv6] = await Promise.allSettled([
      dnsResolve4(hostname),
      dnsResolve6(hostname),
    ]);
    const ips = [
      ...(ipv4.status === "fulfilled" ? ipv4.value : []),
    ];
    const ipv6s = ipv6.status === "fulfilled" ? ipv6.value : [];

    let geoInfo = null;
    if (ips.length > 0) {
      try {
        const res = await fetchUrl(`https://ipapi.co/${ips[0]}/json/`);
        geoInfo = JSON.parse(res.body);
      } catch {}
    }

    return {
      hostname,
      ipv4: ips,
      ipv6: ipv6s,
      geo: geoInfo,
    };
  } catch (e) {
    return { error: e.message, hostname };
  }
}

async function getDnsRecords(domain) {
  const hostname = extractHostname(domain);
  const results = {};
  const types = [
    ["A", () => dnsResolve4(hostname)],
    ["AAAA", () => dnsResolve6(hostname)],
    ["MX", () => dnsResolveMx(hostname)],
    ["TXT", () => dnsResolveTxt(hostname)],
    ["NS", () => dnsResolveNs(hostname)],
    ["CNAME", () => dnsResolveCname(hostname)],
    ["SOA", () => dnsResolveSoa(hostname)],
  ];

  await Promise.all(
    types.map(async ([type, fn]) => {
      try {
        results[type] = await fn();
      } catch {
        results[type] = [];
      }
    })
  );
  return { hostname, records: results };
}

async function getSslCertificate(domain) {
  const hostname = extractHostname(domain);
  try {
    const { cert, protocol, cipher } = await getTlsInfo(hostname);
    const formatDate = (d) => (d ? new Date(d).toISOString() : null);
    const buildChain = (c, depth = 0) => {
      if (!c || depth > 5) return null;
      const issuer = c.issuerCertificate;
      return {
        subject: c.subject,
        issuer: c.issuer,
        valid_from: formatDate(c.valid_from),
        valid_to: formatDate(c.valid_to),
        serialNumber: c.serialNumber,
        fingerprint: c.fingerprint,
        isCA: c.isCA,
        issuerCert:
          issuer && issuer.fingerprint !== c.fingerprint
            ? buildChain(issuer, depth + 1)
            : null,
      };
    };

    const now = new Date();
    const expiry = cert.valid_to ? new Date(cert.valid_to) : null;
    const daysUntilExpiry = expiry
      ? Math.floor((expiry - now) / (1000 * 60 * 60 * 24))
      : null;

    return {
      hostname,
      protocol,
      cipher,
      certificate: buildChain(cert),
      daysUntilExpiry,
      isExpired: expiry ? expiry < now : null,
      subjectAltNames: cert.subjectaltname,
    };
  } catch (e) {
    return { error: e.message, hostname };
  }
}

async function getHeaders(domain) {
  let url = domain;
  if (!url.startsWith("http://") && !url.startsWith("https://")) {
    url = "https://" + url;
  }
  try {
    const res = await fetchUrl(url);
    const securityHeaders = [
      "strict-transport-security",
      "content-security-policy",
      "x-frame-options",
      "x-content-type-options",
      "referrer-policy",
      "permissions-policy",
      "x-xss-protection",
      "cross-origin-embedder-policy",
      "cross-origin-opener-policy",
    ];

    const present = {};
    const missing = [];
    securityHeaders.forEach((h) => {
      if (res.headers[h]) {
        present[h] = res.headers[h];
      } else {
        missing.push(h);
      }
    });

    return {
      url,
      statusCode: res.status,
      allHeaders: res.headers,
      securityHeaders: { present, missing },
    };
  } catch (e) {
    return { error: e.message, url };
  }
}

async function getCookies(domain) {
  let url = domain;
  if (!url.startsWith("http://") && !url.startsWith("https://")) {
    url = "https://" + url;
  }
  try {
    const res = await fetchUrl(url);
    const rawCookies = res.headers["set-cookie"] || [];
    const parsed = rawCookies.map((cookie) => {
      const parts = cookie.split(";").map((p) => p.trim());
      const [nameValue, ...attrs] = parts;
      const [name, ...valueParts] = nameValue.split("=");
      const flags = {
        httpOnly: attrs.some((a) => a.toLowerCase() === "httponly"),
        secure: attrs.some((a) => a.toLowerCase() === "secure"),
        sameSite:
          attrs.find((a) => a.toLowerCase().startsWith("samesite"))?.split("=")[1] || null,
        path:
          attrs.find((a) => a.toLowerCase().startsWith("path"))?.split("=")[1] || null,
        domain:
          attrs.find((a) => a.toLowerCase().startsWith("domain"))?.split("=")[1] || null,
        expires:
          attrs.find((a) => a.toLowerCase().startsWith("expires"))?.split("=")[1] || null,
      };
      return { name, value: valueParts.join("="), ...flags };
    });

    return { url, count: parsed.length, cookies: parsed };
  } catch (e) {
    return { error: e.message, url };
  }
}

async function getRobotsTxt(domain) {
  const hostname = extractHostname(domain);
  let url = `https://${hostname}/robots.txt`;
  try {
    const res = await fetchUrl(url);
    if (res.status >= 400) {
      url = `http://${hostname}/robots.txt`;
      const res2 = await fetchUrl(url);
      if (res2.status >= 400) return { found: false, hostname };

      return { found: true, url, status: res2.status, content: res2.body };
    }
    const lines = res.body.split("\n");
    const rules = [];
    let currentAgent = null;
    lines.forEach((line) => {
      const l = line.trim();
      if (l.startsWith("User-agent:")) currentAgent = l.split(":")[1].trim();
      else if (l.startsWith("Disallow:"))
        rules.push({
          agent: currentAgent,
          disallow: l.split(":")[1].trim(),
        });
      else if (l.startsWith("Allow:"))
        rules.push({ agent: currentAgent, allow: l.split(":")[1].trim() });
    });

    return { found: true, url, status: res.status, content: res.body, parsedRules: rules };
  } catch (e) {
    return { error: e.message, hostname };
  }
}

async function getRedirectChain(domain) {
  let url = domain;
  if (!url.startsWith("http://") && !url.startsWith("https://")) {
    url = "https://" + url;
  }
  try {
    const chain = await fetchWithRedirects(url);
    return {
      originalUrl: url,
      finalUrl: chain[chain.length - 1]?.url,
      redirectCount: chain.length - 1,
      chain,
    };
  } catch (e) {
    return { error: e.message, url };
  }
}

async function getOpenPorts(domain) {
  const hostname = extractHostname(domain);
  const commonPorts = [
    { port: 21, service: "FTP" },
    { port: 22, service: "SSH" },
    { port: 23, service: "Telnet" },
    { port: 25, service: "SMTP" },
    { port: 53, service: "DNS" },
    { port: 80, service: "HTTP" },
    { port: 110, service: "POP3" },
    { port: 143, service: "IMAP" },
    { port: 443, service: "HTTPS" },
    { port: 465, service: "SMTPS" },
    { port: 587, service: "SMTP Submission" },
    { port: 993, service: "IMAPS" },
    { port: 995, service: "POP3S" },
    { port: 3306, service: "MySQL" },
    { port: 5432, service: "PostgreSQL" },
    { port: 6379, service: "Redis" },
    { port: 8080, service: "HTTP Alt" },
    { port: 8443, service: "HTTPS Alt" },
    { port: 27017, service: "MongoDB" },
  ];

  let ip;
  try {
    const ips = await dnsResolve4(hostname);
    ip = ips[0];
  } catch {
    return { error: "Could not resolve hostname", hostname };
  }

  const results = await Promise.all(
    commonPorts.map(async ({ port, service }) => {
      const open = await checkPort(ip, port, 2000);
      return { port, service, open };
    })
  );

  return {
    hostname,
    ip,
    scannedPorts: commonPorts.length,
    openPorts: results.filter((r) => r.open),
    allResults: results,
  };
}

async function getDnssec(domain) {
  const hostname = extractHostname(domain);
  try {
    const txtRecords = await dnsResolveTxt(hostname).catch(() => []);
    const nsRecords = await dnsResolveNs(hostname).catch(() => []);

    let dnsoverHttps = false;
    let dnsoverTls = false;
    try {
      const res = await fetchUrl(`https://dns.google/resolve?name=${hostname}&type=DNSKEY`);
      const data = JSON.parse(res.body);
      dnsoverHttps = true;
      const hasDnskey = data.Answer?.some((r) => r.type === 48);
      return {
        hostname,
        dnssecEnabled: hasDnskey || false,
        dnsKeyRecords: data.Answer?.filter((r) => r.type === 48) || [],
        dohSupported: dnsoverHttps,
        dotSupported: dnsoverTls,
        nsRecords,
      };
    } catch {}

    return {
      hostname,
      dnssecEnabled: false,
      dohSupported: false,
      dotSupported: false,
      nsRecords,
      note: "Could not verify DNSSEC via DoH",
    };
  } catch (e) {
    return { error: e.message, hostname };
  }
}

async function getWhois(domain) {
  const hostname = extractHostname(domain);
  try {
    const res = await fetchUrl(
      `https://rdap.org/domain/${hostname}`
    );
    if (res.status === 200) {
      const data = JSON.parse(res.body);
      const getEvent = (type) =>
        data.events?.find((e) => e.eventAction === type)?.eventDate;

      return {
        hostname,
        source: "RDAP",
        registrar: data.entities?.find((e) => e.roles?.includes("registrar"))
          ?.vcardArray?.[1]?.find((v) => v[0] === "fn")?.[3],
        registeredOn: getEvent("registration"),
        expiresOn: getEvent("expiration"),
        updatedOn: getEvent("last changed"),
        nameservers: data.nameservers?.map((ns) => ns.ldhName),
        status: data.status,
        rawRdap: data,
      };
    }
  } catch {}

  return { hostname, note: "RDAP lookup failed. Try https://who.is/whois/" + hostname };
}

async function getSitemap(domain) {
  const hostname = extractHostname(domain);
  const candidates = [
    `https://${hostname}/sitemap.xml`,
    `https://${hostname}/sitemap_index.xml`,
    `https://${hostname}/sitemap/sitemap.xml`,
    `http://${hostname}/sitemap.xml`,
  ];

  for (const url of candidates) {
    try {
      const res = await fetchUrl(url);
      if (res.status === 200 && res.body.includes("<url")) {
        const urlMatches = res.body.match(/<loc>(.*?)<\/loc>/g) || [];
        const urls = urlMatches.map((m) => m.replace(/<\/?loc>/g, ""));
        return {
          found: true,
          url,
          urlCount: urls.length,
          urls: urls.slice(0, 100),
          hasMore: urls.length > 100,
        };
      }
    } catch {}
  }
  return { found: false, hostname, checked: candidates };
}

async function getSecurityTxt(domain) {
  const hostname = extractHostname(domain);
  const candidates = [
    `https://${hostname}/.well-known/security.txt`,
    `https://${hostname}/security.txt`,
    `http://${hostname}/.well-known/security.txt`,
  ];

  for (const url of candidates) {
    try {
      const res = await fetchUrl(url);
      if (res.status === 200) {
        const fields = {};
        const lines = res.body.split("\n");
        lines.forEach((line) => {
          const l = line.trim();
          if (l && !l.startsWith("#")) {
            const idx = l.indexOf(":");
            if (idx > -1) {
              const key = l.substring(0, idx).trim().toLowerCase();
              const val = l.substring(idx + 1).trim();
              if (!fields[key]) fields[key] = [];
              fields[key].push(val);
            }
          }
        });
        return { found: true, url, fields, rawContent: res.body };
      }
    } catch {}
  }
  return { found: false, hostname, checked: candidates };
}

async function getEmailSecurity(domain) {
  const hostname = extractHostname(domain);
  const results = { hostname };

  try {
    const spfRecords = await dnsResolveTxt(hostname).catch(() => []);
    const spf = spfRecords.flat().find((r) => r.startsWith("v=spf1"));
    results.spf = spf
      ? { found: true, record: spf }
      : { found: false };
  } catch {
    results.spf = { found: false };
  }

  try {
    const dmarcRecords = await dnsResolveTxt(`_dmarc.${hostname}`).catch(() => []);
    const dmarc = dmarcRecords.flat().find((r) => r.startsWith("v=DMARC1"));
    results.dmarc = dmarc
      ? { found: true, record: dmarc }
      : { found: false };
  } catch {
    results.dmarc = { found: false };
  }

  try {
    const mxRecords = await dnsResolveMx(hostname).catch(() => []);
    results.mx = { records: mxRecords };
  } catch {
    results.mx = { records: [] };
  }

  try {
    const bimiRecords = await dnsResolveTxt(`default._bimi.${hostname}`).catch(() => []);
    const bimi = bimiRecords.flat().find((r) => r.startsWith("v=BIMI1"));
    results.bimi = bimi
      ? { found: true, record: bimi }
      : { found: false };
  } catch {
    results.bimi = { found: false };
  }

  return results;
}

async function getServerInfo(domain) {
  const hostname = extractHostname(domain);
  let url = `https://${hostname}`;
  try {
    const [ipResult, headerResult] = await Promise.allSettled([
      dnsResolve4(hostname),
      fetchUrl(url),
    ]);

    const ip = ipResult.status === "fulfilled" ? ipResult.value[0] : null;
    const headers =
      headerResult.status === "fulfilled" ? headerResult.value.headers : {};

    let asnInfo = null;
    if (ip) {
      try {
        const res = await fetchUrl(`https://ipapi.co/${ip}/json/`);
        asnInfo = JSON.parse(res.body);
      } catch {}
    }

    return {
      hostname,
      ip,
      server: headers.server,
      poweredBy: headers["x-powered-by"],
      via: headers.via,
      asn: asnInfo?.asn,
      org: asnInfo?.org,
      isp: asnInfo?.isp,
      location: asnInfo
        ? {
            city: asnInfo.city,
            region: asnInfo.region,
            country: asnInfo.country_name,
            countryCode: asnInfo.country_code,
            lat: asnInfo.latitude,
            lon: asnInfo.longitude,
            timezone: asnInfo.timezone,
          }
        : null,
      hosting: asnInfo?.org,
      responseHeaders: headers,
    };
  } catch (e) {
    return { error: e.message, hostname };
  }
}

async function getLinkedPages(domain) {
  let url = domain;
  if (!url.startsWith("http://") && !url.startsWith("https://")) {
    url = "https://" + url;
  }
  const hostname = new URL(url).hostname;

  try {
    const res = await fetchUrl(url);
    const hrefMatches = res.body.match(/href=["']([^"']+)["']/g) || [];
    const links = hrefMatches.map((m) => m.match(/href=["']([^"']+)["']/)[1]);

    const internal = [];
    const external = [];
    links.forEach((link) => {
      if (link.startsWith("http://") || link.startsWith("https://")) {
        try {
          const linkHost = new URL(link).hostname;
          if (linkHost === hostname) internal.push(link);
          else external.push(link);
        } catch {}
      } else if (link.startsWith("/") || link.startsWith("#") || !link.includes(":")) {
        internal.push(link);
      }
    });

    const uniqueInternal = [...new Set(internal)];
    const uniqueExternal = [...new Set(external)];

    return {
      url,
      total: links.length,
      internal: { count: uniqueInternal.length, links: uniqueInternal.slice(0, 50) },
      external: { count: uniqueExternal.length, links: uniqueExternal.slice(0, 50) },
    };
  } catch (e) {
    return { error: e.message, url };
  }
}

async function getSocialTags(domain) {
  let url = domain;
  if (!url.startsWith("http://") && !url.startsWith("https://")) {
    url = "https://" + url;
  }
  try {
    const res = await fetchUrl(url);
    const body = res.body;

    const getMeta = (name) => {
      const match = body.match(
        new RegExp(`<meta[^>]+(?:name|property)=["']${name}["'][^>]+content=["']([^"']+)["']`, "i")
      ) ||
        body.match(
          new RegExp(`<meta[^>]+content=["']([^"']+)["'][^>]+(?:name|property)=["']${name}["']`, "i")
        );
      return match ? match[1] : null;
    };

    return {
      url,
      title: getMeta("title") || body.match(/<title>([^<]+)<\/title>/i)?.[1],
      description: getMeta("description"),
      keywords: getMeta("keywords"),
      author: getMeta("author"),
      openGraph: {
        title: getMeta("og:title"),
        description: getMeta("og:description"),
        image: getMeta("og:image"),
        url: getMeta("og:url"),
        type: getMeta("og:type"),
        siteName: getMeta("og:site_name"),
      },
      twitter: {
        card: getMeta("twitter:card"),
        title: getMeta("twitter:title"),
        description: getMeta("twitter:description"),
        image: getMeta("twitter:image"),
        site: getMeta("twitter:site"),
      },
    };
  } catch (e) {
    return { error: e.message, url };
  }
}

async function getHttpSecurityFeatures(domain) {
  let url = domain;
  if (!url.startsWith("http://") && !url.startsWith("https://")) {
    url = "https://" + url;
  }
  try {
    const res = await fetchUrl(url);
    const h = res.headers;

    const checks = {
      hsts: {
        present: !!h["strict-transport-security"],
        value: h["strict-transport-security"],
        recommendation: "max-age=31536000; includeSubDomains; preload",
      },
      csp: {
        present: !!h["content-security-policy"],
        value: h["content-security-policy"],
      },
      xFrameOptions: {
        present: !!h["x-frame-options"],
        value: h["x-frame-options"],
        recommendation: "DENY or SAMEORIGIN",
      },
      xContentTypeOptions: {
        present: !!h["x-content-type-options"],
        value: h["x-content-type-options"],
        recommendation: "nosniff",
      },
      referrerPolicy: {
        present: !!h["referrer-policy"],
        value: h["referrer-policy"],
      },
      permissionsPolicy: {
        present: !!h["permissions-policy"],
        value: h["permissions-policy"],
      },
      xssProtection: {
        present: !!h["x-xss-protection"],
        value: h["x-xss-protection"],
        note: "Deprecated in modern browsers, CSP preferred",
      },
    };

    const score = Object.values(checks).filter((c) => c.present).length;
    const total = Object.keys(checks).length;

    return {
      url,
      score: `${score}/${total}`,
      securityGrade:
        score >= 6 ? "A" : score >= 4 ? "B" : score >= 2 ? "C" : "F",
      checks,
    };
  } catch (e) {
    return { error: e.message, url };
  }
}

async function getArchiveHistory(domain) {
  const hostname = extractHostname(domain);
  try {
    const res = await fetchUrl(
      `https://archive.org/wayback/available?url=${hostname}`
    );
    const latest = JSON.parse(res.body);

    const cdxUrl = `https://web.archive.org/cdx/search/cdx?url=${hostname}&output=json&limit=20&fl=timestamp,statuscode&collapse=timestamp:6`;
    let history = [];
    try {
      const cdxRes = await fetchUrl(cdxUrl);
      const rows = JSON.parse(cdxRes.body);
      history = rows.slice(1).map(([timestamp, status]) => ({
        timestamp,
        date: `${timestamp.slice(0, 4)}-${timestamp.slice(4, 6)}-${timestamp.slice(6, 8)}`,
        url: `https://web.archive.org/web/${timestamp}/${hostname}`,
        status,
      }));
    } catch {}

    return {
      hostname,
      latestSnapshot: latest.archived_snapshots?.closest,
      history,
      waybackUrl: `https://web.archive.org/web/*/${hostname}`,
    };
  } catch (e) {
    return { error: e.message, hostname };
  }
}

async function getTlsCipherSuites(domain) {
  const hostname = extractHostname(domain);
  try {
    const { cert, protocol, cipher } = await getTlsInfo(hostname);
    return {
      hostname,
      protocol,
      cipher,
      certDetails: {
        subject: cert.subject,
        issuer: cert.issuer,
        valid_from: cert.valid_from,
        valid_to: cert.valid_to,
      },
    };
  } catch (e) {
    return { error: e.message, hostname };
  }
}

async function getBlockDetection(domain) {
  const hostname = extractHostname(domain);
  const dnsServers = [
    { name: "Cloudflare", ip: "1.1.1.1" },
    { name: "Google", ip: "8.8.8.8" },
    { name: "OpenDNS", ip: "208.67.222.222" },
    { name: "Quad9 (malware blocking)", ip: "9.9.9.9" },
    { name: "CleanBrowsing (adult filter)", ip: "185.228.168.168" },
    { name: "AdGuard DNS", ip: "94.140.14.14" },
  ];

  const results = await Promise.all(
    dnsServers.map(async ({ name, ip }) => {
      return new Promise((resolve) => {
        const resolver = new dns.Resolver();
        resolver.setServers([ip]);
        resolver.resolve4(hostname, (err, addresses) => {
          resolve({
            provider: name,
            ip,
            blocked: !!err,
            resolvedIps: addresses || [],
            error: err?.code,
          });
        });
      });
    })
  );

  return {
    hostname,
    blockDetection: results,
    blockedBy: results.filter((r) => r.blocked).map((r) => r.provider),
  };
}

async function getServerStatus(domain) {
  let url = domain;
  if (!url.startsWith("http://") && !url.startsWith("https://")) {
    url = "https://" + url;
  }
  const start = Date.now();
  try {
    const res = await fetchUrl(url);
    const responseTime = Date.now() - start;
    return {
      url,
      online: res.status < 500,
      statusCode: res.status,
      responseTimeMs: responseTime,
      server: res.headers.server,
    };
  } catch (e) {
    return {
      url,
      online: false,
      error: e.message,
      responseTimeMs: Date.now() - start,
    };
  }
}

async function getFirewallDetection(domain) {
  const hostname = extractHostname(domain);
  let url = `https://${hostname}`;
  try {
    const res = await fetchUrl(url);
    const headers = res.headers;
    const body = res.body.toLowerCase();

    const wafSignatures = [
      { name: "Cloudflare", headers: ["cf-ray", "cf-cache-status"], body: ["cloudflare"] },
      { name: "AWS WAF", headers: ["x-amzn-requestid", "x-amz-cf-id"], body: [] },
      { name: "Akamai", headers: ["x-akamai-transformed", "akamai-origin-hop"], body: [] },
      { name: "Sucuri", headers: ["x-sucuri-id", "x-sucuri-cache"], body: ["sucuri"] },
      { name: "Incapsula", headers: ["x-iinfo", "x-cdn"], body: ["incapsula"] },
      { name: "Imperva", headers: ["x-iinfo"], body: ["imperva"] },
      { name: "F5 BIG-IP", headers: ["x-cnection", "x-wa-info"], body: [] },
      { name: "ModSecurity", headers: [], body: ["mod_security", "modsecurity"] },
    ];

    const detected = [];
    for (const waf of wafSignatures) {
      const headerMatch = waf.headers.some((h) => !!headers[h]);
      const bodyMatch = waf.body.some((b) => body.includes(b));
      if (headerMatch || bodyMatch) {
        detected.push({ name: waf.name, confidence: headerMatch ? "high" : "medium" });
      }
    }

    return {
      hostname,
      wafDetected: detected.length > 0,
      detectedWafs: detected,
      relevantHeaders: {
        server: headers.server,
        via: headers.via,
        "x-powered-by": headers["x-powered-by"],
        "cf-ray": headers["cf-ray"],
        "x-sucuri-id": headers["x-sucuri-id"],
      },
    };
  } catch (e) {
    return { error: e.message, hostname };
  }
}

async function getTechStack(domain) {
  let url = domain;
  if (!url.startsWith("http://") && !url.startsWith("https://")) {
    url = "https://" + url;
  }
  try {
    const res = await fetchUrl(url);
    const body = res.body;
    const headers = res.headers;

    const technologies = [];

    // CMS detection
    if (body.includes("/wp-content/") || body.includes("wp-json")) technologies.push({ name: "WordPress", category: "CMS", confidence: "high" });
    if (body.includes("Drupal.settings") || headers["x-generator"]?.includes("Drupal")) technologies.push({ name: "Drupal", category: "CMS", confidence: "high" });
    if (body.includes("Joomla") || body.includes("/components/com_")) technologies.push({ name: "Joomla", category: "CMS", confidence: "high" });

    // JS Frameworks
    if (body.includes("React") || body.includes("__NEXT_DATA__") || body.includes("_next/")) technologies.push({ name: "Next.js / React", category: "JavaScript Framework", confidence: "high" });
    if (body.includes("__nuxt") || body.includes("_nuxt/")) technologies.push({ name: "Nuxt.js / Vue", category: "JavaScript Framework", confidence: "high" });
    if (body.includes("ng-version") || body.includes("angular")) technologies.push({ name: "Angular", category: "JavaScript Framework", confidence: "medium" });
    if (body.includes("data-gatsby-")) technologies.push({ name: "Gatsby", category: "JavaScript Framework", confidence: "high" });
    if (body.includes("__SVELTE") || body.includes("svelte")) technologies.push({ name: "Svelte", category: "JavaScript Framework", confidence: "medium" });

    // Analytics
    if (body.includes("google-analytics.com") || body.includes("gtag(")) technologies.push({ name: "Google Analytics", category: "Analytics", confidence: "high" });
    if (body.includes("segment.com") || body.includes("analytics.js")) technologies.push({ name: "Segment", category: "Analytics", confidence: "high" });
    if (body.includes("plausible.io")) technologies.push({ name: "Plausible", category: "Analytics", confidence: "high" });
    if (body.includes("hotjar.com")) technologies.push({ name: "Hotjar", category: "Analytics", confidence: "high" });

    // CDN/Hosting
    if (headers["cf-ray"]) technologies.push({ name: "Cloudflare", category: "CDN/Security", confidence: "high" });
    if (headers["x-vercel-id"] || headers["x-vercel-cache"]) technologies.push({ name: "Vercel", category: "Hosting", confidence: "high" });
    if (headers["x-amz-cf-id"] || headers["x-amzn-requestid"]) technologies.push({ name: "AWS", category: "Hosting/CDN", confidence: "high" });
    if (headers["x-netlify"] || headers["netlify-vary"]) technologies.push({ name: "Netlify", category: "Hosting", confidence: "high" });

    // Server-side
    if (headers.server?.toLowerCase().includes("nginx")) technologies.push({ name: "Nginx", category: "Web Server", confidence: "high" });
    if (headers.server?.toLowerCase().includes("apache")) technologies.push({ name: "Apache", category: "Web Server", confidence: "high" });
    if (headers["x-powered-by"]?.includes("PHP")) technologies.push({ name: "PHP", category: "Programming Language", confidence: "high" });
    if (headers["x-powered-by"]?.includes("ASP.NET")) technologies.push({ name: "ASP.NET", category: "Framework", confidence: "high" });
    if (headers["x-powered-by"]?.includes("Express")) technologies.push({ name: "Express.js", category: "Framework", confidence: "high" });

    // Other
    if (body.includes("shopify")) technologies.push({ name: "Shopify", category: "E-commerce", confidence: "medium" });
    if (body.includes("woocommerce")) technologies.push({ name: "WooCommerce", category: "E-commerce", confidence: "high" });
    if (body.includes("bootstrap")) technologies.push({ name: "Bootstrap", category: "CSS Framework", confidence: "medium" });
    if (body.includes("tailwind")) technologies.push({ name: "Tailwind CSS", category: "CSS Framework", confidence: "medium" });
    if (body.includes("jquery")) technologies.push({ name: "jQuery", category: "JavaScript Library", confidence: "high" });

    return {
      url,
      detectedTechnologies: technologies,
      count: technologies.length,
      categories: [...new Set(technologies.map((t) => t.category))],
      server: headers.server,
      poweredBy: headers["x-powered-by"],
    };
  } catch (e) {
    return { error: e.message, url };
  }
}

async function getGlobalRanking(domain) {
  const hostname = extractHostname(domain);
  try {
    // Try Tranco list via their API
    const res = await fetchUrl(`https://tranco-list.eu/api/ranks/domain/${hostname}`);
    if (res.status === 200) {
      const data = JSON.parse(res.body);
      return {
        hostname,
        source: "Tranco",
        ranks: data.ranks || [],
        latestRank: data.ranks?.[0]?.rank || null,
      };
    }
  } catch {}
  return {
    hostname,
    note: "Ranking data unavailable. Check https://tranco-list.eu/query for rankings.",
  };
}

async function runFullAnalysis(domain) {
  const hostname = extractHostname(domain);
  const results = { hostname, timestamp: new Date().toISOString() };

  const checks = [
    ["ipInfo", () => getIpInfo(domain)],
    ["dns", () => getDnsRecords(domain)],
    ["ssl", () => getSslCertificate(domain)],
    ["headers", () => getHeaders(domain)],
    ["serverInfo", () => getServerInfo(domain)],
    ["whois", () => getWhois(domain)],
    ["httpSecurity", () => getHttpSecurityFeatures(domain)],
    ["emailSecurity", () => getEmailSecurity(domain)],
    ["firewall", () => getFirewallDetection(domain)],
    ["techStack", () => getTechStack(domain)],
    ["redirectChain", () => getRedirectChain(domain)],
    ["robotsTxt", () => getRobotsTxt(domain)],
    ["securityTxt", () => getSecurityTxt(domain)],
    ["socialTags", () => getSocialTags(domain)],
  ];

  const settled = await Promise.allSettled(checks.map(([, fn]) => fn()));
  checks.forEach(([key], i) => {
    results[key] =
      settled[i].status === "fulfilled"
        ? settled[i].value
        : { error: settled[i].reason?.message };
  });

  return results;
}

// ─── MCP Server ───────────────────────────────────────────────────────────────

const server = new Server(
  { name: "web-check-mcp", version: "1.0.0" },
  { capabilities: { tools: {} } }
);

const TOOLS = [
  {
    name: "ip_info",
    description: "Get IP address information for a domain, including IPv4/IPv6 addresses and geolocation data",
    inputSchema: {
      type: "object",
      properties: { domain: { type: "string", description: "Domain name or URL to analyse" } },
      required: ["domain"],
    },
  },
  {
    name: "dns_records",
    description: "Retrieve all DNS records for a domain (A, AAAA, MX, TXT, NS, CNAME, SOA)",
    inputSchema: {
      type: "object",
      properties: { domain: { type: "string", description: "Domain name or URL" } },
      required: ["domain"],
    },
  },
  {
    name: "ssl_certificate",
    description: "Analyse the SSL/TLS certificate chain for a domain, including validity, issuer, and cipher info",
    inputSchema: {
      type: "object",
      properties: { domain: { type: "string", description: "Domain name or URL" } },
      required: ["domain"],
    },
  },
  {
    name: "http_headers",
    description: "Fetch and analyse HTTP response headers, highlighting security headers present or missing",
    inputSchema: {
      type: "object",
      properties: { domain: { type: "string", description: "Domain name or URL" } },
      required: ["domain"],
    },
  },
  {
    name: "cookies",
    description: "Inspect cookies set by a website and analyse their security attributes (HttpOnly, Secure, SameSite)",
    inputSchema: {
      type: "object",
      properties: { domain: { type: "string", description: "Domain name or URL" } },
      required: ["domain"],
    },
  },
  {
    name: "robots_txt",
    description: "Fetch and parse the robots.txt file to see crawl rules and potentially hidden paths",
    inputSchema: {
      type: "object",
      properties: { domain: { type: "string", description: "Domain name or URL" } },
      required: ["domain"],
    },
  },
  {
    name: "redirect_chain",
    description: "Trace all HTTP redirects from a URL to its final destination",
    inputSchema: {
      type: "object",
      properties: { domain: { type: "string", description: "Domain name or URL" } },
      required: ["domain"],
    },
  },
  {
    name: "open_ports",
    description: "Scan common ports on a server to determine which services are running",
    inputSchema: {
      type: "object",
      properties: { domain: { type: "string", description: "Domain name or URL" } },
      required: ["domain"],
    },
  },
  {
    name: "dnssec",
    description: "Check if DNSSEC, DoH (DNS over HTTPS) or DoT (DNS over TLS) are configured for a domain",
    inputSchema: {
      type: "object",
      properties: { domain: { type: "string", description: "Domain name or URL" } },
      required: ["domain"],
    },
  },
  {
    name: "whois",
    description: "Perform a WHOIS / RDAP lookup to get domain registration info, registrar, and expiry dates",
    inputSchema: {
      type: "object",
      properties: { domain: { type: "string", description: "Domain name or URL" } },
      required: ["domain"],
    },
  },
  {
    name: "sitemap",
    description: "Fetch and parse the sitemap.xml to discover all publicly listed pages",
    inputSchema: {
      type: "object",
      properties: { domain: { type: "string", description: "Domain name or URL" } },
      required: ["domain"],
    },
  },
  {
    name: "security_txt",
    description: "Check for a security.txt file and parse its vulnerability disclosure policy",
    inputSchema: {
      type: "object",
      properties: { domain: { type: "string", description: "Domain name or URL" } },
      required: ["domain"],
    },
  },
  {
    name: "email_security",
    description: "Check email security records: SPF, DKIM, DMARC, BIMI, and MX records",
    inputSchema: {
      type: "object",
      properties: { domain: { type: "string", description: "Domain name or URL" } },
      required: ["domain"],
    },
  },
  {
    name: "server_info",
    description: "Get server information including ASN, hosting provider, location, and response headers",
    inputSchema: {
      type: "object",
      properties: { domain: { type: "string", description: "Domain name or URL" } },
      required: ["domain"],
    },
  },
  {
    name: "linked_pages",
    description: "Extract all internal and external links found on a webpage",
    inputSchema: {
      type: "object",
      properties: { domain: { type: "string", description: "Domain name or URL" } },
      required: ["domain"],
    },
  },
  {
    name: "social_tags",
    description: "Extract Open Graph, Twitter Card, and other social meta tags from a webpage",
    inputSchema: {
      type: "object",
      properties: { domain: { type: "string", description: "Domain name or URL" } },
      required: ["domain"],
    },
  },
  {
    name: "http_security_features",
    description: "Evaluate HTTP security headers and score the overall security posture (HSTS, CSP, X-Frame-Options, etc.)",
    inputSchema: {
      type: "object",
      properties: { domain: { type: "string", description: "Domain name or URL" } },
      required: ["domain"],
    },
  },
  {
    name: "archive_history",
    description: "Fetch historical snapshots from the Wayback Machine (Internet Archive)",
    inputSchema: {
      type: "object",
      properties: { domain: { type: "string", description: "Domain name or URL" } },
      required: ["domain"],
    },
  },
  {
    name: "tls_cipher_suites",
    description: "Get TLS protocol version and cipher suite information for a domain",
    inputSchema: {
      type: "object",
      properties: { domain: { type: "string", description: "Domain name or URL" } },
      required: ["domain"],
    },
  },
  {
    name: "block_detection",
    description: "Check if a domain is blocked by popular DNS-based content/malware filters",
    inputSchema: {
      type: "object",
      properties: { domain: { type: "string", description: "Domain name or URL" } },
      required: ["domain"],
    },
  },
  {
    name: "server_status",
    description: "Check if a server is online and measure its response time",
    inputSchema: {
      type: "object",
      properties: { domain: { type: "string", description: "Domain name or URL" } },
      required: ["domain"],
    },
  },
  {
    name: "firewall_detection",
    description: "Detect if a website is protected by a WAF (Web Application Firewall) and identify which one",
    inputSchema: {
      type: "object",
      properties: { domain: { type: "string", description: "Domain name or URL" } },
      required: ["domain"],
    },
  },
  {
    name: "tech_stack",
    description: "Detect technologies used on a website (CMS, frameworks, analytics, CDN, etc.)",
    inputSchema: {
      type: "object",
      properties: { domain: { type: "string", description: "Domain name or URL" } },
      required: ["domain"],
    },
  },
  {
    name: "global_ranking",
    description: "Get the global traffic ranking of a website using the Tranco list",
    inputSchema: {
      type: "object",
      properties: { domain: { type: "string", description: "Domain name or URL" } },
      required: ["domain"],
    },
  },
  {
    name: "full_analysis",
    description: "Run a complete OSINT analysis on a website covering all available checks (IP, DNS, SSL, headers, WHOIS, security, tech stack, etc.)",
    inputSchema: {
      type: "object",
      properties: { domain: { type: "string", description: "Domain name or URL to fully analyse" } },
      required: ["domain"],
    },
  },
];

server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: TOOLS }));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;
  const domain = args?.domain;

  if (!domain) {
    return { content: [{ type: "text", text: JSON.stringify({ error: "domain is required" }) }] };
  }

  const toolMap = {
    ip_info: getIpInfo,
    dns_records: getDnsRecords,
    ssl_certificate: getSslCertificate,
    http_headers: getHeaders,
    cookies: getCookies,
    robots_txt: getRobotsTxt,
    redirect_chain: getRedirectChain,
    open_ports: getOpenPorts,
    dnssec: getDnssec,
    whois: getWhois,
    sitemap: getSitemap,
    security_txt: getSecurityTxt,
    email_security: getEmailSecurity,
    server_info: getServerInfo,
    linked_pages: getLinkedPages,
    social_tags: getSocialTags,
    http_security_features: getHttpSecurityFeatures,
    archive_history: getArchiveHistory,
    tls_cipher_suites: getTlsCipherSuites,
    block_detection: getBlockDetection,
    server_status: getServerStatus,
    firewall_detection: getFirewallDetection,
    tech_stack: getTechStack,
    global_ranking: getGlobalRanking,
    full_analysis: runFullAnalysis,
  };

  const fn = toolMap[name];
  if (!fn) {
    return { content: [{ type: "text", text: JSON.stringify({ error: `Unknown tool: ${name}` }) }] };
  }

  try {
    const result = await fn(domain);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  } catch (e) {
    return { content: [{ type: "text", text: JSON.stringify({ error: e.message }) }] };
  }
});

const transport = new StdioServerTransport();
await server.connect(transport);

// api/bypass.js  —  Vercel Serverless Function (Node.js)
// Dipanggil dari index.html:  /api/bypass?url=<tautan>[&mode=web]
// Cara kerja: ikuti redirect (manual, max 8 lompatan), baca halaman, cari tujuan berikutnya
// (meta refresh, location=..., atob("..."), tombol download/lanjut), ulangi sampai ketemu file/tujuan akhir.

const dns = require("dns").promises;
const net = require("net");

const UA = "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36";
const MAX_HOPS = 8;
const MAX_BYTES = 2000000;
const TIMEOUT = 7000;
const BUDGET = 8500;
const ALLOW_PRIVATE = process.env.SECRETLY_ALLOW_PRIVATE === "1"; // hanya untuk tes lokal
const PARAM_KEYS = ["url", "u", "link", "r", "redirect", "target", "dest", "destination", "go", "to", "href", "out"];
const BAD_HOST = /facebook\.com|twitter\.com|\/\/x\.com|instagram\.com|youtube\.com|youtu\.be|t\.me|wa\.me|whatsapp|tiktok\.com|play\.google|apps\.apple|privacy|terms|dmca|contact/i;

/* ---------- Keamanan: tolak alamat internal (SSRF) ---------- */
function isPrivateIp(ip) {
  if (net.isIPv4(ip)) {
    const [a, b] = ip.split(".").map(Number);
    return a === 0 || a === 10 || a === 127 || a >= 224 ||
      (a === 100 && b >= 64 && b <= 127) || (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) || (a === 192 && (b === 168 || b === 0));
  }
  const v = ip.toLowerCase();
  if (v === "::" || v === "::1" || v.includes("::ffff:")) return true;
  return /^(fc|fd|fe[89ab]|ff)/.test(v);
}
async function assertPublic(href) {
  const u = new URL(href);
  if (!/^https?:$/.test(u.protocol)) throw new Error("Protokol tidak didukung");
  if (ALLOW_PRIVATE) return u;
  const host = u.hostname.replace(/^\[|\]$/g, "");
  if (net.isIP(host)) { if (isPrivateIp(host)) throw new Error("Alamat tidak diizinkan"); return u; }
  const list = await dns.lookup(host, { all: true });
  if (!list.length || list.some(x => isPrivateIp(x.address))) throw new Error("Alamat tidak diizinkan");
  return u;
}

/* ---------- Helper parsing ---------- */
const abs = (h, base) => {
  try {
    const u = new URL(String(h).replace(/&amp;/g, "&").replace(/\\\//g, "/").trim(), base);
    return /^https?:$/.test(u.protocol) ? u.href : null;
  } catch (e) { return null; }
};
function b64url(s) {
  const d = Buffer.from(s.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8");
  return /^https?:\/\/[^\s]+$/i.test(d) ? d : null;
}
function paramTarget(href) {
  const p = new URL(href);
  for (const k of PARAM_KEYS) {
    const v = p.searchParams.get(k);
    if (!v) continue;
    if (/^https?:\/\//i.test(v)) return v;
    const d = b64url(v);
    if (d) return d;
  }
  return null;
}
function anchors(html, base) {
  const out = [], seen = new Set();
  for (const m of html.matchAll(/<a\b([^>]*)>([\s\S]*?)<\/a>/gi)) {
    const attrs = m[1];
    const href = (attrs.match(/\bhref=["']([^"']+)["']/i) || [])[1] ||
                 (attrs.match(/\bdata-(?:href|url|link)=["']([^"']+)["']/i) || [])[1];
    if (!href || /^(#|javascript:|mailto:|tel:)/i.test(href.trim())) continue;
    const url = abs(href, base);
    if (!url || BAD_HOST.test(url) || seen.has(url)) continue;
    seen.add(url);
    const text = m[2].replace(/<[^>]*>/g, " ").replace(/\s+/g, " ").trim().slice(0, 80);
    const meta = (attrs.match(/\b(?:id|class)=["'][^"']*["']/gi) || []).join(" ");
    let score = 0;
    if (/\bid=["']download["']/i.test(attrs)) score += 10;
    if (/download|get-?link|getlink|btn-main|go-?link|skip|continue|unlock|btn-success/i.test(meta)) score += 4;
    if (/download|unduh|get link|dapatkan|lanjut|continue|skip|unlock|buka|proceed/i.test(text)) score += 3;
    if (/\.(zip|rar|7z|apk|mp4|mp3|pdf|exe|txt|json|lua)(\?|$)/i.test(url)) score += 5;
    if (/download/i.test(url)) score += 2;
    out.push({ url, text, score });
  }
  return out.sort((a, b) => b.score - a.score);
}
function findNext(html, base) {
  let m;
  // 1) meta refresh
  m = html.match(/<meta[^>]+http-equiv=["']?refresh["']?[^>]*content=["']?\s*\d+\s*;\s*url=['"]?([^"'>\s]+)/i);
  if (m) { const a = abs(m[1], base); if (a && a !== base) return a; }
  // 2) redirect lewat JavaScript
  const js = [
    /getElementById\(\s*["']download["']\s*\)\.(?:href\s*=|setAttribute\(\s*["']href["']\s*,)\s*["']([^"']+)["']/i,
    /(?:window\.|document\.|top\.|self\.)?location(?:\.href)?\s*=\s*["']([^"']+)["']/i,
    /location\.(?:replace|assign)\(\s*["']([^"']+)["']/i,
    /window\.open\(\s*["'](https?:[^"']+)["']/i
  ];
  for (const re of js) {
    m = html.match(re);
    if (m) { const a = abs(m[1], base); if (a && a !== base && !/\.(css|js|png|jpe?g|gif|svg|ico|woff2?)(\?|$)/i.test(a)) return a; }
  }
  // 3) string base64 di script: atob("aHR0cHM6Ly8...")
  for (const mm of html.matchAll(/atob\(\s*["']([A-Za-z0-9+/=_-]{16,})["']\s*\)/g)) {
    const d = b64url(mm[1]); if (d) return d;
  }
  // 4) tombol / link download
  const best = anchors(html, base)[0];
  if (best && best.score >= 3 && best.url !== base) return best.url;
  return null;
}

/* ---------- Jaringan ---------- */
async function readLimited(res) {
  const reader = res.body.getReader(), chunks = [];
  let n = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    chunks.push(value); n += value.length;
    if (n > MAX_BYTES) { try { await reader.cancel(); } catch (e) {} break; }
  }
  return Buffer.concat(chunks).toString("utf8");
}
async function hop(url, jars, referer, deadline) {
  const ms = Math.min(TIMEOUT, deadline - Date.now());
  if (ms < 500) throw new Error("Waktu habis, situs terlalu lambat");
  const host = new URL(url).hostname;
  const jar = jars[host] || (jars[host] = new Map());
  const headers = {
    "user-agent": UA,
    accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "accept-language": "id-ID,id;q=0.9,en;q=0.8"
  };
  if (referer) headers.referer = referer;
  if (jar.size) headers.cookie = [...jar].map(([k, v]) => k + "=" + v).join("; ");
  const ac = new AbortController();
  const t = setTimeout(() => ac.abort(), ms);
  try {
    const res = await fetch(url, { redirect: "manual", headers, signal: ac.signal });
    const sc = typeof res.headers.getSetCookie === "function" ? res.headers.getSetCookie() : [];
    for (const c of sc) {
      const kv = c.split(";")[0], i = kv.indexOf("=");
      if (i > 0) jar.set(kv.slice(0, i).trim(), kv.slice(i + 1).trim());
    }
    const type = res.headers.get("content-type") || "";
    const disp = res.headers.get("content-disposition") || "";
    const location = res.headers.get("location");
    const redirect = res.status >= 300 && res.status < 400 && location;
    let text = "";
    if (!redirect && (!type || /text|json|xml|html/i.test(type)) && !/attachment/i.test(disp)) text = await readLimited(res);
    else { try { await res.body.cancel(); } catch (e) {} }
    return { status: res.status, type, disp, location: redirect ? location : null, text };
  } catch (e) {
    if (e.name === "AbortError") throw new Error("Waktu habis, situs terlalu lambat");
    throw new Error("Tidak bisa membuka situs (" + (e.cause && e.cause.code || e.message) + ")");
  } finally { clearTimeout(t); }
}

async function resolve(start) {
  const deadline = Date.now() + BUDGET;
  const jars = {}, trail = [start];
  let url = start, referer = "", html = "";
  const direct = paramTarget(start);
  if (direct) { url = direct; trail.push(url); }
  for (let i = 0; i < MAX_HOPS; i++) {
    await assertPublic(url);
    const r = await hop(url, jars, referer, deadline);
    if (r.location) {
      referer = url;
      url = new URL(r.location, url).href; trail.push(url);
      continue;
    }
    const isText = !r.type || /text|json|xml|html/i.test(r.type);
    if (!isText || /attachment/i.test(r.disp)) return { url, kind: "file", trail, html: "" };
    html = r.text;
    const next = findNext(html, url);
    if (!next || trail.includes(next)) return { url, kind: "page", trail, html };
    referer = url; url = next; trail.push(next);
  }
  return { url, kind: "page", trail, html };
}

/* ---------- Handler ---------- */
module.exports = async (req, res) => {
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  const send = (code, obj) => res.status(code).send(JSON.stringify(obj));
  try {
    const q = req.query || {};
    const target = String(q.url || "").trim();
    const mode = q.mode === "web" ? "web" : "link";
    if (!/^https?:\/\//i.test(target) || target.length > 2000) return send(400, { ok: false, error: "Tautan tidak valid" });
    await assertPublic(target);

    // Opsional: pakai API bypass lain (set env BYPASS_UPSTREAM di Vercel, contoh: https://api-kamu.com/bypass?url=)
    if (process.env.BYPASS_UPSTREAM) {
      try {
        const r = await fetch(process.env.BYPASS_UPSTREAM + encodeURIComponent(target), { signal: AbortSignal.timeout(6000) });
        const j = await r.json();
        const v = j.result || j.url || j.data || j.link || j.destination;
        if (typeof v === "string" && /^https?:\/\//i.test(v)) return send(200, { ok: true, result: v, via: "upstream" });
      } catch (e) { /* lanjut ke cara bawaan */ }
    }

    const r = await resolve(target);
    const changed = r.url !== target;
    const links = mode === "web" && r.html ? anchors(r.html, r.url).filter(a => a.score > 0).slice(0, 15) : [];
    if (r.kind === "file" || changed || links.length) {
      return send(200, { ok: true, result: r.url, kind: r.kind, trail: r.trail, links });
    }
    return send(200, {
      ok: false,
      error: "Tujuan tidak ditemukan. Kemungkinan situs ini memakai captcha, timer berbasis token, atau iklan yang hanya jalan di browser asli."
    });
  } catch (e) {
    return send(200, { ok: false, error: e.message || "Terjadi kesalahan" });
  }
};

// untuk pengujian lokal
module.exports._t = { findNext, anchors, paramTarget, isPrivateIp, resolve };

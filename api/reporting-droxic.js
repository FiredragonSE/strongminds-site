const crypto = require("crypto");

function secret() {
  return process.env.REPORTING_DROXIC_CODE || "";
}

function mac(payload) {
  return crypto.createHmac("sha256", secret()).update(payload).digest("hex");
}

function cookieValue() {
  const payload = String(Date.now() + 12 * 60 * 60 * 1000);
  return payload + "." + mac(payload);
}

function allowed(header) {
  const s = secret();
  if (!s) return false;
  const found = /(?:^|; )sm_reporting_droxic=([^;]+)/.exec(header || "");
  if (!found) return false;
  const raw = decodeURIComponent(found[1]);
  const cut = raw.lastIndexOf(".");
  if (cut < 1) return false;
  const payload = raw.slice(0, cut);
  const given = raw.slice(cut + 1);
  const expected = mac(payload);
  const a = Buffer.from(given);
  const b = Buffer.from(expected);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return false;
  return Number(payload) > Date.now();
}

function same(code) {
  const a = Buffer.from(String(code));
  const b = Buffer.from(secret());
  return a.length === b.length && a.length > 0 && crypto.timingSafeEqual(a, b);
}

module.exports = async function handler(req, res) {
  res.setHeader("Cache-Control", "no-store");
  if (!secret()) {
    res.status(500).json({ ok: false });
    return;
  }
  if (req.method === "GET") {
    if (!allowed(req.headers.cookie)) {
      res.status(401).json({ ok: false });
      return;
    }
    res.status(200).json({ ok: true });
    return;
  }
  if (req.method !== "POST") {
    res.status(405).json({ ok: false });
    return;
  }
  const body = req.body || {};
  if (!same(body.code || body.password)) {
    res.status(401).json({ ok: false });
    return;
  }
  res.setHeader(
    "Set-Cookie",
    "sm_reporting_droxic=" + encodeURIComponent(cookieValue()) + "; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=43200"
  );
  res.status(200).json({ ok: true });
};

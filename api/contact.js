module.exports = async function handler(req, res) {
  if (req.method !== "POST") {
    res.status(405).json({ ok: false });
    return;
  }
  const body = req.body || {};
  if (body.company_url) {
    res.status(200).json({ ok: true });
    return;
  }
  const name = String(body.name || "").trim().slice(0, 200);
  const email = String(body.email || "").trim().slice(0, 200);
  const company = String(body.company || "").trim().slice(0, 200);
  const message = String(body.message || "").trim().slice(0, 5000);
  if (!name || !email || !message || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    res.status(400).json({ ok: false });
    return;
  }
  const to = process.env.CONTACT_TO;
  if (!to) {
    res.status(500).json({ ok: false });
    return;
  }
  const sent = await fetch("https://formsubmit.co/ajax/" + encodeURIComponent(to), {
    method: "POST",
    headers: { "Content-Type": "application/json", Accept: "application/json" },
    body: JSON.stringify({
      name,
      email,
      company,
      message,
      _replyto: email,
      _subject: "Strong Minds \u2014 " + name,
      _captcha: "false",
      _template: "box",
    }),
  });
  if (!sent.ok) {
    res.status(502).json({ ok: false });
    return;
  }
  res.status(200).json({ ok: true });
};

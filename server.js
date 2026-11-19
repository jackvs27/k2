const express = require("express");
const path = require("path");
const fs = require("fs");
const fsp = fs.promises;

const app = express();
const PORT = Number(process.env.PORT) || 3000;

const ROOT = __dirname;
const DATA_DIR = path.join(ROOT, "data");
const PUBLIC_DIR = path.join(ROOT, "public");

const EXPLOITS_FILE = path.join(DATA_DIR, "exploits.json");
const NEWS_FILE = path.join(DATA_DIR, "news.json");
const MESSAGES_FILE = path.join(DATA_DIR, "messages.json");

const MESSAGE_WINDOW_MS = 60_000;
const MESSAGE_LIMIT_PER_WINDOW = 3;
const MESSAGE_RETENTION = 250;
const pseudoRateLimits = new Map();

app.disable("x-powered-by");
app.set("trust proxy", true);
app.use(express.json({ limit: "16kb" }));

// Small security headers. No CSP here because the UI intentionally uses a
// couple of small inline style hooks; the frontend escapes all dynamic text.
app.use((req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("X-Frame-Options", "SAMEORIGIN");
  next();
});

function clientIp(req) {
  const raw = req.ip || req.socket?.remoteAddress || "";
  return raw.replace(/^::ffff:/i, "");
}

async function readJsonFile(file, fallback) {
  try {
    const raw = await fsp.readFile(file, "utf8");
    return JSON.parse(raw);
  } catch (err) {
    console.error(`[data] Impossible de lire ${path.basename(file)}:`, err.message);
    return fallback;
  }
}

function normalizeMessages(value) {
  return Array.isArray(value) ? value : [];
}

app.get("/api/ip", (req, res) => {
  res.setHeader("Cache-Control", "no-store");
  res.json({
    ip: clientIp(req),
    source: "server",
    checkedAt: new Date().toISOString()
  });
});

app.get("/api/exploits", async (req, res) => {
  res.setHeader("Cache-Control", "no-store");
  const exploits = await readJsonFile(EXPLOITS_FILE, []);
  res.json(Array.isArray(exploits) ? exploits : []);
});

app.get("/api/news", async (req, res) => {
  res.setHeader("Cache-Control", "no-store");
  const news = await readJsonFile(NEWS_FILE, { news: [], tools: [] });
  res.json(news);
});

app.get("/api/messages", async (req, res) => {
  res.setHeader("Cache-Control", "no-store");
  const stored = await readJsonFile(MESSAGES_FILE, []);
  const messages = normalizeMessages(stored).slice(-MESSAGE_RETENTION);
  res.setHeader("X-Total-Count", String(messages.length));
  res.json(messages);
});

app.post("/api/messages", async (req, res) => {
  const body = req.body && typeof req.body === "object" ? req.body : {};

  const pseudo = typeof body.pseudo === "string" ? body.pseudo.trim() : "";
  const rawContent = typeof body.content === "string" ? body.content : "";
  // Drop control characters that can break a terminal/JSON display.
  const content = rawContent
    .replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, "")
    .trim();

  if (!/^[\p{L}\p{N}_.-]{2,24}$/u.test(pseudo)) {
    return res.status(400).json({
      error: "Pseudo invalide : 2 à 24 caractères (lettres, chiffres, _, ., -)."
    });
  }

  if (content.length < 3) {
    return res.status(400).json({ error: "Le message doit contenir au moins 3 caractères." });
  }

  if (content.length > 500) {
    return res.status(400).json({ error: "Le message est limité à 500 caractères." });
  }

  const now = Date.now();
  const rateKey = pseudo.toLocaleLowerCase("fr");
  const previous = pseudoRateLimits.get(rateKey) || [];
  const recent = previous.filter((ts) => now - ts < MESSAGE_WINDOW_MS);

  if (recent.length >= MESSAGE_LIMIT_PER_WINDOW) {
    return res.status(429).json({
      error: "Trop de messages envoyés. Réessayez dans une minute.",
      retryAfterSeconds: 60
    });
  }

  const stored = normalizeMessages(await readJsonFile(MESSAGES_FILE, []));
  const message = {
    id: `${now.toString(36)}-${Math.random().toString(36).slice(2, 8)}`,
    pseudo,
    content,
    createdAt: new Date().toISOString()
  };

  stored.push(message);
  const trimmed = stored.slice(-MESSAGE_RETENTION);

  try {
    const tmpFile = `${MESSAGES_FILE}.${process.pid}.tmp`;
    await fsp.writeFile(tmpFile, `${JSON.stringify(trimmed, null, 2)}\n`, "utf8");
    await fsp.rename(tmpFile, MESSAGES_FILE);
  } catch (err) {
    console.error("[data] Écriture des messages impossible:", err);
    return res.status(500).json({ error: "Impossible d'enregistrer le message pour le moment." });
  }

  pseudoRateLimits.set(rateKey, recent.concat(now));

  // Opportunistic cleanup so the in-memory map cannot grow forever.
  if (pseudoRateLimits.size > 1000) {
    for (const [key, timestamps] of pseudoRateLimits.entries()) {
      const stillRelevant = timestamps.some((ts) => now - ts < MESSAGE_WINDOW_MS);
      if (!stillRelevant) pseudoRateLimits.delete(key);
    }
  }

  res.status(201).json(message);
});

// Serve the static portfolio.
app.use(express.static(PUBLIC_DIR, { extensions: ["html"] }));

app.get("/", (req, res) => {
  res.sendFile(path.join(PUBLIC_DIR, "index.html"));
});

app.get("/api/*", (req, res) => {
  res.status(404).json({ error: "Route API inconnue." });
});

// Unknown non-API route: send the SPA-ish landing page for convenience.
app.use((req, res) => {
  if (req.accepts("html")) {
    return res.sendFile(path.join(PUBLIC_DIR, "index.html"));
  }
  return res.status(404).json({ error: "Ressource introuvable." });
});

app.use((err, req, res, next) => {
  console.error("[express]", err);
  if (res.headersSent) return next(err);
  res.status(500).json({ error: "Erreur interne du serveur." });
});

app.listen(PORT, () => {
  console.log(`\n  cybersite — http://localhost:${PORT}`);
  console.log(`  API       — http://localhost:${PORT}/api/exploits`);
  console.log(`  Données   — ${DATA_DIR}\n`);
});
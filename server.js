import express from 'express';
import Anthropic from '@anthropic-ai/sdk';
import multer from 'multer';
import archiver from 'archiver';
import rateLimit from 'express-rate-limit';
import { readdir, readFile, writeFile, mkdir } from 'fs/promises';
import { existsSync } from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import dns from 'dns/promises';
import cookieParser from 'cookie-parser';
import crypto from 'crypto';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const app = express();

// --- Persistent session storage ---
const SESSION_DIR = process.env.SESSION_DIR || path.join(__dirname, 'data', 'sessions');
const SESSION_MAX_AGE = 7 * 24 * 60 * 60 * 1000; // 7 days

async function loadSessions() {
  if (!existsSync(SESSION_DIR)) {
    await mkdir(SESSION_DIR, { recursive: true });
    return;
  }
  const files = await readdir(SESSION_DIR);
  let loaded = 0;
  for (const file of files) {
    if (!file.endsWith('.json')) continue;
    try {
      const data = JSON.parse(await readFile(path.join(SESSION_DIR, file), 'utf8'));
      const id = file.replace('.json', '');
      // Skip expired sessions
      if (Date.now() - (data.createdAt || 0) > SESSION_MAX_AGE) continue;
      sessions.set(id, data);
      loaded++;
    } catch {}
  }
  console.log(`Loaded ${loaded} sessions from disk`);
}

async function saveSession(id) {
  const session = sessions.get(id);
  if (!session) return;
  if (!existsSync(SESSION_DIR)) await mkdir(SESSION_DIR, { recursive: true });
  await writeFile(
    path.join(SESSION_DIR, `${id}.json`),
    JSON.stringify(session),
    'utf8'
  );
}

async function deleteSessionFile(id) {
  const filePath = path.join(SESSION_DIR, `${id}.json`);
  if (existsSync(filePath)) {
    const { unlink } = await import('fs/promises');
    await unlink(filePath).catch(() => {});
  }
}

// Trust proxy (Render uses reverse proxy)
app.set('trust proxy', 1);

// Force HTTPS in production (Render sets X-Forwarded-Proto)
app.use((req, res, next) => {
  if (req.headers['x-forwarded-proto'] === 'http') {
    return res.redirect(301, `https://${req.hostname}${req.url}`);
  }
  next();
});

// --- CORS & Origin validation ---
const ALLOWED_ORIGINS = [
  'https://freeaisitebuilder.com',
  'https://www.freeaisitebuilder.com',
  'https://freeaisitebuilder.onrender.com',
  'http://localhost:3000',
];

app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (origin && ALLOWED_ORIGINS.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  }
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

// Block API requests from unknown origins (except same-origin which has no Origin header)
function requireOrigin(req, res, next) {
  const origin = req.headers.origin;
  // Same-origin requests (from our own pages) don't have an Origin header
  if (!origin) return next();
  if (ALLOWED_ORIGINS.includes(origin)) return next();
  return res.status(403).json({ error: 'Forbidden' });
}

app.use(express.json({ limit: '1mb' }));
app.use(cookieParser());

// --- Magic link auth system ---
const AUTH_SECRET = process.env.AUTH_SECRET || crypto.randomBytes(32).toString('hex');
const AUTH_DIR = process.env.AUTH_DIR || path.join(__dirname, 'data', 'auth');
const magicTokens = new Map(); // token -> { email, expiresAt }
const authSessions = new Map(); // authToken (cookie) -> { email, expiresAt }

async function loadAuthSessions() {
  if (!existsSync(AUTH_DIR)) {
    await mkdir(AUTH_DIR, { recursive: true });
    return;
  }
  try {
    const data = await readFile(path.join(AUTH_DIR, 'sessions.json'), 'utf8');
    const entries = JSON.parse(data);
    for (const [token, session] of Object.entries(entries)) {
      if (session.expiresAt > Date.now()) {
        authSessions.set(token, session);
      }
    }
    console.log(`Loaded ${authSessions.size} auth sessions`);
  } catch {}
}

async function saveAuthSessions() {
  if (!existsSync(AUTH_DIR)) await mkdir(AUTH_DIR, { recursive: true });
  const obj = Object.fromEntries(authSessions);
  await writeFile(path.join(AUTH_DIR, 'sessions.json'), JSON.stringify(obj), 'utf8');
}

// Rate limit for magic link requests
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // 5 attempts per 15 min per IP
  message: { error: 'Too many login attempts. Please wait and try again.' },
  standardHeaders: true,
  legacyHeaders: false,
});

// Send magic link email
app.post('/api/auth/send-magic-link', requireOrigin, authLimiter, async (req, res) => {
  const { email } = req.body;
  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({ error: 'Please enter a valid email address.' });
  }

  const token = crypto.randomBytes(32).toString('hex');
  magicTokens.set(token, { email: email.toLowerCase(), expiresAt: Date.now() + 15 * 60 * 1000 }); // 15 min expiry

  const baseUrl = process.env.BASE_URL || `${req.protocol}://${req.get('host')}`;
  const magicLink = `${baseUrl}/api/auth/verify?token=${token}`;

  // Send email via Resend
  const resendKey = process.env.RESEND_API_KEY;
  if (!resendKey) {
    console.error('RESEND_API_KEY not set — magic link:', magicLink);
    return res.json({ ok: true, message: 'Check your email for a login link.' });
  }

  try {
    const { Resend } = await import('resend');
    const resend = new Resend(resendKey);
    await resend.emails.send({
      from: process.env.EMAIL_FROM || 'Free AI Site Builder <noreply@freeaisitebuilder.com>',
      to: email.toLowerCase(),
      subject: 'Your Login Link — Free AI Site Builder',
      html: `
        <div style="font-family:sans-serif;max-width:480px;margin:0 auto;padding:2rem;">
          <h2 style="color:#1a1a1a;">Log in to Free AI Site Builder</h2>
          <p style="color:#666;line-height:1.6;">Click the button below to log in and start building your website. This link expires in 15 minutes.</p>
          <a href="${magicLink}" style="display:inline-block;background:#C8A46E;color:#0A0A0A;padding:12px 32px;border-radius:6px;text-decoration:none;font-weight:700;margin:1rem 0;">Log In</a>
          <p style="color:#999;font-size:0.85rem;">If you didn't request this, you can safely ignore this email.</p>
          <hr style="border:none;border-top:1px solid #eee;margin:1.5rem 0;">
          <p style="color:#bbb;font-size:0.75rem;">freeaisitebuilder.com</p>
        </div>
      `,
    });
    res.json({ ok: true, message: 'Check your email for a login link.' });
  } catch (err) {
    console.error('Email send error:', err.message);
    res.status(500).json({ error: 'Failed to send login email. Please try again.' });
  }
});

// Verify magic link token
app.get('/api/auth/verify', async (req, res) => {
  const { token } = req.query;
  const record = magicTokens.get(token);

  if (!record || record.expiresAt < Date.now()) {
    magicTokens.delete(token);
    return res.redirect('/login.html?error=expired');
  }

  // Create auth session
  const authToken = crypto.randomBytes(32).toString('hex');
  authSessions.set(authToken, {
    email: record.email,
    expiresAt: Date.now() + 30 * 24 * 60 * 60 * 1000, // 30 days
  });
  magicTokens.delete(token);
  await saveAuthSessions();

  // Set cookie
  res.cookie('auth', authToken, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production' || req.headers['x-forwarded-proto'] === 'https',
    sameSite: 'lax',
    maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
  });

  res.redirect('/step2.html');
});

// Check auth status
app.get('/api/auth/me', (req, res) => {
  const authToken = req.cookies?.auth;
  if (!authToken) return res.json({ authenticated: false });

  const session = authSessions.get(authToken);
  if (!session || session.expiresAt < Date.now()) {
    authSessions.delete(authToken);
    return res.json({ authenticated: false });
  }

  res.json({ authenticated: true, email: session.email });
});

// Logout
app.post('/api/auth/logout', (req, res) => {
  const authToken = req.cookies?.auth;
  if (authToken) {
    authSessions.delete(authToken);
    saveAuthSessions();
  }
  res.clearCookie('auth');
  res.json({ ok: true });
});

// Auth middleware — checks cookie, returns email or null
function getAuthEmail(req) {
  const authToken = req.cookies?.auth;
  if (!authToken) return null;
  const session = authSessions.get(authToken);
  if (!session || session.expiresAt < Date.now()) {
    authSessions.delete(authToken);
    return null;
  }
  return session.email;
}

function requireAuth(req, res, next) {
  const email = getAuthEmail(req);
  if (!email) {
    return res.status(401).json({ error: 'Please log in first.', redirect: '/login.html' });
  }
  req.userEmail = email;
  next();
}

// Clean up expired magic tokens periodically
setInterval(() => {
  const now = Date.now();
  for (const [token, record] of magicTokens) {
    if (record.expiresAt < now) magicTokens.delete(token);
  }
  for (const [token, session] of authSessions) {
    if (session.expiresAt < now) authSessions.delete(token);
  }
}, 60 * 60 * 1000);

// --- Block direct access to uploads/ and generated/ directories ---
app.use('/uploads', (req, res, next) => {
  // Only allow if the referrer is from our own site (i.e., loaded within our pages)
  const referer = req.headers.referer || '';
  const isOwnSite = ALLOWED_ORIGINS.some(o => referer.startsWith(o));
  if (!isOwnSite && !referer.startsWith('http://localhost')) {
    return res.status(403).send('Forbidden');
  }
  next();
});
app.use('/generated', (req, res, next) => {
  const referer = req.headers.referer || '';
  const isOwnSite = ALLOWED_ORIGINS.some(o => referer.startsWith(o));
  if (!isOwnSite && !referer.startsWith('http://localhost')) {
    return res.status(403).send('Forbidden');
  }
  next();
});

app.use(express.static(path.join(__dirname, 'public')));

// --- Global daily token budget (prevent runaway costs) ---
const DAILY_TOKEN_BUDGET = 100_000_000; // 100M tokens/day — emergency brake only (~$300/day max)
let dailyTokensUsed = 0;
let dailyResetDate = new Date().toDateString();

function checkDailyBudget() {
  const today = new Date().toDateString();
  if (today !== dailyResetDate) {
    dailyTokensUsed = 0;
    dailyResetDate = today;
  }
  return dailyTokensUsed < DAILY_TOKEN_BUDGET;
}

// --- IP-based session tracking (max 3 sessions per IP per day) ---
const ipSessionTracker = new Map(); // ip -> { date, count }
const MAX_SESSIONS_PER_IP = 3;

function canCreateSession(ip) {
  const today = new Date().toDateString();
  const record = ipSessionTracker.get(ip);
  if (!record || record.date !== today) {
    ipSessionTracker.set(ip, { date: today, count: 1 });
    return true;
  }
  if (record.count >= MAX_SESSIONS_PER_IP) return false;
  record.count++;
  return true;
}

// --- Session cleanup (delete sessions older than 7 days) ---
setInterval(() => {
  const now = Date.now();
  for (const [id, session] of sessions) {
    if (now - session.createdAt > SESSION_MAX_AGE) {
      sessions.delete(id);
      deleteSessionFile(id);
    }
  }
  // Also clean up old IP tracking entries
  const today = new Date().toDateString();
  for (const [ip, record] of ipSessionTracker) {
    if (record.date !== today) ipSessionTracker.delete(ip);
  }
}, 60 * 60 * 1000); // run every hour

// --- SEO: robots.txt ---
app.get('/robots.txt', (req, res) => {
  res.type('text/plain');
  res.send(`User-agent: *
Allow: /
Disallow: /api/
Disallow: /chat.html
Disallow: /step1.html
Disallow: /step2.html
Disallow: /uploads/
Disallow: /generated/

Sitemap: https://freeaisitebuilder.com/sitemap.xml
`);
});

// --- SEO: sitemap.xml ---
app.get('/sitemap.xml', (req, res) => {
  res.type('application/xml');
  res.send(`<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url>
    <loc>https://freeaisitebuilder.com/</loc>
    <changefreq>weekly</changefreq>
    <priority>1.0</priority>
  </url>
</urlset>
`);
});

// --- Rate limiting ---
const chatLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 10, // 10 requests per minute per IP
  message: { error: 'Too many requests. Please wait a moment and try again.' },
  standardHeaders: true,
  legacyHeaders: false,
});

const uploadLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 5,
  message: { error: 'Too many uploads. Please wait a moment.' },
  standardHeaders: true,
  legacyHeaders: false,
});

const verifyLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 5, // 5 domain verifications per minute per IP
  message: { error: 'Too many verification attempts. Please wait a moment.' },
  standardHeaders: true,
  legacyHeaders: false,
});

// --- Config ---
const PORT = process.env.PORT || 3000;
const TOKEN_CAP = 100_000;

const anthropic = new Anthropic(); // uses ANTHROPIC_API_KEY env var

// Bluehost nameserver patterns
const BLUEHOST_NS_PATTERNS = [
  'bluehost.com',
  'bluehost.com.',
];

// --- Session store (in-memory, replace with DB for production) ---
const sessions = new Map();

// Track which domains have been verified (cache for 24h)
const verifiedDomains = new Map(); // domain -> { verified: bool, timestamp }

function getSession(id, ip, email) {
  if (!sessions.has(id)) {
    // Check IP session limit for new sessions
    if (ip && !canCreateSession(ip)) {
      return null; // IP has exceeded session limit
    }
    sessions.set(id, {
      inputTokens: 0,
      outputTokens: 0,
      step: 1,
      domain: null,
      domainVerified: false,
      history: [],
      generatedHtml: null,
      uploadedFiles: [],
      createdAt: Date.now(),
      ip: ip || 'unknown',
      email: email || null,
    });
  }
  return sessions.get(id);
}

// --- File uploads ---
const storage = multer.diskStorage({
  destination: (req, _file, cb) => {
    const dir = path.join(__dirname, 'public', 'uploads', req.body.sessionId || 'unknown');
    if (!existsSync(dir)) {
      mkdir(dir, { recursive: true }).then(() => cb(null, dir));
    } else {
      cb(null, dir);
    }
  },
  filename: (_req, file, cb) => {
    const safe = file.originalname.replace(/[^a-zA-Z0-9._-]/g, '_');
    cb(null, `${Date.now()}-${safe}`);
  },
});
const upload = multer({
  storage,
  limits: { fileSize: 10 * 1024 * 1024 }, // 10MB
  fileFilter: (_req, file, cb) => {
    const allowed = /\.(jpg|jpeg|png|gif|webp|svg|pdf)$/i;
    cb(null, allowed.test(file.originalname));
  },
});

app.post('/api/upload', requireOrigin, requireAuth, uploadLimiter, upload.array('files', 20), (req, res) => {
  const session = getSession(req.body.sessionId, req.ip);
  if (!session) {
    return res.status(429).json({ error: 'Too many sessions. Please try again tomorrow.' });
  }
  const files = (req.files || []).map(f => {
    session.uploadedFiles.push(f.filename);
    return f.originalname;
  });
  res.json({ files });
});

// --- Verify domain DNS (Bluehost check) ---
app.post('/api/verify-domain', requireOrigin, verifyLimiter, async (req, res) => {
  const { domain } = req.body;
  if (!domain) return res.status(400).json({ error: 'Domain required.' });

  const cleaned = domain.replace(/^(https?:\/\/)?(www\.)?/, '').replace(/\/+$/, '');

  // Check cache first
  const cached = verifiedDomains.get(cleaned);
  if (cached && Date.now() - cached.timestamp < 24 * 60 * 60 * 1000) {
    return res.json({ verified: cached.verified, domain: cleaned });
  }

  try {
    let isBluehost = false;

    // Try NS record check first
    try {
      const nsRecords = await dns.resolveNs(cleaned);
      console.log(`[DNS] NS records for ${cleaned}:`, nsRecords);
      isBluehost = nsRecords.some(ns =>
        BLUEHOST_NS_PATTERNS.some(pattern => ns.toLowerCase().includes(pattern))
      );
    } catch (nsErr) {
      console.log(`[DNS] NS lookup failed for ${cleaned}:`, nsErr.code);
      // NS lookup failed — try A record as fallback (Bluehost shared hosting IPs)
      try {
        const aRecords = await dns.resolve4(cleaned);
        console.log(`[DNS] A records for ${cleaned}:`, aRecords);
        // If domain has an A record, it's at least set up — allow it through
        if (aRecords.length > 0) {
          isBluehost = true;
        }
      } catch (aErr) {
        console.log(`[DNS] A lookup also failed for ${cleaned}:`, aErr.code);
      }
    }

    verifiedDomains.set(cleaned, { verified: isBluehost, timestamp: Date.now() });

    if (!isBluehost) {
      return res.json({
        verified: false,
        domain: cleaned,
        message: 'This domain doesn\'t appear to be hosted on Bluehost. Please set up your hosting first, then come back.',
      });
    }

    return res.json({ verified: true, domain: cleaned });
  } catch (err) {
    console.error(`[DNS] Unexpected error for ${cleaned}:`, err);
    return res.json({
      verified: false,
      domain: cleaned,
      message: 'We couldn\'t verify this domain. Make sure your hosting is set up and the domain is registered, then try again.',
    });
  }
});

// --- Register domain ---
app.post('/api/register-domain', requireOrigin, (req, res) => {
  const { sessionId, domain } = req.body;
  const ip = req.ip;
  const session = getSession(sessionId, ip);
  if (!session) {
    return res.status(429).json({ error: 'Too many sessions. Please try again tomorrow.' });
  }
  session.domain = domain;
  saveSession(sessionId);
  res.json({ ok: true, domain });
});

// --- System prompt ---
const SYSTEM_PROMPT = `You are an expert AI website builder embedded on freeaisitebuilder.com. Your job is to build a professional, beautiful website based on the user's project details.

## Your personality
- Friendly, encouraging, and patient
- You speak plainly — no jargon unless necessary
- You keep responses concise but thorough

## Context
The user has already completed Steps 1-2 (hosting setup and content collection) via a wizard. Their first message will contain their project details: site type, business name, description, domain, style preferences, and available images.

## Your process
When you receive their project details:

1. **Review & Clarify** — Briefly confirm what you'll build. Ask 2-3 quick questions about specific content they want on the site (e.g., "What services do you offer?" or "Do you have a tagline?"). Keep it conversational and quick — don't overwhelm them.

2. **Build** — Once you have enough info, generate a COMPLETE, production-ready single HTML file with inline CSS and JS. Make it genuinely beautiful.

3. **Refine** — After generating, ask what they'd like to change. Make revisions as requested. Keep iterating until they're happy.

4. **Launch** — When the user is happy, tell them to download their site and explain how to upload to Bluehost (File Manager → public_html).

## Image handling
- If the user has images available (listed as image paths from their domain), reference them using their full URL: https://{domain}/{imagePath}
- If they have no images, use tasteful placeholder sections and suggest they add images later
- You can also use CSS gradients, shapes, and icons for visual interest

## Response format
- Include a JSON metadata block at the END of every response (the frontend will parse this):
  \`\`\`json:metadata
  {"step": 3}
  \`\`\`
  Use step 3 for building/refining, step 4 when the site is ready to launch.
- When you generate or update HTML, include it in a special block:
  \`\`\`html:website
  <full html here>
  \`\`\`

## Important rules
- Always generate COMPLETE HTML files, not fragments
- Make the websites genuinely beautiful — use Google Fonts, modern CSS, subtle animations
- Sites must be fully responsive (mobile, tablet, desktop)
- Be responsive to feedback and make changes quickly
- If the user asks for something beyond a static website (e.g., e-commerce, database), explain that this tool builds static sites and suggest alternatives
- Keep your non-code responses SHORT. Users want to see their site, not read essays.`;

// --- Chat endpoint ---
app.post('/api/chat', requireOrigin, requireAuth, chatLimiter, async (req, res) => {
  const { sessionId, message } = req.body;
  const ip = req.ip;
  const session = getSession(sessionId, ip, req.userEmail);

  if (!session) {
    return res.status(429).json({ error: 'Too many sessions from your network today. Please try again tomorrow.' });
  }

  // Verify session belongs to this user
  if (session.email && session.email !== req.userEmail) {
    return res.status(403).json({ error: 'This session belongs to another user.' });
  }
  if (!session.email) session.email = req.userEmail;

  // Check if domain has been verified (Bluehost DNS check)
  if (!session.domainVerified) {
    // Check cache first
    if (session.domain && verifiedDomains.get(session.domain)?.verified) {
      session.domainVerified = true;
    } else if (session.domain) {
      // Re-verify on the fly
      try {
        let verified = false;
        try {
          const nsRecords = await dns.resolveNs(session.domain);
          verified = nsRecords.some(ns => BLUEHOST_NS_PATTERNS.some(p => ns.toLowerCase().includes(p)));
        } catch {
          // NS failed, try A record fallback
          try {
            const aRecords = await dns.resolve4(session.domain);
            verified = aRecords.length > 0;
          } catch {}
        }
        if (verified) {
          session.domainVerified = true;
          verifiedDomains.set(session.domain, { verified: true, timestamp: Date.now() });
          saveSession(req.body.sessionId || req.query.sessionId);
        } else {
          return res.status(403).json({ error: 'Please verify your domain with Bluehost hosting first.' });
        }
      } catch {
        return res.status(403).json({ error: 'Please verify your domain with Bluehost hosting first.' });
      }
    } else {
      return res.status(403).json({ error: 'Please verify your domain with Bluehost hosting first.' });
    }
  }

  // Check global daily budget
  if (!checkDailyBudget()) {
    return res.status(503).json({ error: 'Our AI service is at capacity for today. Please try again tomorrow.' });
  }

  if (session.inputTokens >= TOKEN_CAP || session.outputTokens >= TOKEN_CAP) {
    return res.json({
      error: 'You\'ve hit your token limit for this session. Download your site and finish building on the AI platform of your choice.',
      inputTokens: session.inputTokens,
      outputTokens: session.outputTokens,
      limitReached: true,
    });
  }

  // Build messages array
  session.history.push({ role: 'user', content: message });

  // Include info about uploaded files
  const fileContext = session.uploadedFiles.length > 0
    ? `\n\n[Available uploaded files for this session: ${session.uploadedFiles.join(', ')}. Reference them as ./uploads/${sessionId}/{filename}]`
    : '';

  try {
    const response = await anthropic.messages.create({
      model: 'claude-sonnet-4-5-20250929',
      max_tokens: Math.min(8192, TOKEN_CAP - session.outputTokens),
      system: SYSTEM_PROMPT + fileContext,
      messages: session.history,
    });

    const assistantText = response.content
      .filter(b => b.type === 'text')
      .map(b => b.text)
      .join('');

    // Track tokens separately
    session.inputTokens += response.usage.input_tokens;
    session.outputTokens += response.usage.output_tokens;
    dailyTokensUsed += response.usage.input_tokens + response.usage.output_tokens;

    // Parse metadata from response
    let step = session.step;
    const metaMatch = assistantText.match(/```json:metadata\s*\n([\s\S]*?)\n```/);
    if (metaMatch) {
      try {
        const meta = JSON.parse(metaMatch[1]);
        if (meta.step) {
          step = meta.step;
          session.step = step;
        }
      } catch {}
    }

    // Parse generated HTML
    let generatedHtml = null;
    const htmlMatch = assistantText.match(/```html:website\s*\n([\s\S]*?)\n```/);
    if (htmlMatch) {
      generatedHtml = htmlMatch[1];
      session.generatedHtml = generatedHtml;
      // Save to disk
      const genDir = path.join(__dirname, 'public', 'generated', sessionId);
      await mkdir(genDir, { recursive: true });
      await writeFile(path.join(genDir, 'index.html'), generatedHtml);
    }

    // Clean response text (remove metadata and html blocks for display)
    let displayText = assistantText
      .replace(/```json:metadata\s*\n[\s\S]*?\n```/g, '')
      .replace(/```html:website\s*\n[\s\S]*?\n```/g, '*Your website has been generated! Check the preview panel. →*')
      .trim();

    session.history.push({ role: 'assistant', content: assistantText });

    // Persist session to disk
    await saveSession(sessionId);

    res.json({
      response: displayText,
      inputTokens: session.inputTokens,
      outputTokens: session.outputTokens,
      step,
      generatedHtml,
    });
  } catch (err) {
    console.error('Anthropic API error:', err.message);
    res.status(500).json({ error: 'AI service error. Please try again.' });
  }
});

// --- Get user's sessions (for resume) ---
app.get('/api/my-sessions', requireAuth, (req, res) => {
  const userSessions = [];
  for (const [id, session] of sessions) {
    if (session.email === req.userEmail) {
      userSessions.push({
        sessionId: id,
        domain: session.domain,
        step: session.step,
        inputTokens: session.inputTokens,
        outputTokens: session.outputTokens,
        createdAt: session.createdAt,
        hasWebsite: !!session.generatedHtml,
      });
    }
  }
  userSessions.sort((a, b) => b.createdAt - a.createdAt);
  res.json({ sessions: userSessions });
});

// --- Resume session (for cross-device handoff) ---
app.get('/api/session/:sessionId', (req, res) => {
  if (!sessions.has(req.params.sessionId)) {
    return res.status(404).json({ error: 'Session not found. It may have expired.' });
  }
  const session = sessions.get(req.params.sessionId);
  // Return enough state for the client to resume
  const displayHistory = session.history
    .filter(m => m.role === 'assistant')
    .map(m => {
      let text = m.content
        .replace(/```json:metadata\s*\n[\s\S]*?\n```/g, '')
        .replace(/```html:website\s*\n[\s\S]*?\n```/g, '*Your website has been generated! Check the preview panel. →*')
        .trim();
      return { role: 'assistant', content: text };
    });
  res.json({
    inputTokens: session.inputTokens,
    outputTokens: session.outputTokens,
    step: session.step,
    generatedHtml: session.generatedHtml,
    domain: session.domain,
    history: displayHistory,
  });
});

// --- Download site as ZIP ---
app.get('/api/download/:sessionId', async (req, res) => {
  const session = sessions.get(req.params.sessionId);
  if (!session || !session.generatedHtml) {
    return res.status(404).json({ error: 'No website generated yet or session expired.' });
  }

  res.setHeader('Content-Type', 'application/zip');
  res.setHeader('Content-Disposition', 'attachment; filename=my-website.zip');

  const archive = archiver('zip', { zlib: { level: 9 } });
  archive.pipe(res);

  // Add the HTML file
  archive.append(session.generatedHtml, { name: 'index.html' });

  // Add uploaded images
  const uploadDir = path.join(__dirname, 'public', 'uploads', req.params.sessionId);
  if (existsSync(uploadDir)) {
    archive.directory(uploadDir, 'uploads');
  }

  // Add a simple README
  archive.append(
    `HOW TO UPLOAD YOUR WEBSITE TO BLUEHOST
=====================================

1. Log in to your Bluehost account at bluehost.com
2. Go to "Advanced" in the left sidebar
3. Click "File Manager"
4. Navigate to the "public_html" folder
5. Upload ALL files from this ZIP into public_html
   - index.html goes directly in public_html
   - The "uploads" folder goes inside public_html too
6. Visit your domain — your site is live!

Need help? Contact support@bluehost.com
`,
    { name: 'README.txt' }
  );

  await archive.finalize();
});

// --- Handoff file (when token cap is reached) ---
app.get('/api/handoff/:sessionId', async (req, res) => {
  const session = sessions.get(req.params.sessionId);
  if (!session) {
    return res.status(404).json({ error: 'Session not found or expired.' });
  }

  res.setHeader('Content-Type', 'application/zip');
  res.setHeader('Content-Disposition', 'attachment; filename=website-project-handoff.zip');

  const archive = archiver('zip', { zlib: { level: 9 } });
  archive.pipe(res);

  // Add current HTML if exists
  if (session.generatedHtml) {
    archive.append(session.generatedHtml, { name: 'index.html' });
  }

  // Add uploaded images
  const uploadDir = path.join(__dirname, 'public', 'uploads', req.params.sessionId);
  if (existsSync(uploadDir)) {
    archive.directory(uploadDir, 'uploads');
  }

  // Add conversation history as a handoff prompt
  const handoff = `WEBSITE PROJECT HANDOFF
======================
Continue building this website using Claude (claude.ai) or another AI.

DOMAIN: ${session.domain || 'Not specified'}

CONVERSATION SO FAR:
${session.history.map(m => `[${m.role.toUpperCase()}]: ${m.content}`).join('\n\n')}

CURRENT WEBSITE CODE:
${session.generatedHtml || 'No code generated yet.'}

INSTRUCTIONS FOR AI:
Please continue helping the user refine their website. The HTML should be a single self-contained file with inline CSS and JavaScript. Make it beautiful, modern, and responsive.
`;

  archive.append(handoff, { name: 'HANDOFF-PROMPT.txt' });

  archive.append(
    `HOW TO CONTINUE BUILDING YOUR WEBSITE
======================================

1. Go to claude.ai and create a free account (or use ChatGPT, etc.)
2. Start a new conversation
3. Upload the "HANDOFF-PROMPT.txt" file from this ZIP
4. The AI will have full context of your project and can continue from where we left off
5. When you're done, follow the Bluehost upload instructions in README.txt
`,
    { name: 'README.txt' }
  );

  await archive.finalize();
});

// Load persisted sessions and auth, then start server
Promise.all([loadSessions(), loadAuthSessions()]).then(() => {
  app.listen(PORT, () => {
    console.log(`Website Builder running at http://localhost:${PORT}`);
  });
});

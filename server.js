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
  const { email, next } = req.body;
  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({ error: 'Please enter a valid email address.' });
  }

  // Whitelist valid redirect destinations
  const validNextPages = { step1: '/step1.html', step2: '/step2.html', chat: '/chat.html', 'affiliate-dashboard': '/affiliate-dashboard.html' };
  const redirectTo = validNextPages[next] || '/step2.html';

  const token = crypto.randomBytes(32).toString('hex');
  magicTokens.set(token, { email: email.toLowerCase(), redirectTo, expiresAt: Date.now() + 15 * 60 * 1000 }); // 15 min expiry

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

  res.redirect(record.redirectTo || '/step2.html');
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

// Helper: create a magic link token and return the full URL
function createMagicToken(email, redirectTo) {
  const token = crypto.randomBytes(32).toString('hex');
  magicTokens.set(token, { email: email.toLowerCase(), redirectTo, expiresAt: Date.now() + 24 * 60 * 60 * 1000 }); // 24 hour expiry for referral emails
  const baseUrl = process.env.BASE_URL || 'https://freeaisitebuilder.com';
  return `${baseUrl}/api/auth/verify?token=${token}`;
}

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

// Health check endpoint — responds before static files for fast Render health checks
app.get('/healthz', (req, res) => res.status(200).send('ok'));

app.use(express.static(path.join(__dirname, 'public')));

// Clean URL routes
app.get('/affiliate', (req, res) => res.sendFile(path.join(__dirname, 'public', 'affiliate.html')));
app.get('/affiliate-dashboard', (req, res) => res.sendFile(path.join(__dirname, 'public', 'affiliate-dashboard.html')));

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
      bonusTokens: 0,
      step: 1,
      domain: null,
      domainVerified: false,
      history: [],
      generatedHtml: null,
      uploadedFiles: [],
      createdAt: Date.now(),
      ip: ip || 'unknown',
      email: email || null,
      referralTokenCredited: false,
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
app.post('/api/register-domain', requireOrigin, async (req, res) => {
  const { sessionId, domain, ref } = req.body;
  const ip = req.ip;
  const session = getSession(sessionId, ip);
  if (!session) {
    return res.status(429).json({ error: 'Too many sessions. Please try again tomorrow.' });
  }
  session.domain = domain;
  saveSession(sessionId);

  // Auto-create affiliate account for this user
  let userRefCode = null;
  if (AIRTABLE_TOKEN) {
    try {
      const userEmail = getAuthEmail(req);
      if (userEmail) {
        const existingAffiliate = await findAffiliate('Email', userEmail);
        if (existingAffiliate) {
          userRefCode = existingAffiliate.fields.RefCode;
        } else {
          // Create a new affiliate account automatically
          const refCode = generateRefCode(userEmail.split('@')[0]);
          const createRes = await fetch(AFFILIATES_URL, {
            method: 'POST',
            headers: {
              Authorization: `Bearer ${AIRTABLE_TOKEN}`,
              'Content-Type': 'application/json',
            },
            body: JSON.stringify({
              records: [{
                fields: {
                  Name: userEmail.split('@')[0],
                  Email: userEmail.toLowerCase().trim(),
                  RefCode: refCode,
                  PayPalEmail: userEmail.toLowerCase().trim(),
                  Clicks: 0,
                  Conversions: 0,
                }
              }]
            }),
          });
          if (createRes.ok) {
            userRefCode = refCode;
            console.log(`[Affiliate] Auto-created affiliate for ${userEmail}: ${refCode}`);
          }
        }
      }
    } catch (err) {
      console.error('Auto-create affiliate error:', err.message);
    }
  }

  // Track affiliate conversion if ref code provided
  if (ref && AIRTABLE_TOKEN) {
    try {
      const affiliate = await findAffiliate('RefCode', ref);
      if (affiliate) {
        const customerEmail = getAuthEmail(req) || 'unknown';

        // Log conversion in Conversions table
        await fetch(CONVERSIONS_URL, {
          method: 'POST',
          headers: {
            Authorization: `Bearer ${AIRTABLE_TOKEN}`,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            records: [{
              fields: {
                RefCode: ref,
                CustomerEmail: customerEmail,
                Domain: domain,
                Date: new Date().toISOString().split('T')[0],
                PaidOut: false,
                Status: 'Pending',
              }
            }]
          }),
        });

        // Increment conversion count on affiliate record
        const currentConversions = affiliate.fields.Conversions || 0;
        await fetch(`${AFFILIATES_URL}/${affiliate.id}`, {
          method: 'PATCH',
          headers: {
            Authorization: `Bearer ${AIRTABLE_TOKEN}`,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({ fields: { Conversions: currentConversions + 1 } }),
        });

        console.log(`[Affiliate] Conversion logged: ref=${ref}, domain=${domain}`);

        // Credit bonus tokens to referrer if this is their first referral conversion
        const referrerEmail = affiliate.fields.Email;
        if (referrerEmail) {
          // Find referrer's session and credit 100k bonus tokens (first conversion only)
          let referrerSession = null;
          let referrerSessionId = null;
          for (const [sid, sess] of sessions) {
            if (sess.email && sess.email.toLowerCase() === referrerEmail.toLowerCase() && !sess.referralTokenCredited) {
              referrerSession = sess;
              referrerSessionId = sid;
              break;
            }
          }

          if (referrerSession && !referrerSession.referralTokenCredited) {
            referrerSession.bonusTokens = (referrerSession.bonusTokens || 0) + 100000;
            referrerSession.referralTokenCredited = true;
            await saveSession(referrerSessionId);
            console.log(`[Affiliate] Credited 100k bonus tokens to ${referrerEmail}`);
          }

          // Send email notification to referrer
          const RESEND_API_KEY = process.env.RESEND_API_KEY;
          if (RESEND_API_KEY) {
            const baseUrl = process.env.BASE_URL || 'https://freeaisitebuilder.com';
            // Create a magic link so they can jump back to their session
            const magicLink = createMagicToken(referrerEmail, '/chat.html' + (referrerSessionId ? `?session=${referrerSessionId}` : ''));
            try {
              await fetch('https://api.resend.com/emails', {
                method: 'POST',
                headers: {
                  Authorization: `Bearer ${RESEND_API_KEY}`,
                  'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                  from: 'Free AI Site Builder <noreply@freeaisitebuilder.com>',
                  to: [referrerEmail],
                  subject: 'Your friend signed up! You just earned 100k bonus tokens 🎉',
                  html: `
                    <div style="font-family:sans-serif;max-width:500px;margin:0 auto;padding:2rem;">
                      <h2 style="color:#1a1a1a;">Great news!</h2>
                      <p style="color:#666;line-height:1.6;">One of the friends you shared your link with just signed up and started building their website.</p>
                      <p style="color:#666;line-height:1.6;">We've credited your account with <strong style="color:#1a1a1a;">100,000 bonus tokens</strong> so you can keep building your site.</p>
                      <div style="text-align:center;margin:2rem 0;">
                        <a href="${magicLink}" style="display:inline-block;background:#C8A46E;color:#0A0A0A;padding:0.8rem 2rem;border-radius:6px;text-decoration:none;font-weight:700;">Continue Building My Site</a>
                      </div>
                      <p style="color:#999;font-size:0.85rem;">Every additional friend who builds a site earns you $10. Keep sharing!</p>
                    </div>
                  `,
                }),
              });
              console.log(`[Affiliate] Sent token credit email to ${referrerEmail}`);
            } catch (emailErr) {
              console.error('Failed to send referral token email:', emailErr.message);
            }
          }
        }
      }
    } catch (err) {
      console.error('Affiliate conversion tracking error:', err.message);
      // Don't block the main flow — conversion tracking is best-effort
    }
  }

  res.json({ ok: true, domain, refCode: userRefCode });
});

// GET /api/session/token-status — check if bonus tokens were credited
app.get('/api/session/token-status', requireAuth, (req, res) => {
  // Find user's session
  for (const [sid, sess] of sessions) {
    if (sess.email && sess.email.toLowerCase() === req.userEmail.toLowerCase()) {
      return res.json({
        inputTokens: sess.inputTokens,
        outputTokens: sess.outputTokens,
        bonusTokens: sess.bonusTokens || 0,
        tokenCap: TOKEN_CAP + (sess.bonusTokens || 0),
        referralTokenCredited: sess.referralTokenCredited || false,
      });
    }
  }
  res.json({ bonusTokens: 0, tokenCap: TOKEN_CAP, referralTokenCredited: false });
});

// GET /api/affiliate/my-link — get current user's affiliate ref code
app.get('/api/affiliate/my-link', async (req, res) => {
  const email = getAuthEmail(req);
  if (!email || !AIRTABLE_TOKEN) return res.json({ refCode: null });
  try {
    const affiliate = await findAffiliate('Email', email);
    if (affiliate) {
      return res.json({ refCode: affiliate.fields.RefCode });
    }
  } catch (err) {
    console.error('Get my-link error:', err.message);
  }
  res.json({ refCode: null });
});

// --- Airtable config ---
const AIRTABLE_TOKEN = process.env.AIRTABLE_TOKEN;
const AIRTABLE_BASE_ID = 'appv8t55Y7YYDmXQj';
const AIRTABLE_TABLE_NAME = 'Free AI Site Builder Website';
const AIRTABLE_URL = `https://api.airtable.com/v0/${AIRTABLE_BASE_ID}/${encodeURIComponent(AIRTABLE_TABLE_NAME)}`;
const AFFILIATES_TABLE = 'Affiliates';
const CONVERSIONS_TABLE = 'Conversions';
const AFFILIATES_URL = `https://api.airtable.com/v0/${AIRTABLE_BASE_ID}/${encodeURIComponent(AFFILIATES_TABLE)}`;
const CONVERSIONS_URL = `https://api.airtable.com/v0/${AIRTABLE_BASE_ID}/${encodeURIComponent(CONVERSIONS_TABLE)}`;
const REIMBURSEMENTS_TABLE = 'Reimbursements';
const REIMBURSEMENTS_URL = `https://api.airtable.com/v0/${AIRTABLE_BASE_ID}/${encodeURIComponent(REIMBURSEMENTS_TABLE)}`;
const REIMBURSE_CAP = 20;

// In-memory click counter (persisted to Airtable periodically)
const clickBuffer = new Map(); // refCode -> count since last flush

app.post('/api/zoom-signup', requireOrigin, async (req, res) => {
  const { name, email } = req.body;
  if (!name || !email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({ error: 'Please provide a valid name and email.' });
  }

  if (!AIRTABLE_TOKEN) {
    console.error('AIRTABLE_TOKEN not set');
    return res.status(500).json({ error: 'Signup service not configured.' });
  }

  try {
    // Check for duplicate email in Airtable
    const searchUrl = `${AIRTABLE_URL}?filterByFormula=${encodeURIComponent(`LOWER({Email})="${email.toLowerCase().trim()}"`)}&maxRecords=1`;
    const searchRes = await fetch(searchUrl, {
      headers: { Authorization: `Bearer ${AIRTABLE_TOKEN}` },
    });
    const searchData = await searchRes.json();

    if (searchData.records && searchData.records.length > 0) {
      return res.json({ ok: true, message: 'Already signed up.' });
    }

    // Create new record
    const createRes = await fetch(AIRTABLE_URL, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${AIRTABLE_TOKEN}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        records: [{
          fields: {
            Name: name.trim(),
            Email: email.toLowerCase().trim(),
          }
        }]
      }),
    });

    if (!createRes.ok) {
      const errData = await createRes.json();
      console.error('Airtable create error:', errData);
      return res.status(500).json({ error: 'Could not save signup. Please try again.' });
    }

    res.json({ ok: true });
  } catch (err) {
    console.error('Zoom signup error:', err);
    res.status(500).json({ error: 'Could not save signup. Please try again.' });
  }
});

// --- Affiliate Program ---

// Generate a unique ref code from name
function generateRefCode(name) {
  const prefix = name.toLowerCase().replace(/[^a-z]/g, '').slice(0, 5) || 'ref';
  const suffix = Math.random().toString(36).slice(2, 6);
  return `${prefix}${suffix}`;
}

// Helper: find affiliate by field
async function findAffiliate(field, value) {
  if (!AIRTABLE_TOKEN) return null;
  const formula = encodeURIComponent(`LOWER({${field}})="${value.toLowerCase()}"`);
  const url = `${AFFILIATES_URL}?filterByFormula=${formula}&maxRecords=1`;
  const res = await fetch(url, { headers: { Authorization: `Bearer ${AIRTABLE_TOKEN}` } });
  const data = await res.json();
  return data.records && data.records.length > 0 ? data.records[0] : null;
}

// Flush click buffer to Airtable
async function flushClicks() {
  if (!AIRTABLE_TOKEN || clickBuffer.size === 0) return;
  for (const [refCode, count] of clickBuffer) {
    try {
      const affiliate = await findAffiliate('RefCode', refCode);
      if (affiliate) {
        const currentClicks = affiliate.fields.Clicks || 0;
        await fetch(`${AFFILIATES_URL}/${affiliate.id}`, {
          method: 'PATCH',
          headers: {
            Authorization: `Bearer ${AIRTABLE_TOKEN}`,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({ fields: { Clicks: currentClicks + count } }),
        });
      }
    } catch (err) {
      console.error(`Failed to flush clicks for ${refCode}:`, err.message);
    }
  }
  clickBuffer.clear();
}

// Flush clicks every 5 minutes
setInterval(flushClicks, 5 * 60 * 1000);

// POST /api/affiliate/signup — register new affiliate
app.post('/api/affiliate/signup', requireOrigin, async (req, res) => {
  const { name, email, paypal } = req.body;
  if (!name || !email || !paypal) {
    return res.status(400).json({ error: 'Please fill out all fields.' });
  }
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(paypal)) {
    return res.status(400).json({ error: 'Please enter valid email addresses.' });
  }
  if (!AIRTABLE_TOKEN) {
    return res.status(500).json({ error: 'Affiliate system not configured.' });
  }

  try {
    // Check for existing affiliate
    const existing = await findAffiliate('Email', email);
    if (existing) {
      return res.status(400).json({ error: 'This email is already registered as an affiliate. Use the login to access your dashboard.' });
    }

    // Generate unique ref code
    let refCode = generateRefCode(name);
    // Ensure uniqueness
    let existingRef = await findAffiliate('RefCode', refCode);
    let attempts = 0;
    while (existingRef && attempts < 5) {
      refCode = generateRefCode(name);
      existingRef = await findAffiliate('RefCode', refCode);
      attempts++;
    }

    // Create affiliate in Airtable
    const createRes = await fetch(AFFILIATES_URL, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${AIRTABLE_TOKEN}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        records: [{
          fields: {
            Name: name.trim(),
            Email: email.toLowerCase().trim(),
            RefCode: refCode,
            PayPalEmail: paypal.trim(),
            Clicks: 0,
            Conversions: 0,
          }
        }]
      }),
    });

    if (!createRes.ok) {
      const errData = await createRes.json();
      console.error('Airtable create affiliate error:', errData);
      return res.status(500).json({ error: 'Could not create affiliate account. Please try again.' });
    }

    const baseUrl = process.env.BASE_URL || 'https://freeaisitebuilder.com';
    const refLink = `${baseUrl}?ref=${refCode}`;

    // Send magic link email so they can access dashboard
    const token = crypto.randomBytes(32).toString('hex');
    magicTokens.set(token, {
      email: email.toLowerCase(),
      redirectTo: '/affiliate-dashboard.html',
      expiresAt: Date.now() + 24 * 60 * 60 * 1000, // 24 hours for signup
    });

    const magicLink = `${baseUrl}/api/auth/verify?token=${token}`;
    const resendKey = process.env.RESEND_API_KEY;
    if (resendKey) {
      try {
        const { Resend } = await import('resend');
        const resend = new Resend(resendKey);
        await resend.emails.send({
          from: process.env.EMAIL_FROM || 'Free AI Site Builder <noreply@freeaisitebuilder.com>',
          to: email.toLowerCase(),
          subject: 'Welcome to the Affiliate Program — Free AI Site Builder',
          html: `
            <div style="font-family:sans-serif;max-width:480px;margin:0 auto;padding:2rem;">
              <h2 style="color:#1a1a1a;">Welcome, ${name}!</h2>
              <p style="color:#666;line-height:1.6;">You're now part of the Free AI Site Builder affiliate program. Here's your unique referral link:</p>
              <div style="background:#f5f5f5;border:1px solid #e0e0e0;border-radius:8px;padding:1rem;margin:1rem 0;font-family:monospace;font-size:0.95rem;word-break:break-all;">${refLink}</div>
              <p style="color:#666;line-height:1.6;">Share this link with your audience. You earn <strong>$10 for every person</strong> who uses it to build their site and set up hosting.</p>
              <a href="${magicLink}" style="display:inline-block;background:#C8A46E;color:#0A0A0A;padding:12px 32px;border-radius:6px;text-decoration:none;font-weight:700;margin:1rem 0;">View Your Dashboard</a>
              <hr style="border:none;border-top:1px solid #eee;margin:1.5rem 0;">
              <p style="color:#bbb;font-size:0.75rem;">freeaisitebuilder.com</p>
            </div>
          `,
        });
      } catch (emailErr) {
        console.error('Affiliate welcome email error:', emailErr.message);
      }
    }

    res.json({ ok: true, refCode, refLink });
  } catch (err) {
    console.error('Affiliate signup error:', err);
    res.status(500).json({ error: 'Could not create affiliate account. Please try again.' });
  }
});

// POST /api/affiliate/login — send magic link to affiliate
app.post('/api/affiliate/login', requireOrigin, authLimiter, async (req, res) => {
  const { email } = req.body;
  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({ error: 'Please enter a valid email address.' });
  }
  if (!AIRTABLE_TOKEN) {
    return res.status(500).json({ error: 'Affiliate system not configured.' });
  }

  try {
    const affiliate = await findAffiliate('Email', email);
    if (!affiliate) {
      return res.status(400).json({ error: 'No affiliate account found with this email. Sign up first.' });
    }

    const token = crypto.randomBytes(32).toString('hex');
    magicTokens.set(token, {
      email: email.toLowerCase(),
      redirectTo: '/affiliate-dashboard.html',
      expiresAt: Date.now() + 15 * 60 * 1000,
    });

    const baseUrl = process.env.BASE_URL || `${req.protocol}://${req.get('host')}`;
    const magicLink = `${baseUrl}/api/auth/verify?token=${token}`;

    const resendKey = process.env.RESEND_API_KEY;
    if (!resendKey) {
      console.error('RESEND_API_KEY not set — affiliate magic link:', magicLink);
      return res.json({ ok: true });
    }

    const { Resend } = await import('resend');
    const resend = new Resend(resendKey);
    await resend.emails.send({
      from: process.env.EMAIL_FROM || 'Free AI Site Builder <noreply@freeaisitebuilder.com>',
      to: email.toLowerCase(),
      subject: 'Your Dashboard Login — Free AI Site Builder',
      html: `
        <div style="font-family:sans-serif;max-width:480px;margin:0 auto;padding:2rem;">
          <h2 style="color:#1a1a1a;">Log in to your affiliate dashboard</h2>
          <p style="color:#666;line-height:1.6;">Click below to view your referral stats. This link expires in 15 minutes.</p>
          <a href="${magicLink}" style="display:inline-block;background:#C8A46E;color:#0A0A0A;padding:12px 32px;border-radius:6px;text-decoration:none;font-weight:700;margin:1rem 0;">View Dashboard</a>
          <hr style="border:none;border-top:1px solid #eee;margin:1.5rem 0;">
          <p style="color:#bbb;font-size:0.75rem;">freeaisitebuilder.com</p>
        </div>
      `,
    });

    res.json({ ok: true });
  } catch (err) {
    console.error('Affiliate login error:', err);
    res.status(500).json({ error: 'Could not send login email. Please try again.' });
  }
});

// GET /api/affiliate/stats — get affiliate's dashboard data
app.get('/api/affiliate/stats', requireAuth, async (req, res) => {
  if (!AIRTABLE_TOKEN) {
    return res.status(500).json({ error: 'Affiliate system not configured.' });
  }

  try {
    const affiliate = await findAffiliate('Email', req.userEmail);
    if (!affiliate) {
      return res.json({ ok: false, error: 'Not an affiliate.' });
    }

    const f = affiliate.fields;
    const baseUrl = process.env.BASE_URL || 'https://freeaisitebuilder.com';

    // Include any buffered clicks
    const bufferedClicks = clickBuffer.get(f.RefCode) || 0;

    // Fetch conversions for this affiliate
    const convFormula = encodeURIComponent(`{RefCode}="${f.RefCode}"`);
    const convRes = await fetch(`${CONVERSIONS_URL}?filterByFormula=${convFormula}&sort%5B0%5D%5Bfield%5D=Date&sort%5B0%5D%5Bdirection%5D=desc&maxRecords=50`, {
      headers: { Authorization: `Bearer ${AIRTABLE_TOKEN}` },
    });
    const convData = await convRes.json();

    const conversionList = (convData.records || []).map(r => ({
      domain: r.fields.Domain || '',
      date: r.fields.Date || '',
      paidOut: r.fields.PaidOut || false,
      status: r.fields.Status || 'Pending',
    }));

    res.json({
      ok: true,
      name: f.Name,
      refCode: f.RefCode,
      refLink: `${baseUrl}?ref=${f.RefCode}`,
      clicks: (f.Clicks || 0) + bufferedClicks,
      conversions: f.Conversions || 0,
      conversionList,
    });
  } catch (err) {
    console.error('Affiliate stats error:', err);
    res.status(500).json({ error: 'Could not load stats.' });
  }
});

// POST /api/affiliate/track-click — record a click
app.post('/api/affiliate/track-click', requireOrigin, async (req, res) => {
  const { ref } = req.body;
  if (!ref) return res.json({ ok: false });

  // Buffer clicks in memory, flush to Airtable periodically
  clickBuffer.set(ref, (clickBuffer.get(ref) || 0) + 1);
  res.json({ ok: true });
});

// --- Hosting Reimbursement ---

// GET /api/reimbursement/spots — check remaining spots and if user already applied
app.get('/api/reimbursement/spots', async (req, res) => {
  if (!AIRTABLE_TOKEN) return res.json({ remaining: 0, userApplied: false });

  try {
    // Count total reimbursement records
    const countRes = await fetch(`${REIMBURSEMENTS_URL}?maxRecords=100&fields%5B%5D=Email`, {
      headers: { Authorization: `Bearer ${AIRTABLE_TOKEN}` },
    });
    const countData = await countRes.json();
    const total = (countData.records || []).length;
    const remaining = Math.max(0, REIMBURSE_CAP - total);

    // Check if current user already applied
    let userApplied = false;
    const email = getAuthEmail(req);
    if (email) {
      userApplied = (countData.records || []).some(r =>
        r.fields.Email && r.fields.Email.toLowerCase() === email.toLowerCase()
      );
    }

    res.json({ remaining, total, userApplied });
  } catch (err) {
    console.error('Reimbursement spots error:', err.message);
    res.json({ remaining: 0, userApplied: false });
  }
});

// POST /api/reimbursement/apply — apply for hosting reimbursement
app.post('/api/reimbursement/apply', requireOrigin, async (req, res) => {
  const { paypalEmail } = req.body;
  const email = getAuthEmail(req);

  if (!paypalEmail || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(paypalEmail)) {
    return res.status(400).json({ error: 'Please enter a valid PayPal email.' });
  }
  if (!AIRTABLE_TOKEN) {
    return res.status(500).json({ error: 'Reimbursement system not configured.' });
  }

  try {
    // Check remaining spots
    const countRes = await fetch(`${REIMBURSEMENTS_URL}?maxRecords=100&fields%5B%5D=Email`, {
      headers: { Authorization: `Bearer ${AIRTABLE_TOKEN}` },
    });
    const countData = await countRes.json();
    const total = (countData.records || []).length;

    if (total >= REIMBURSE_CAP) {
      return res.status(400).json({ error: 'Sorry, all reimbursement spots have been claimed.' });
    }

    // Check if user already applied
    if (email) {
      const alreadyApplied = (countData.records || []).some(r =>
        r.fields.Email && r.fields.Email.toLowerCase() === email.toLowerCase()
      );
      if (alreadyApplied) {
        return res.status(400).json({ error: 'You\'ve already applied for reimbursement.' });
      }
    }

    // Create reimbursement record
    const createRes = await fetch(REIMBURSEMENTS_URL, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${AIRTABLE_TOKEN}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        records: [{
          fields: {
            Email: (email || paypalEmail).toLowerCase().trim(),
            PayPalEmail: paypalEmail.toLowerCase().trim(),
            Amount: 47.88,
            Date: new Date().toISOString().split('T')[0],
            Status: 'Pending',
            PaidOut: false,
          }
        }]
      }),
    });

    if (!createRes.ok) {
      const errData = await createRes.json();
      console.error('Airtable reimbursement error:', errData);
      return res.status(500).json({ error: 'Could not submit application. Please try again.' });
    }

    console.log(`[Reimbursement] Application from ${email || paypalEmail}`);

    // Also sign them up for the Zoom walkthrough
    const userEmail = (email || paypalEmail).toLowerCase().trim();
    try {
      const zoomSearchUrl = `${AIRTABLE_URL}?filterByFormula=${encodeURIComponent(`LOWER({Email})="${userEmail}"`)}&maxRecords=1`;
      const zoomSearchRes = await fetch(zoomSearchUrl, {
        headers: { Authorization: `Bearer ${AIRTABLE_TOKEN}` },
      });
      const zoomSearchData = await zoomSearchRes.json();
      if (!zoomSearchData.records || zoomSearchData.records.length === 0) {
        await fetch(AIRTABLE_URL, {
          method: 'POST',
          headers: {
            Authorization: `Bearer ${AIRTABLE_TOKEN}`,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            records: [{
              fields: {
                Name: userEmail.split('@')[0],
                Email: userEmail,
              }
            }]
          }),
        });
        console.log(`[Zoom] Auto-signed up reimbursement user: ${userEmail}`);
      }
    } catch (zoomErr) {
      console.error('Zoom auto-signup error:', zoomErr.message);
    }

    res.json({ ok: true });
  } catch (err) {
    console.error('Reimbursement apply error:', err.message);
    res.status(500).json({ error: 'Could not submit application. Please try again.' });
  }
});

// --- Admin: Payout Scan ---
const ADMIN_SECRET = process.env.ADMIN_SECRET || '';

// GET /api/admin/payout-scan — scan eligible conversions, check DNS, return report
app.get('/api/admin/payout-scan', async (req, res) => {
  // Auth: require admin secret
  const secret = req.query.secret || req.headers['x-admin-secret'];
  if (!ADMIN_SECRET || secret !== ADMIN_SECRET) {
    return res.status(403).json({ error: 'Unauthorized.' });
  }
  if (!AIRTABLE_TOKEN) {
    return res.status(500).json({ error: 'Airtable not configured.' });
  }

  try {
    // Calculate cutoff: conversions older than 1 month + 20 days ago
    const now = new Date();
    const cutoff = new Date(now);
    cutoff.setMonth(cutoff.getMonth() - 1);
    cutoff.setDate(cutoff.getDate() - 20);
    const cutoffStr = cutoff.toISOString().split('T')[0];

    // Fetch all pending conversions (Status is empty or "Pending") with Date <= cutoff
    const formula = encodeURIComponent(`AND(OR({Status}="Pending",{Status}=""),IS_BEFORE({Date},"${cutoffStr}"))`);
    const convRes = await fetch(`${CONVERSIONS_URL}?filterByFormula=${formula}&maxRecords=100`, {
      headers: { Authorization: `Bearer ${AIRTABLE_TOKEN}` },
    });
    const convData = await convRes.json();
    const records = convData.records || [];

    if (records.length === 0) {
      return res.json({ message: 'No eligible conversions to scan.', results: [] });
    }

    const results = [];

    for (const record of records) {
      const domain = record.fields.Domain || '';
      const refCode = record.fields.RefCode || '';
      const date = record.fields.Date || '';
      let dnsActive = false;

      if (domain) {
        // Clean domain for DNS check
        const cleaned = domain.replace(/^https?:\/\//, '').replace(/\/.*$/, '').toLowerCase().trim();
        try {
          const nsRecords = await dns.resolveNs(cleaned);
          dnsActive = nsRecords.some(ns =>
            BLUEHOST_NS_PATTERNS.some(pattern => ns.toLowerCase().includes(pattern))
          );
        } catch (nsErr) {
          // NS failed, try A record
          try {
            const aRecords = await dns.resolve4(cleaned);
            dnsActive = aRecords.length > 0;
          } catch (aErr) {
            dnsActive = false;
          }
        }
      }

      const newStatus = dnsActive ? 'Approved' : 'Cancelled';
      results.push({ id: record.id, domain, refCode, date, dnsActive, status: newStatus });
    }

    res.json({
      message: `Scanned ${results.length} conversions.`,
      approved: results.filter(r => r.status === 'Approved').length,
      cancelled: results.filter(r => r.status === 'Cancelled').length,
      results,
    });
  } catch (err) {
    console.error('Payout scan error:', err);
    res.status(500).json({ error: 'Scan failed.' });
  }
});

// POST /api/admin/payout-approve — apply scan results (update Status in Airtable)
app.post('/api/admin/payout-approve', async (req, res) => {
  const secret = req.query.secret || req.headers['x-admin-secret'];
  if (!ADMIN_SECRET || secret !== ADMIN_SECRET) {
    return res.status(403).json({ error: 'Unauthorized.' });
  }
  if (!AIRTABLE_TOKEN) {
    return res.status(500).json({ error: 'Airtable not configured.' });
  }

  const { results } = req.body;
  if (!results || !Array.isArray(results)) {
    return res.status(400).json({ error: 'Provide results array from payout-scan.' });
  }

  try {
    let updated = 0;
    // Airtable batch update: max 10 records per request
    for (let i = 0; i < results.length; i += 10) {
      const batch = results.slice(i, i + 10);
      const records = batch.map(r => ({
        id: r.id,
        fields: { Status: r.status },
      }));

      const patchRes = await fetch(CONVERSIONS_URL, {
        method: 'PATCH',
        headers: {
          Authorization: `Bearer ${AIRTABLE_TOKEN}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ records }),
      });

      if (patchRes.ok) {
        updated += batch.length;
      } else {
        const errData = await patchRes.json();
        console.error('Airtable batch update error:', errData);
      }
    }

    res.json({ message: `Updated ${updated} conversions.` });
  } catch (err) {
    console.error('Payout approve error:', err);
    res.status(500).json({ error: 'Update failed.' });
  }
});

// --- System prompt ---
const SYSTEM_PROMPT = `You are an expert AI website builder embedded on freeaisitebuilder.com. Your job is to build a professional, beautiful website based on the user's project details.

## Your personality
- Friendly, encouraging, and patient
- You speak plainly — no jargon unless necessary
- You keep responses concise but thorough

## Context
The user has already completed Steps 1-2 (design/content collection and hosting setup) via a wizard. Their first message will contain their project details: site type, business name, description, domain, style preferences, and available images.

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

  const effectiveCap = TOKEN_CAP + (session.bonusTokens || 0);
  if (session.inputTokens >= effectiveCap || session.outputTokens >= effectiveCap) {
    return res.json({
      error: 'You\'ve hit your token limit for this session.',
      inputTokens: session.inputTokens,
      outputTokens: session.outputTokens,
      tokenCap: effectiveCap,
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
      max_tokens: Math.min(8192, effectiveCap - session.outputTokens),
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
      tokenCap: effectiveCap,
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

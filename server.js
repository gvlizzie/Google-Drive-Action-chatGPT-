// File: server.js
// Node 18+. Minimal Drive export action server.
import 'dotenv/config';
import express from 'express';
import crypto from 'crypto';
import jwt from 'jsonwebtoken';
import bodyParser from 'body-parser';
import querystring from 'querystring';
import { google } from 'googleapis';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const {
  PORT = 10000,
  APP_BASE_URL,
  GOOGLE_CLIENT_ID,
  GOOGLE_CLIENT_SECRET,
  GOOGLE_OAUTH_SCOPES = 'https://www.googleapis.com/auth/drive.readonly',
  JWT_ISSUER = 'drive-action',
  JWT_AUDIENCE = 'drive-action-client',
  JWT_SIGNING_KEY,
  JWT_TTL_SECONDS = '3600',
  GRANT_TTL_SECONDS = '300',
  DOWNLOAD_TTL_SECONDS = '600',
} = process.env;

const required = [APP_BASE_URL, GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, JWT_SIGNING_KEY];
if (required.some((v) => !v)) {
  console.error('Missing required env vars. Set them in Render later. For local dev, use .env.');
  // Don’t exit in Render first boot; allow blueprint to provision.
}

const app = express();
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

import path from 'path';
import { fileURLToPath } from 'url';
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// serve /privacy and /terms from /public
app.use(express.static(path.join(__dirname, 'public')));


// Demo-grade in-memory stores. Swap for Redis in prod.
const grants = new Map();    // grant -> { sub, exp }
const users = new Map();     // sub -> { googleTokens }
const downloads = new Map(); // id -> { filePath, mimeType, filename, exp, used }

const now = () => Math.floor(Date.now() / 1000);
const rid = (n = 16) => crypto.randomBytes(n).toString('hex');

const makeOAuthClient = (redirectUri) =>
  new google.auth.OAuth2(GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, redirectUri);

async function exchangeGoogleCode(code, redirectUri) {
  const oauth2Client = makeOAuthClient(redirectUri);
  const { tokens } = await oauth2Client.getToken(code);
  oauth2Client.setCredentials(tokens);
  const oauth2 = google.oauth2({ auth: oauth2Client, version: 'v2' });
  const { data: profile } = await oauth2.userinfo.get();
  return { tokens, profile };
}

function signAccessToken(sub) {
  return jwt.sign({ sub, scope: 'drive.readonly' }, JWT_SIGNING_KEY, {
    issuer: JWT_ISSUER,
    audience: JWT_AUDIENCE,
    expiresIn: Number(JWT_TTL_SECONDS),
  });
}
function verifyAccessToken(token) {
  return jwt.verify(token, JWT_SIGNING_KEY, { issuer: JWT_ISSUER, audience: JWT_AUDIENCE });
}
function authRequired(req, res, next) {
  try {
    const token = (req.headers.authorization || '').replace(/^Bearer /, '');
    if (!token) return res.status(401).json({ error: 'missing_token' });
    const payload = verifyAccessToken(token);
    req.user = { sub: payload.sub };
    next();
  } catch {
    return res.status(401).json({ error: 'invalid_token' });
  }
}

// === OAuth: GPT -> our /oauth/authorize -> Google -> /oauth/callback -> back to GPT with grant ===
app.get('/oauth/authorize', (req, res) => {
  const { client_id, redirect_uri, state } = req.query;
  if (!client_id || !redirect_uri || !state) return res.status(400).send('Missing query params');
  const googleRedirectUri = `${APP_BASE_URL}/oauth/callback`;
  const oc = makeOAuthClient(googleRedirectUri);
  const url = oc.generateAuthUrl({
    access_type: 'offline',
    prompt: 'consent',
    scope: GOOGLE_OAUTH_SCOPES.split(' '),
    state: Buffer.from(JSON.stringify({ gptRedirect: redirect_uri, gptState: state })).toString('base64'),
  });
  res.redirect(url);
});

app.get('/oauth/callback', async (req, res) => {
  try {
    const { code, state } = req.query;
    if (!code || !state) return res.status(400).send('Missing code/state');
    const { gptRedirect, gptState } = JSON.parse(Buffer.from(String(state), 'base64').toString('utf8'));
    const { tokens, profile } = await exchangeGoogleCode(String(code), `${APP_BASE_URL}/oauth/callback`);
    if (!tokens.refresh_token) {
      return res
        .status(400)
        .send('Google returned no refresh_token. Revoke prior consent at myaccount.google.com/permissions and try again.');
    }
    const sub = `google:${profile.id}`;
    users.set(sub, { googleTokens: tokens });
    const grant = rid(12);
    grants.set(grant, { sub, exp: now() + Number(GRANT_TTL_SECONDS) });
    const loc = `${gptRedirect}?code=${grant}&state=${encodeURIComponent(gptState)}`;
    res.redirect(loc);
  } catch (e) {
    console.error(e);
    res.status(500).send('OAuth error');
  }
});

app.post('/oauth/token', (req, res) => {
  const { grant_type } = req.body || {};
  if (grant_type === 'authorization_code') {
    const grant = grants.get(req.body.code);
    if (!grant || grant.exp < now()) {
      grants.delete(req.body.code);
      return res.status(400).json({ error: 'invalid_or_expired_grant' });
    }
    const access_token = signAccessToken(grant.sub);
    const refresh_token = Buffer.from(JSON.stringify({ sub: grant.sub })).toString('base64');
    grants.delete(req.body.code);
    return res.json({
      access_token,
      token_type: 'Bearer',
      expires_in: Number(JWT_TTL_SECONDS),
      refresh_token,
    });
  }
  if (grant_type === 'refresh_token') {
    try {
      const { sub } = JSON.parse(Buffer.from(String(req.body.refresh_token), 'base64').toString('utf8'));
      if (!users.has(sub)) return res.status(400).json({ error: 'invalid_refresh' });
      const access_token = signAccessToken(sub);
      return res.json({ access_token, token_type: 'Bearer', expires_in: Number(JWT_TTL_SECONDS) });
    } catch {
      return res.status(400).json({ error: 'invalid_refresh' });
    }
  }
  res.status(400).json({ error: 'unsupported_grant_type' });
});

// Google Drive client per user
function driveForSub(sub) {
  const rec = users.get(sub);
  if (!rec) throw new Error('user_not_connected');
  const oc = makeOAuthClient(`${APP_BASE_URL}/oauth/callback`);
  oc.setCredentials(rec.googleTokens);
  return google.drive({ version: 'v3', auth: oc });
}

app.get('/drive/files', authRequired, async (req, res) => {
  try {
    const d = driveForSub(req.user.sub);
    const q = req.query.q ? String(req.query.q) : '';
    const pageSize = Math.min(Number(req.query.pageSize || 25), 100);
    const { data } = await d.files.list({
      q,
      pageSize,
      fields: 'files(id,name,mimeType,modifiedTime,owners/emailAddress)',
      spaces: 'drive',
    });
    res.json(data);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'list_failed' });
  }
});

app.post('/drive/export', authRequired, async (req, res) => {
  try {
    const { fileId, exportMimeType } = req.body || {};
    if (!fileId || !exportMimeType) return res.status(400).json({ error: 'missing_params' });
    const d = driveForSub(req.user.sub);
    const { data: meta } = await d.files.get({ fileId, fields: 'id,name,mimeType' });
    const resp = await d.files.export({ fileId, mimeType: exportMimeType }, { responseType: 'arraybuffer' });
    const buf = Buffer.from(resp.data);
    const safeName = (meta.name || 'export').replace(/[^\w.-]+/g, '_');
    const ext = mimeToExt(exportMimeType);
    const filename = ext ? `${safeName}.${ext}` : safeName;
    const tmpDir = path.join(__dirname, 'tmp');
    fs.mkdirSync(tmpDir, { recursive: true });
    const filePath = path.join(tmpDir, `${rid(6)}_${filename}`);
    fs.writeFileSync(filePath, buf);
    const id = rid(12);
    downloads.set(id, {
      filePath,
      mimeType: exportMimeType,
      filename,
      exp: now() + Number(DOWNLOAD_TTL_SECONDS),
      used: false,
    });
    return res.json({
      fileName: filename,
      downloadUrl: `${APP_BASE_URL}/download/${id}`,
      expiresInSeconds: Number(DOWNLOAD_TTL_SECONDS),
    });
  } catch (e) {
    console.error(e);
    const msg = String(e?.message || e);
    if (msg.includes('file not found')) return res.status(404).json({ error: 'file_not_found' });
    return res.status(500).json({ error: 'export_failed' });
  }
});

function mimeToExt(m) {
  const map = {
    'application/pdf': 'pdf',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document': 'docx',
    'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet': 'xlsx',
    'application/vnd.openxmlformats-officedocument.presentationml.presentation': 'pptx',
    'text/plain': 'txt',
    'application/rtf': 'rtf',
    'application/vnd.oasis.opendocument.text': 'odt',
    'application/vnd.oasis.opendocument.spreadsheet': 'ods',
    'application/vnd.oasis.opendocument.presentation': 'odp',
  };
  return map[m] || '';
}

app.get('/download/:id', (req, res) => {
  const rec = downloads.get(req.params.id);
  if (!rec) return res.status(410).send('Expired');
  if (rec.used || rec.exp < now()) {
    downloads.delete(req.params.id);
    try { fs.unlinkSync(rec.filePath); } catch {}
    return res.status(410).send('Expired');
  }
  rec.used = true;
  res.setHeader('Content-Type', rec.mimeType);
  res.setHeader('Content-Disposition', `attachment; filename="${rec.filename}"`);
  fs.createReadStream(rec.filePath)
    .on('close', () => {
      downloads.delete(req.params.id);
      try { fs.unlinkSync(rec.filePath); } catch {}
    })
    .pipe(res);
});

app.get('/.well-known/openapi.yaml', (req, res) => {
  res.type('application/yaml').send(fs.readFileSync(path.join(__dirname, 'openapi.yaml'), 'utf8'));
});

app.get('/healthz', (_, res) => res.json({ ok: true }));

app.listen(Number(PORT), () => {
  console.log(`Listening on :${PORT}`);
});

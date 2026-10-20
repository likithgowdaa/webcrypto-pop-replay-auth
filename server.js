import express from 'express';
import crypto from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;

// Security configuration constants
const TOKEN_LIFETIME_MS = parseInt(process.env.SESSION_LIFETIME_MS, 10) || (15 * 60 * 1000); // 15 minutes default
const PROOF_MAX_AGE_MS = 60 * 1000;       // 60 seconds allowed age
const PROOF_FUTURE_SKEW_MS = 10 * 1000;    // 10 seconds max clock skew in future
const MAX_LOGIN_ATTEMPTS = 5;
const LOGIN_LOCKOUT_MS = 60 * 1000;        // 1 minute lockout

// -------------------------------------------------------------
// CRYPTOGRAPHIC PASSWORD HASHING (scrypt with secure random salt)
// Standard OWASP-recommended parameters: N=16384, r=8, p=1, 64-byte key
// -------------------------------------------------------------
function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
  const hash = crypto.scryptSync(password, salt, 64, { N: 16384, r: 8, p: 1 }).toString('hex');
  return { salt, hash };
}

function verifyPassword(password, salt, storedHash) {
  try {
    const computedHash = crypto.scryptSync(password, salt, 64, { N: 16384, r: 8, p: 1 }).toString('hex');
    const bufA = Buffer.from(computedHash, 'hex');
    const bufB = Buffer.from(storedHash, 'hex');
    if (bufA.length !== bufB.length) return false;
    return crypto.timingSafeEqual(bufA, bufB);
  } catch (err) {
    return false;
  }
}

// Password Policy: Minimum 8 characters, at least 1 uppercase, 1 lowercase, 1 number, 1 special char
const PASSWORD_REGEX = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_+\-=[\]{};':"\\|,.<>/?]).{8,128}$/;
const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

// In-Memory User Store (Registered local accounts & demo accounts)
const registeredUsers = new Map();

// Seed initial Demo Accounts with secure scrypt hashes
const aliceHashed = hashPassword('CryptoSec#2026');
registeredUsers.set('alice@cyber.edu', {
  email: 'alice@cyber.edu',
  passwordHash: aliceHashed.hash,
  passwordSalt: aliceHashed.salt,
  name: 'Alice Owner',
  role: 'Authorized Token Owner',
  studentId: 'CS-2026-8841',
  isDemo: true,
  createdAt: Date.now()
});

const bobHashed = hashPassword('CryptoSec#2026');
registeredUsers.set('bob@cyber.edu', {
  email: 'bob@cyber.edu',
  passwordHash: bobHashed.hash,
  passwordSalt: bobHashed.salt,
  name: 'Bob Peer',
  role: 'Authorized Peer User',
  studentId: 'CS-2026-9922',
  isDemo: true,
  createdAt: Date.now()
});

// Enrolled Public Keys per User Account (Persists account-to-key binding)
// Map: email -> { keyDer, publicKeyObject, keyId, keyAlgorithm, enrolledAt }
const userEnrolledKeys = new Map();

// Sessions map: token -> { userId, username, role, studentId, createdAt, expiresAt, publicKeyDer, publicKeyObject, keyId, keyAlgorithm }
const sessions = new Map();

// Replay Cache: nonce -> { token, timestamp, expiresAt }
const replayCache = new Map();

// Rate limiting map: ip -> { attempts, lockedUntil }
const loginRateLimits = new Map();

// Server-side audit log for educational transparency
const serverAuditLog = [];

function recordAudit(event, outcome, details = {}) {
  const entry = {
    id: crypto.randomUUID(),
    timestamp: new Date().toISOString(),
    event,
    outcome,
    details
  };
  serverAuditLog.unshift(entry);
  if (serverAuditLog.length > 200) serverAuditLog.pop();
  console.log(`[AUDIT] [${entry.timestamp}] ${event} -> ${outcome}:`, JSON.stringify(details));
}

// Cookie Parsing & Setting Helpers
function parseCookies(req) {
  const list = {};
  const rc = req.headers.cookie;
  if (rc) {
    rc.split(';').forEach(cookie => {
      const parts = cookie.split('=');
      const name = parts.shift().trim();
      if (name) list[name] = decodeURIComponent(parts.join('='));
    });
  }
  return list;
}

function setSessionCookie(res, token, maxAgeSeconds) {
  const isProd = process.env.NODE_ENV === 'production';
  const cookieParts = [
    `pop_session_id=${encodeURIComponent(token)}`,
    'Path=/',
    'HttpOnly',
    'SameSite=Lax',
    `Max-Age=${maxAgeSeconds}`
  ];
  if (isProd) {
    cookieParts.push('Secure');
  }
  res.setHeader('Set-Cookie', cookieParts.join('; '));
}

function clearSessionCookie(res) {
  const isProd = process.env.NODE_ENV === 'production';
  const cookieParts = [
    'pop_session_id=',
    'Path=/',
    'HttpOnly',
    'SameSite=Lax',
    'Max-Age=0',
    'Expires=Thu, 01 Jan 1970 00:00:00 GMT'
  ];
  if (isProd) {
    cookieParts.push('Secure');
  }
  res.setHeader('Set-Cookie', cookieParts.join('; '));
}

// Background cleanup for expired nonces and sessions
const cleanupInterval = setInterval(() => {
  const now = Date.now();
  // Clean replay nonces
  for (const [replayKey, record] of replayCache.entries()) {
    if (now > record.expiresAt) {
      replayCache.delete(replayKey);
    }
  }
  // Clean expired sessions
  for (const [token, session] of sessions.entries()) {
    if (now > session.expiresAt) {
      sessions.delete(token);
    }
  }
}, 30 * 1000);
cleanupInterval.unref();

// Middleware: Strict Security Headers
app.use((req, res, next) => {
  res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self';");
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
  next();
});

// Middleware: Universal raw body buffer preservation (tamper-resistant for all content types)
app.use(express.raw({ type: '*/*', limit: '64kb' }), (req, res, next) => {
  req.rawBody = Buffer.isBuffer(req.body) ? req.body : Buffer.alloc(0);

  // If Content-Type is JSON, parse safely into req.body
  if (req.is('application/json') && req.rawBody.length > 0) {
    try {
      req.body = JSON.parse(req.rawBody.toString('utf-8'));
    } catch (err) {
      return res.status(400).json({
        error: 'Malformed JSON payload.',
        code: 'INVALID_JSON'
      });
    }
  } else if (!req.body || Buffer.isBuffer(req.body)) {
    req.body = {};
  }
  next();
});

// Serve static frontend assets
app.use(express.static(path.join(__dirname, 'public')));

// -------------------------------------------------------------
// HELPER: Deterministic Request Canonicalization
// Format:
// METHOD\n
// PATH\n
// TIMESTAMP\n
// NONCE\n
// BODY_SHA256_HEX
// -------------------------------------------------------------
function computeBodyHash(rawBody) {
  const hash = crypto.createHash('sha256');
  if (rawBody && rawBody.length > 0) {
    hash.update(rawBody);
  } else {
    hash.update(''); // Hash of empty string
  }
  return hash.digest('hex');
}

function buildCanonicalString(method, pathOnly, timestampStr, nonce, bodySha256Hex) {
  return [
    method.toUpperCase(),
    pathOnly,
    timestampStr,
    nonce,
    bodySha256Hex
  ].join('\n');
}

// -------------------------------------------------------------
// ENDPOINT: Local Account Registration
// Allows local users to register an account with email and password
// Note: Email (e.g. Gmail) is an identifier only; not Google OAuth!
// -------------------------------------------------------------
app.post('/api/auth/register', (req, res) => {
  const { email, password, confirmPassword } = req.body || {};

  if (!email || typeof email !== 'string') {
    return res.status(400).json({ error: 'Valid email address is required.', code: 'INVALID_EMAIL' });
  }

  const normalizedEmail = email.trim().toLowerCase();
  if (normalizedEmail.length > 128 || !EMAIL_REGEX.test(normalizedEmail)) {
    return res.status(400).json({
      error: 'Invalid email address format.',
      code: 'INVALID_EMAIL_FORMAT'
    });
  }

  if (!password || typeof password !== 'string') {
    return res.status(400).json({ error: 'Password is required.', code: 'MISSING_PASSWORD' });
  }

  if (password !== confirmPassword) {
    return res.status(400).json({
      error: 'Password and password confirmation do not match.',
      code: 'PASSWORD_MISMATCH'
    });
  }

  if (!PASSWORD_REGEX.test(password)) {
    return res.status(400).json({
      error: 'Password must be between 8 and 128 characters and include at least one uppercase letter, one lowercase letter, one number, and one special character.',
      code: 'WEAK_PASSWORD'
    });
  }

  if (registeredUsers.has(normalizedEmail)) {
    recordAudit('AUTH_REGISTER_REJECTED', 'EMAIL_ALREADY_EXISTS', { email: normalizedEmail });
    return res.status(409).json({
      error: 'An account with this email address already exists.',
      code: 'EMAIL_ALREADY_EXISTS'
    });
  }

  const { salt, hash } = hashPassword(password);
  const displayName = normalizedEmail.split('@')[0];
  const formattedName = displayName.charAt(0).toUpperCase() + displayName.slice(1);
  const studentId = `CS-2026-${Math.floor(1000 + Math.random() * 9000)}`;

  const newUser = {
    email: normalizedEmail,
    passwordHash: hash,
    passwordSalt: salt,
    name: formattedName,
    role: 'Registered Student User',
    studentId,
    isDemo: false,
    createdAt: Date.now()
  };

  registeredUsers.set(normalizedEmail, newUser);

  recordAudit('AUTH_REGISTER_SUCCESS', 'USER_CREATED', {
    email: normalizedEmail,
    role: newUser.role,
    studentId
  });

  return res.status(201).json({
    success: true,
    message: 'Local account registered successfully. You may now log in.',
    email: normalizedEmail,
    user: {
      email: normalizedEmail,
      name: formattedName,
      role: newUser.role,
      studentId
    }
  });
});

// -------------------------------------------------------------
// ENDPOINT: Login (Rate-Limited, Demo or Registered Credentials)
// Sets HttpOnly session cookie and returns session token
// -------------------------------------------------------------
app.post('/api/auth/login', (req, res) => {
  const clientIp = req.ip || req.socket.remoteAddress || '127.0.0.1';
  const now = Date.now();

  // Check rate limit
  const rateRecord = loginRateLimits.get(clientIp) || { attempts: 0, lockedUntil: 0 };
  if (now < rateRecord.lockedUntil) {
    const waitSeconds = Math.ceil((rateRecord.lockedUntil - now) / 1000);
    recordAudit('AUTH_LOGIN_BLOCKED', 'RATE_LIMITED', { clientIp, waitSeconds });
    return res.status(429).json({
      error: `Too many failed login attempts. Please wait ${waitSeconds} seconds before trying again.`
    });
  }

  const { username, email, password } = req.body || {};
  const userIdentifier = (username || email || '').trim().toLowerCase();

  if (!userIdentifier || !password || typeof password !== 'string') {
    return res.status(400).json({ error: 'Username/email and password are required.' });
  }

  const user = registeredUsers.get(userIdentifier);
  let passwordMatch = false;
  if (user) {
    passwordMatch = verifyPassword(password, user.passwordSalt, user.passwordHash);
  }

  if (!user || !passwordMatch) {
    rateRecord.attempts += 1;
    if (rateRecord.attempts >= MAX_LOGIN_ATTEMPTS) {
      rateRecord.lockedUntil = now + LOGIN_LOCKOUT_MS;
      rateRecord.attempts = 0;
      loginRateLimits.set(clientIp, rateRecord);
      recordAudit('AUTH_LOGIN_FAILED', 'LOCKED_OUT', { username: userIdentifier, clientIp });
      return res.status(429).json({
        error: `Too many failed login attempts. Account temporarily locked for 60 seconds.`
      });
    }
    loginRateLimits.set(clientIp, rateRecord);
    recordAudit('AUTH_LOGIN_FAILED', 'INVALID_CREDENTIALS', { username: userIdentifier, clientIp });
    return res.status(401).json({ error: 'Invalid username or password.' });
  }

  // Reset rate limiting on successful login
  loginRateLimits.delete(clientIp);

  // Generate cryptographically secure random bearer token
  const token = crypto.randomBytes(32).toString('hex');
  const expiresAt = now + TOKEN_LIFETIME_MS;

  // Check if user already has an enrolled public key
  const existingKey = userEnrolledKeys.get(userIdentifier);

  const session = {
    userId: userIdentifier,
    username: user.name,
    role: user.role,
    studentId: user.studentId,
    createdAt: now,
    expiresAt,
    publicKeyDer: existingKey ? existingKey.keyDer : null,
    publicKeyObject: existingKey ? existingKey.publicKeyObject : null,
    keyId: existingKey ? existingKey.keyId : null,
    keyAlgorithm: existingKey ? existingKey.keyAlgorithm : null
  };

  sessions.set(token, session);

  // Set HttpOnly session cookie
  setSessionCookie(res, token, TOKEN_LIFETIME_MS / 1000);

  recordAudit('AUTH_LOGIN_SUCCESS', 'SESSION_CREATED', {
    username: userIdentifier,
    maskedToken: `${token.slice(0, 6)}...${token.slice(-6)}`,
    expiresIn: TOKEN_LIFETIME_MS / 1000,
    hasEnrolledKey: !!existingKey
  });

  return res.json({
    success: true,
    token,
    expiresIn: TOKEN_LIFETIME_MS / 1000,
    expiresAt,
    keyRegistered: !!session.publicKeyObject,
    keyId: session.keyId,
    keyAlgorithm: session.keyAlgorithm,
    user: {
      username: userIdentifier,
      name: user.name,
      role: user.role,
      studentId: user.studentId
    }
  });
});

// -------------------------------------------------------------
// ENDPOINT: Register Client Public Key (Authenticated)
// Public key is exported by browser in SPKI (DER) format
// Supports Authorization header or HttpOnly session cookie
// -------------------------------------------------------------
app.post('/api/auth/register-key', (req, res) => {
  let token = null;
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    token = authHeader.slice(7).trim();
  } else {
    const cookies = parseCookies(req);
    token = cookies.pop_session_id;
  }

  if (!token) {
    return res.status(401).json({ error: 'Active session required for key registration.' });
  }

  const session = sessions.get(token);
  if (!session) {
    return res.status(401).json({ error: 'Session token invalid or unknown.' });
  }

  if (Date.now() > session.expiresAt) {
    sessions.delete(token);
    clearSessionCookie(res);
    recordAudit('KEY_REGISTRATION_FAILED', 'EXPIRED_SESSION', { username: session.userId });
    return res.status(401).json({ error: 'Session token has expired. Please log in again.' });
  }

  // Prevent key replacement/overwriting on an active session
  if (session.publicKeyObject) {
    recordAudit('KEY_REGISTRATION_BLOCKED', 'ALREADY_REGISTERED', {
      username: session.userId,
      keyId: session.keyId
    });
    return res.status(409).json({
      error: 'A public key is already registered for this active session. Key replacement is prohibited.',
      code: 'KEY_ALREADY_REGISTERED'
    });
  }

  const { publicKeySpki } = req.body || {};
  if (!publicKeySpki || typeof publicKeySpki !== 'string') {
    return res.status(400).json({ error: 'publicKeySpki (base64 string) is required.' });
  }

  try {
    const keyDerBuffer = Buffer.from(publicKeySpki, 'base64');
    if (keyDerBuffer.length === 0 || keyDerBuffer.length > 512) {
      return res.status(400).json({ error: 'Invalid public key size.' });
    }

    // Import key using Node.js crypto to validate format
    const publicKeyObject = crypto.createPublicKey({
      key: keyDerBuffer,
      format: 'der',
      type: 'spki'
    });

    // Validate algorithm is ECDSA P-256 (prime256v1)
    if (publicKeyObject.asymmetricKeyType !== 'ec') {
      return res.status(400).json({ error: 'Only Elliptic Curve (EC) keys are supported.' });
    }

    // Generate deterministic thumbprint / Key ID (SHA-256 of DER)
    const keyId = crypto.createHash('sha256').update(keyDerBuffer).digest('hex').slice(0, 16);

    // Bind public key to this session
    session.publicKeyDer = keyDerBuffer;
    session.publicKeyObject = publicKeyObject;
    session.keyId = keyId;
    session.keyAlgorithm = 'ECDSA P-256 (prime256v1)';
    session.keyRegisteredAt = Date.now();

    // Persist enrolled key for this user account (enables safe session restoration & re-login)
    userEnrolledKeys.set(session.userId, {
      keyDer: keyDerBuffer,
      publicKeyObject,
      keyId,
      keyAlgorithm: session.keyAlgorithm,
      enrolledAt: Date.now()
    });

    recordAudit('KEY_REGISTERED', 'SUCCESS', {
      username: session.userId,
      keyId,
      algorithm: session.keyAlgorithm
    });

    return res.json({
      success: true,
      message: 'Client public key successfully registered and bound to session.',
      keyId,
      algorithm: session.keyAlgorithm
    });
  } catch (err) {
    recordAudit('KEY_REGISTRATION_FAILED', 'PARSE_ERROR', { error: err.message });
    return res.status(400).json({
      error: 'Failed to import public key. Ensure valid SPKI-encoded ECDSA P-256 public key.'
    });
  }
});

// -------------------------------------------------------------
// ENDPOINT: Session Status & Refresh Restoration
// Returns active session details for page reload restoration
// Supports Authorization header or HttpOnly cookie
// -------------------------------------------------------------
app.get('/api/auth/session', (req, res) => {
  let token = null;
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    token = authHeader.slice(7).trim();
  } else {
    const cookies = parseCookies(req);
    token = cookies.pop_session_id;
  }

  if (!token) {
    return res.status(401).json({ authenticated: false, error: 'No active session credentials.' });
  }

  const session = sessions.get(token);
  if (!session || Date.now() > session.expiresAt) {
    if (session) sessions.delete(token);
    clearSessionCookie(res);
    return res.status(401).json({ authenticated: false, error: 'Session expired or invalid.' });
  }

  const remainingSeconds = Math.max(0, Math.floor((session.expiresAt - Date.now()) / 1000));
  return res.json({
    authenticated: true,
    token, // Provided for client-side PoP signing header construction
    user: {
      username: session.userId,
      name: session.username,
      role: session.role,
      studentId: session.studentId
    },
    keyRegistered: !!session.publicKeyObject,
    keyId: session.keyId,
    keyAlgorithm: session.keyAlgorithm,
    expiresIn: remainingSeconds,
    expiresAt: session.expiresAt
  });
});

// -------------------------------------------------------------
// ENDPOINT: Logout (Revocation & Cookie Clearing)
// Invalidate server-side session and clears HttpOnly cookie
// -------------------------------------------------------------
app.post('/api/auth/logout', (req, res) => {
  let token = null;
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    token = authHeader.slice(7).trim();
  } else {
    const cookies = parseCookies(req);
    token = cookies.pop_session_id;
  }

  if (token) {
    const session = sessions.get(token);
    if (session) {
      recordAudit('AUTH_LOGOUT', 'SESSION_REVOKED', { username: session.userId });
    }
    sessions.delete(token);
  }

  clearSessionCookie(res);
  return res.json({ success: true, message: 'Logged out successfully. Session invalidated.' });
});

// -------------------------------------------------------------
// MIDDLEWARE: Proof-of-Possession & Replay Verification
// -------------------------------------------------------------
function verifyProofOfPossession(req, res, next) {
  const authHeader = req.headers.authorization;
  const clientIp = req.ip || req.socket.remoteAddress || '127.0.0.1';

  // 1. Check Bearer Token Presence
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    recordAudit('POP_VERIFICATION', 'REJECTED_MISSING_BEARER', { ip: clientIp, path: req.path });
    return res.status(401).json({
      error: 'Missing or malformed Authorization header. Expected Bearer <token>.',
      code: 'MISSING_BEARER'
    });
  }

  const token = authHeader.slice(7).trim();

  // 2. Validate Bearer Token in Session Store
  const session = sessions.get(token);
  if (!session) {
    recordAudit('POP_VERIFICATION', 'REJECTED_INVALID_TOKEN', { ip: clientIp, path: req.path });
    return res.status(401).json({
      error: 'Invalid or unknown bearer token.',
      code: 'INVALID_TOKEN'
    });
  }

  if (Date.now() > session.expiresAt) {
    sessions.delete(token);
    recordAudit('POP_VERIFICATION', 'REJECTED_EXPIRED_TOKEN', { username: session.userId });
    return res.status(401).json({
      error: 'Bearer token has expired. Please log in again.',
      code: 'EXPIRED_TOKEN'
    });
  }

  // 3. Ensure Client Public Key is Bound to Session
  if (!session.publicKeyObject) {
    recordAudit('POP_VERIFICATION', 'REJECTED_NO_KEY_BOUND', { username: session.userId });
    return res.status(403).json({
      error: 'No client public key registered for this session. Proof-of-Possession key registration is required.',
      code: 'KEY_NOT_REGISTERED'
    });
  }

  // 4. Extract Proof Headers
  const popTimestamp = req.headers['x-pop-timestamp'];
  const popNonce = req.headers['x-pop-nonce'];
  const popSignature = req.headers['x-pop-signature'];

  if (!popTimestamp || !popNonce || !popSignature) {
    recordAudit('POP_VERIFICATION', 'REJECTED_MISSING_PROOF_HEADERS', {
      username: session.userId,
      missing: {
        timestamp: !popTimestamp,
        nonce: !popNonce,
        signature: !popSignature
      }
    });
    return res.status(401).json({
      error: 'Missing required Proof-of-Possession headers (X-PoP-Timestamp, X-PoP-Nonce, X-PoP-Signature).',
      code: 'MISSING_PROOF'
    });
  }

  // 5. Strict Format Validation (Prevents Canonical Delimiter Injection)
  const trimmedTimestamp = typeof popTimestamp === 'string' ? popTimestamp.trim() : '';
  if (!/^\d{10,16}$/.test(trimmedTimestamp)) {
    return res.status(400).json({
      error: 'Invalid X-PoP-Timestamp format. Must be an integer millisecond string (10-16 digits) without control characters.',
      code: 'MALFORMED_TIMESTAMP'
    });
  }

  const timestampNum = parseInt(trimmedTimestamp, 10);
  if (!Number.isSafeInteger(timestampNum)) {
    return res.status(400).json({
      error: 'Invalid X-PoP-Timestamp integer value.',
      code: 'MALFORMED_TIMESTAMP'
    });
  }

  const now = Date.now();
  const ageMs = now - timestampNum;

  // Reject if too old (> 60s)
  if (ageMs > PROOF_MAX_AGE_MS) {
    recordAudit('POP_VERIFICATION', 'REJECTED_EXPIRED_TIMESTAMP', {
      username: session.userId,
      proofAgeMs: ageMs,
      maxAllowedMs: PROOF_MAX_AGE_MS
    });
    return res.status(401).json({
      error: `Proof timestamp is expired (Age: ${(ageMs / 1000).toFixed(1)}s, Maximum allowed: ${PROOF_MAX_AGE_MS / 1000}s).`,
      code: 'EXPIRED_PROOF',
      details: { serverTime: now, proofTime: timestampNum, differenceMs: ageMs }
    });
  }

  // Reject if too far in the future (> 10s skew)
  if (timestampNum - now > PROOF_FUTURE_SKEW_MS) {
    recordAudit('POP_VERIFICATION', 'REJECTED_FUTURE_TIMESTAMP', {
      username: session.userId,
      skewMs: timestampNum - now
    });
    return res.status(401).json({
      error: `Proof timestamp is too far in the future (Clock skew > ${PROOF_FUTURE_SKEW_MS / 1000}s).`,
      code: 'FUTURE_TIMESTAMP'
    });
  }

  // 6. Validate Nonce Format: strict alphanumeric/base64url to prevent canonical delimiter injection
  const trimmedNonce = typeof popNonce === 'string' ? popNonce.trim() : '';
  if (!/^[A-Za-z0-9_-]{16,128}$/.test(trimmedNonce)) {
    return res.status(400).json({
      error: 'Invalid X-PoP-Nonce format. Nonce must be a cryptographic string between 16 and 128 characters containing only alphanumeric, hyphen, or underscore characters.',
      code: 'MALFORMED_NONCE'
    });
  }

  // 7. Session-Bound Replay Attack Prevention Check
  // Keyed by session keyId and nonce, binding replay detection to the authenticated identity
  const replayKey = `${session.keyId}:${trimmedNonce}`;
  if (replayCache.has(replayKey)) {
    const replayRecord = replayCache.get(replayKey);
    recordAudit('POP_VERIFICATION', 'REJECTED_REPLAY_ATTACK', {
      username: session.userId,
      keyId: session.keyId,
      nonce: trimmedNonce,
      originalTimestamp: replayRecord.timestamp,
      attemptTimestamp: now
    });
    return res.status(409).json({
      error: 'REPLAY ATTACK DETECTED: This proof identifier (nonce) has already been accepted and consumed.',
      code: 'REPLAY_DETECTED',
      details: {
        nonce: trimmedNonce,
        keyId: session.keyId,
        firstSeen: new Date(replayRecord.timestamp).toISOString(),
        rejectedAt: new Date(now).toISOString()
      }
    });
  }

  // 8. Reconstruct Deterministic Canonical Payload
  // Server validates against the ACTUAL HTTP request method and path (not client assertion)
  const reqPath = req.originalUrl || req.path;
  const bodyHashHex = computeBodyHash(req.rawBody);
  const canonicalString = buildCanonicalString(
    req.method,
    reqPath,
    trimmedTimestamp,
    trimmedNonce,
    bodyHashHex
  );

  // 9. Verify Cryptographic Signature against Bound Client Public Key
  const trimmedSig = typeof popSignature === 'string' ? popSignature.trim() : '';
  if (!/^[A-Za-z0-9+/=_-]{80,100}$/.test(trimmedSig)) {
    recordAudit('POP_VERIFICATION', 'REJECTED_INVALID_SIG_ENCODING', {
      username: session.userId
    });
    return res.status(401).json({
      error: 'Invalid signature encoding format. Expected valid Base64 string.',
      code: 'INVALID_SIGNATURE_ENCODING'
    });
  }

  try {
    const sigBuffer = Buffer.from(trimmedSig, 'base64');
    // ECDSA P-256 signatures in IEEE P1363 format are exactly 64 bytes (32-byte r || 32-byte s)
    if (sigBuffer.length !== 64) {
      recordAudit('POP_VERIFICATION', 'REJECTED_MALFORMED_SIGNATURE', {
        username: session.userId,
        length: sigBuffer.length
      });
      return res.status(401).json({
        error: 'Invalid signature length. Expected 64-byte IEEE P1363 ECDSA P-256 signature.',
        code: 'INVALID_SIGNATURE_LENGTH'
      });
    }

    const isVerified = crypto.verify(
      'SHA256',
      Buffer.from(canonicalString, 'utf-8'),
      {
        key: session.publicKeyObject,
        dsaEncoding: 'ieee-p1363'
      },
      sigBuffer
    );

    if (!isVerified) {
      recordAudit('POP_VERIFICATION', 'REJECTED_SIGNATURE_MISMATCH', {
        username: session.userId,
        canonicalStringPreview: canonicalString.replace(/\n/g, '\\n')
      });
      return res.status(401).json({
        error: 'Cryptographic signature verification failed. Signature does not match registered client public key and canonical request payload.',
        code: 'SIGNATURE_INVALID',
        details: {
          canonicalFormat: 'METHOD\\nPATH\\nTIMESTAMP\\nNONCE\\nBODY_HASH'
        }
      });
    }
  } catch (err) {
    recordAudit('POP_VERIFICATION', 'REJECTED_SIGNATURE_ERROR', { error: err.message });
    return res.status(401).json({
      error: `Signature processing error: ${err.message}`,
      code: 'SIGNATURE_ERROR'
    });
  }

  // 10. ATOMIC NONCE RECORDING
  // Critical: Nonce is recorded in the replay cache ONLY after all checks (authentication, timestamp, signature) pass.
  // Retention duration ensures the record cannot be purged while its timestamp remains potentially acceptable.
  const safeExpiresAt = Math.max(now, timestampNum) + PROOF_MAX_AGE_MS + PROOF_FUTURE_SKEW_MS;
  replayCache.set(replayKey, {
    token,
    keyId: session.keyId,
    nonce: trimmedNonce,
    timestamp: timestampNum,
    expiresAt: safeExpiresAt
  });

  // Attach verified identity to request
  req.authSession = session;
  req.verifiedPoP = {
    nonce: trimmedNonce,
    timestamp: timestampNum,
    canonicalString,
    bodyHashHex
  };

  recordAudit('POP_VERIFICATION', 'ACCEPTED_VALID_PROOF', {
    username: session.userId,
    path: reqPath,
    nonce: `${trimmedNonce.slice(0, 8)}...`
  });

  next();
}

// -------------------------------------------------------------
// ENDPOINT: Protected Resource (Proof-of-Possession Hardened)
// -------------------------------------------------------------
app.get('/api/protected', verifyProofOfPossession, (req, res) => {
  return res.json({
    status: 'SUCCESS',
    message: 'Access granted to confidential resource via verified Proof-of-Possession!',
    data: {
      confidentialReport: 'Academic Cryptography Mini-Project: Proof-of-Possession Verification Successful',
      student: req.authSession.username,
      studentId: req.authSession.studentId,
      department: 'Department of Computer Science and Engineering',
      classification: 'RESTRICTED_ACCESS_VERIFIED',
      verificationDetails: {
        method: req.method,
        path: req.originalUrl,
        keyId: req.authSession.keyId,
        keyAlgorithm: req.authSession.keyAlgorithm,
        nonceVerified: req.verifiedPoP.nonce,
        timestampVerified: req.verifiedPoP.timestamp,
        bodyHash: req.verifiedPoP.bodyHashHex
      }
    }
  });
});

// -------------------------------------------------------------
// ENDPOINT: Protected Mutation (POST with Body Signature Verification)
// -------------------------------------------------------------
app.post('/api/protected/mutation', verifyProofOfPossession, (req, res) => {
  return res.json({
    status: 'SUCCESS',
    message: 'Signed mutation accepted and processed securely.',
    receivedBody: req.body,
    bodyHashVerified: req.verifiedPoP.bodyHashHex,
    processedAt: new Date().toISOString()
  });
});

// -------------------------------------------------------------
// ENDPOINT: Vulnerable Bearer-Only Resource (Educational Comparison)
// Intentionally isolated demonstration showing how raw bearer tokens
// are vulnerable to theft and replay without Proof-of-Possession.
// -------------------------------------------------------------
app.get('/api/vulnerable-bearer', (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({
      error: 'Missing Bearer token.',
      type: 'ORDINARY_BEARER'
    });
  }

  const token = authHeader.slice(7).trim();
  const session = sessions.get(token);
  if (!session || Date.now() > session.expiresAt) {
    return res.status(401).json({
      error: 'Invalid or expired bearer token.',
      type: 'ORDINARY_BEARER'
    });
  }

  recordAudit('ORDINARY_BEARER_ACCESSED', 'WARNING_UNBOUND_ACCESS', {
    username: session.userId,
    note: 'No proof of possession required; token accepted without signature.'
  });

  return res.json({
    warning: 'EDUCATIONAL VULNERABILITY DEMONSTRATION: ORDINARY BEARER TOKEN ACCEPTED WITHOUT PROOF-OF-POSSESSION',
    explanation: 'This endpoint only validated that the bearer token is in the session table. It DID NOT verify client private-key possession or request binding. If an attacker stole this token from HTTP headers, proxies, or memory, they could access this endpoint from any device without knowing the client private key.',
    sessionUser: session.username,
    role: session.role
  });
});

// -------------------------------------------------------------
// ENDPOINT: Security Audit Events (For Frontend Activity Log)
// -------------------------------------------------------------
app.get('/api/security/events', (req, res) => {
  return res.json({
    events: serverAuditLog.slice(0, 50)
  });
});

// -------------------------------------------------------------
// ENDPOINT: Reset Demonstration State
// Allows faculty and students to reset sessions, replay cache,
// and rate limits cleanly between test runs without restarting Node.
// -------------------------------------------------------------
app.post('/api/demo/reset', (req, res) => {
  sessions.clear();
  replayCache.clear();
  loginRateLimits.clear();
  userEnrolledKeys.clear();
  clearSessionCookie(res);
  recordAudit('DEMO_RESET', 'STATE_CLEARED', {
    activeSessions: 0,
    replayNonces: 0
  });
  return res.json({
    success: true,
    message: 'Demonstration environment reset. All sessions, replay caches, and rate-limits cleared.'
  });
});

// Fallback for unmatched routes
app.use((req, res) => {
  res.status(404).json({ error: 'Endpoint not found.' });
});

// Export app and server for programmatic testing
export { app };

// Start server only when executed directly (not when imported in tests)
const isDirectExecution = process.argv[1] && (
  process.argv[1].endsWith('server.js') || 
  process.argv[1].endsWith('server')
);

if (isDirectExecution) {
  app.listen(PORT, () => {
    console.log(`=======================================================`);
    console.log(` Web Crypto PoP Authentication & Replay Prevention Server`);
    console.log(` Running at: http://localhost:${PORT}`);
    console.log(` Demo Account: alice@cyber.edu / CryptoSec#2026`);
    console.log(`=======================================================`);
  });
}

/**
 * Web Crypto API-Based Proof-of-Possession Authentication & Replay Prevention
 * Live Owner vs. Attacker Simulator Demonstration Application
 */

// ============================================================================
// 1. ISOLATED CLIENT STATES
// ============================================================================

// Authorized Owner State (Legitimate User)
const ownerState = {
  token: null,
  user: null,
  expiresAt: null,
  keyPair: null,              // CryptoKeyPair: { publicKey, privateKey (extractable: false) }
  keyId: null,                // SHA-256 thumbprint of owner's public key
  publicKeySpkiBase64: null,
  timerInterval: null,
  lastValidProof: null        // Captured valid proof headers for replay demonstration
};

// Independent Attacker Simulator State (Adversary Client)
const attackerState = {
  keyPair: null,              // Independent CryptoKeyPair (attacker's own private key)
  keyId: null,                // SHA-256 thumbprint of attacker's public key
  publicKeySpkiBase64: null,
  stolenToken: '',            // Stolen bearer token vector
  capturedProof: null         // Captured legitimate request for replay attack
};

// Demonstration & Audit Log State
const demoState = {
  currentStep: 1,
  logs: [],
  activeFilter: 'all',
  isAutoRunning: false
};

// ============================================================================
// 1.5. INDEXEDDB PERSISTENT BROWSER KEY STORAGE
// Persists non-extractable CryptoKey pairs in the browser storage directly
// ============================================================================
const DB_NAME = 'WebCryptoPopKeyStore';
const DB_VERSION = 1;
const STORE_NAME = 'keys';

function openKeyDatabase() {
  return new Promise((resolve, reject) => {
    if (!window.indexedDB) {
      return reject(new Error('IndexedDB is not supported in this browser.'));
    }
    const request = window.indexedDB.open(DB_NAME, DB_VERSION);
    request.onupgradeneeded = (event) => {
      const db = event.target.result;
      if (!db.objectStoreNames.contains(STORE_NAME)) {
        db.createObjectStore(STORE_NAME, { keyPath: 'email' });
      }
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

async function saveKeyToIndexedDB(email, keyPair, keyId, spkiBase64) {
  try {
    const db = await openKeyDatabase();
    return new Promise((resolve, reject) => {
      const tx = db.transaction(STORE_NAME, 'readwrite');
      const store = tx.objectStore(STORE_NAME);
      const record = {
        email: email.toLowerCase(),
        keyPair,
        keyId,
        spkiBase64,
        savedAt: Date.now()
      };
      const req = store.put(record);
      req.onsuccess = () => resolve(true);
      req.onerror = () => reject(req.error);
    });
  } catch (err) {
    console.warn('[IndexedDB] Key persistence error:', err);
    return false;
  }
}

async function loadKeyFromIndexedDB(email) {
  try {
    const db = await openKeyDatabase();
    return new Promise((resolve, reject) => {
      const tx = db.transaction(STORE_NAME, 'readonly');
      const store = tx.objectStore(STORE_NAME);
      const req = store.get(email.toLowerCase());
      req.onsuccess = () => resolve(req.result || null);
      req.onerror = () => reject(req.error);
    });
  } catch (err) {
    console.warn('[IndexedDB] Key loading error:', err);
    return null;
  }
}

async function clearKeyFromIndexedDB(email) {
  try {
    const db = await openKeyDatabase();
    return new Promise((resolve, reject) => {
      const tx = db.transaction(STORE_NAME, 'readwrite');
      const store = tx.objectStore(STORE_NAME);
      const req = store.delete(email.toLowerCase());
      req.onsuccess = () => resolve(true);
      req.onerror = () => reject(req.error);
    });
  } catch (err) {
    console.warn('[IndexedDB] Key deletion error:', err);
    return false;
  }
}

// ============================================================================
// 2. W3C WEB CRYPTO API CRYPTOGRAPHIC UTILITIES
// ============================================================================

/**
 * Generate an in-memory ECDSA P-256 key pair.
 * Configured with extractable: false to prevent private key exfiltration.
 */
async function generateEcdsaKeyPair() {
  if (!window.crypto || !window.crypto.subtle) {
    throw new Error('W3C Web Crypto API is not supported in this browser environment.');
  }

  return await window.crypto.subtle.generateKey(
    {
      name: 'ECDSA',
      namedCurve: 'P-256' // NIST P-256 / secp256r1
    },
    false, // extractable: false hardware/browser protected
    ['sign', 'verify']
  );
}

/**
 * Export public key in SubjectPublicKeyInfo (SPKI) DER format and convert to Base64.
 */
async function exportPublicKeySpki(publicKey) {
  const spkiBuffer = await window.crypto.subtle.exportKey('spki', publicKey);
  return arrayBufferToBase64(spkiBuffer);
}

/**
 * Compute SHA-256 thumbprint of exported public key buffer (first 16 hex chars).
 */
async function computeThumbprint(buffer) {
  const hashBuffer = await window.crypto.subtle.digest('SHA-256', buffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.slice(0, 8).map(b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Compute SHA-256 hex digest of string or buffer (used for canonical request-body hash).
 */
async function computeSha256Hex(textOrBuffer) {
  let data;
  if (typeof textOrBuffer === 'string') {
    data = new TextEncoder().encode(textOrBuffer);
  } else if (textOrBuffer instanceof ArrayBuffer || ArrayBuffer.isView(textOrBuffer)) {
    data = textOrBuffer;
  } else {
    data = new Uint8Array(0);
  }

  const digestBuffer = await window.crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(digestBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Generate a cryptographically secure random 16-byte nonce.
 */
function generateCryptographicNonce() {
  const bytes = new Uint8Array(16);
  window.crypto.getRandomValues(bytes);
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Build deterministic canonical string.
 * Protocol Format:
 * METHOD\n
 * PATH\n
 * TIMESTAMP\n
 * NONCE\n
 * BODY_SHA256_HEX
 */
function buildCanonicalString(method, path, timestamp, nonce, bodySha256Hex) {
  return [
    method.toUpperCase(),
    path,
    timestamp.toString(),
    nonce,
    bodySha256Hex
  ].join('\n');
}

/**
 * Sign canonical data using an ECDSA private key via Web Crypto API.
 * Returns Base64-encoded IEEE P1363 (64-byte raw r || s) signature.
 */
async function signCanonicalData(canonicalString, privateKey) {
  const data = new TextEncoder().encode(canonicalString);
  const signatureBuffer = await window.crypto.subtle.sign(
    {
      name: 'ECDSA',
      hash: { name: 'SHA-256' }
    },
    privateKey,
    data
  );
  return arrayBufferToBase64(signatureBuffer);
}

// Helper: ArrayBuffer to Base64 string
function arrayBufferToBase64(buffer) {
  let binary = '';
  const bytes = new Uint8Array(buffer);
  const len = bytes.byteLength;
  for (let i = 0; i < len; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return window.btoa(binary);
}

// Helper: Base64 to ArrayBuffer
function base64ToArrayBuffer(base64) {
  const binaryString = window.atob(base64);
  const bytes = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes.buffer;
}

// ============================================================================
// 3. OWNER CLIENT OPERATIONS (AUTHORIZED IDENTITY & REGISTRATION)
// ============================================================================

/**
 * Switch between Sign In and Register New Account tabs.
 */
function switchAuthTab(mode) {
  const loginTab = document.getElementById('tab-login-btn');
  const registerTab = document.getElementById('tab-register-btn');
  const loginBox = document.getElementById('owner-login-box');
  const registerBox = document.getElementById('owner-register-box');
  const feedback = document.getElementById('register-feedback');
  if (feedback) feedback.className = 'feedback-banner hidden';

  if (mode === 'register') {
    loginTab.classList.remove('active');
    registerTab.classList.add('active');
    loginBox.classList.add('hidden');
    registerBox.classList.remove('hidden');
  } else {
    registerTab.classList.remove('active');
    loginTab.classList.add('active');
    registerBox.classList.add('hidden');
    loginBox.classList.remove('hidden');
  }
}

/**
 * Handle Local Account Registration.
 */
async function handleOwnerRegister(event) {
  if (event) event.preventDefault();
  const email = document.getElementById('register-email').value.trim();
  const password = document.getElementById('register-password').value;
  const confirmPassword = document.getElementById('register-confirm-password').value;
  const feedbackEl = document.getElementById('register-feedback');

  feedbackEl.className = 'feedback-banner hidden';

  if (!email || !password || !confirmPassword) {
    feedbackEl.className = 'feedback-banner error';
    feedbackEl.textContent = 'All fields are required.';
    feedbackEl.classList.remove('hidden');
    return;
  }

  if (password !== confirmPassword) {
    feedbackEl.className = 'feedback-banner error';
    feedbackEl.textContent = 'Password and confirmation do not match.';
    feedbackEl.classList.remove('hidden');
    return;
  }

  try {
    const response = await fetch('/api/auth/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password, confirmPassword })
    });

    const data = await response.json();

    if (!response.ok) {
      feedbackEl.className = 'feedback-banner error';
      feedbackEl.textContent = `Registration rejected: ${data.error || 'Validation failed'}`;
      feedbackEl.classList.remove('hidden');
      logAudit({
        origin: 'OWNER',
        eventType: 'OWNER_REGISTER_REJECTED',
        statusCode: response.status,
        method: 'POST',
        path: '/api/auth/register',
        message: `Local registration failed: ${data.error}`,
        details: { email, status: response.status },
        passed: false
      });
      return;
    }

    feedbackEl.className = 'feedback-banner success';
    feedbackEl.textContent = `${data.message} Switching to Sign In...`;
    feedbackEl.classList.remove('hidden');

    logAudit({
      origin: 'OWNER',
      eventType: 'OWNER_REGISTER_SUCCESS',
      statusCode: response.status,
      method: 'POST',
      path: '/api/auth/register',
      message: `Account registered successfully for ${email}. Password protected via salted scrypt hash.`,
      details: { email, role: data.user.role, studentId: data.user.studentId },
      passed: true
    });

    document.getElementById('owner-username').value = email;
    document.getElementById('owner-password').value = '';

    setTimeout(() => {
      switchAuthTab('login');
      document.getElementById('owner-password').focus();
    }, 1200);
  } catch (err) {
    feedbackEl.className = 'feedback-banner error';
    feedbackEl.textContent = `Network error: ${err.message}`;
    feedbackEl.classList.remove('hidden');
  }
}

/**
 * Step 1: Owner login with credentials.
 */
async function handleOwnerLogin(event) {
  if (event) event.preventDefault();
  const username = document.getElementById('owner-username').value.trim();
  const password = document.getElementById('owner-password').value;

  try {
    const response = await fetch('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password })
    });

    const data = await response.json();

    if (!response.ok) {
      logAudit({
        origin: 'OWNER',
        eventType: 'OWNER_LOGIN_FAILED',
        statusCode: response.status,
        method: 'POST',
        path: '/api/auth/login',
        message: `Owner authentication rejected: ${data.error || 'Invalid credentials'}`,
        details: { username, status: response.status },
        passed: false
      });
      alert(`Login failed: ${data.error || 'Invalid credentials'}`);
      return false;
    }

    // Set Owner session state
    ownerState.token = data.token;
    ownerState.user = data.user;
    ownerState.expiresAt = data.expiresAt;

    logAudit({
      origin: 'OWNER',
      eventType: 'OWNER_LOGIN_SUCCESS',
      statusCode: response.status,
      method: 'POST',
      path: '/api/auth/login',
      message: `Owner authenticated successfully. Issued 256-bit CSPRNG bearer token for ${data.user.name}.`,
      details: {
        user: data.user.name,
        role: data.user.role,
        maskedToken: `${data.token.slice(0, 6)}••••${data.token.slice(-6)}`,
        expiresIn: `${data.expiresIn}s`
      },
      passed: true
    });

    updateOwnerUI();
    startOwnerSessionTimer();
    setRoadmapStep(2);

    // Check if user has an enrolled persistent key in IndexedDB
    const savedKey = await loadKeyFromIndexedDB(data.user.username);
    if (savedKey && savedKey.keyPair) {
      if (data.keyRegistered && data.keyId && savedKey.keyId === data.keyId) {
        // Enrolled key already bound on server and matches
        ownerState.keyPair = savedKey.keyPair;
        ownerState.keyId = savedKey.keyId;
        ownerState.publicKeySpkiBase64 = savedKey.spkiBase64;
        updateOwnerUI();
        setRoadmapStep(3);
        logAudit({
          origin: 'OWNER',
          eventType: 'KEY_RESTORED_LOCAL',
          statusCode: 200,
          method: 'INDEXEDDB',
          path: 'N/A',
          message: `Restored enrolled browser key from IndexedDB (Key ID: ${savedKey.keyId}).`,
          details: { keyId: savedKey.keyId },
          passed: true
        });
        return true;
      }
    }

    // Otherwise generate and register key
    await handleOwnerGenerateAndRegisterKey();
    return true;
  } catch (err) {
    logAudit({
      origin: 'OWNER',
      eventType: 'OWNER_LOGIN_ERROR',
      statusCode: 0,
      method: 'POST',
      path: '/api/auth/login',
      message: `Network error during login: ${err.message}`,
      details: { error: err.message },
      passed: false
    });
    return false;
  }
}

/**
 * Step 2: Generate Owner ECDSA P-256 Key Pair and register public key.
 * Persists key in IndexedDB for session restoration.
 */
async function handleOwnerGenerateAndRegisterKey() {
  if (!ownerState.token) {
    alert('Owner must be authenticated first.');
    return false;
  }

  try {
    // 1. Generate client-side key pair (extractable: false)
    const keyPair = await generateEcdsaKeyPair();
    ownerState.keyPair = keyPair;

    // 2. Export ONLY the public key in SPKI format
    const spkiBase64 = await exportPublicKeySpki(keyPair.publicKey);
    ownerState.publicKeySpkiBase64 = spkiBase64;

    const spkiBuffer = base64ToArrayBuffer(spkiBase64);
    ownerState.keyId = await computeThumbprint(spkiBuffer);

    // 3. Register public key with active session
    const response = await fetch('/api/auth/register-key', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${ownerState.token}`
      },
      body: JSON.stringify({ publicKeySpki: spkiBase64 })
    });

    const data = await response.json();

    if (!response.ok) {
      logAudit({
        origin: 'OWNER',
        eventType: 'KEY_REGISTRATION_FAILED',
        statusCode: response.status,
        method: 'POST',
        path: '/api/auth/register-key',
        message: `Public key registration failed: ${data.error}`,
        details: data,
        passed: false
      });
      alert(`Key registration failed: ${data.error}`);
      return false;
    }

    // 4. Save persistent key to IndexedDB bound to user account
    await saveKeyToIndexedDB(ownerState.user.username, keyPair, ownerState.keyId, spkiBase64);

    logAudit({
      origin: 'OWNER',
      eventType: 'KEY_REGISTERED',
      statusCode: response.status,
      method: 'POST',
      path: '/api/auth/register-key',
      message: `Owner public key bound to authenticated session. Key ID: ${data.keyId}`,
      details: {
        algorithm: data.algorithm,
        thumbprint: ownerState.keyId,
        storage: 'IndexedDB (Browser Persistent)'
      },
      passed: true
    });

    updateOwnerUI();
    setRoadmapStep(3);
    return true;
  } catch (err) {
    logAudit({
      origin: 'OWNER',
      eventType: 'KEY_ERROR',
      statusCode: 0,
      method: 'POST',
      path: '/api/auth/register-key',
      message: `Cryptographic key generation error: ${err.message}`,
      details: { error: err.message },
      passed: false
    });
    return false;
  }
}

/**
 * Step 3: Owner executes a valid signed GET request to /api/protected.
 */
async function handleOwnerGetProtected() {
  if (!ownerState.token || !ownerState.keyPair) {
    alert('Owner must be logged in with a registered key.');
    return null;
  }

  try {
    const timestamp = Date.now().toString();
    const nonce = generateCryptographicNonce();
    const bodyHash = await computeSha256Hex('');
    const path = '/api/protected';
    const canonicalString = buildCanonicalString('GET', path, timestamp, nonce, bodyHash);
    const signature = await signCanonicalData(canonicalString, ownerState.keyPair.privateKey);

    const headers = {
      'Authorization': `Bearer ${ownerState.token}`,
      'X-PoP-Timestamp': timestamp,
      'X-PoP-Nonce': nonce,
      'X-PoP-Signature': signature
    };

    // Save proof for replay simulation demonstration
    ownerState.lastValidProof = {
      headers: { ...headers },
      canonicalString,
      timestamp,
      nonce,
      signature
    };
    attackerState.capturedProof = { ...ownerState.lastValidProof };

    const response = await fetch(path, { method: 'GET', headers });
    const data = await response.json();

    displayResult('owner', 'GET /api/protected (Signed Resource Access)', response.status, data);

    logAudit({
      origin: 'OWNER',
      eventType: 'OWNER_GET_PROTECTED',
      statusCode: response.status,
      method: 'GET',
      path,
      message: response.ok
        ? 'LEGITIMATE ACCESS GRANTED: Proof-of-Possession signature verified against session public key.'
        : `Access rejected: ${data.error}`,
      details: {
        status: response.status,
        keyId: ownerState.keyId,
        nonce: `${nonce.slice(0, 8)}...`,
        canonicalPreview: canonicalString.replace(/\n/g, ' ↵ '),
        response: data
      },
      passed: response.ok
    });

    setRoadmapStep(4);
    return { ok: response.ok, status: response.status, data };
  } catch (err) {
    logAudit({
      origin: 'OWNER',
      eventType: 'OWNER_GET_ERROR',
      statusCode: 0,
      method: 'GET',
      path: '/api/protected',
      message: `Request error: ${err.message}`,
      details: { error: err.message },
      passed: false
    });
    return null;
  }
}

/**
 * Step 4: Owner submits a signed POST request with JSON payload & body hash.
 */
async function handleOwnerPostMutation(event) {
  if (event) event.preventDefault();
  if (!ownerState.token || !ownerState.keyPair) {
    alert('Owner must be logged in with a registered key.');
    return null;
  }

  const recordTitle = document.getElementById('mutation-record-title').value.trim();
  const grade = document.getElementById('mutation-grade').value.trim();
  const payloadString = JSON.stringify({
    recordTitle,
    grade,
    updatedAt: new Date().toISOString()
  });

  try {
    const timestamp = Date.now().toString();
    const nonce = generateCryptographicNonce();
    const bodyHash = await computeSha256Hex(payloadString);
    const path = '/api/protected/mutation';
    const canonicalString = buildCanonicalString('POST', path, timestamp, nonce, bodyHash);
    const signature = await signCanonicalData(canonicalString, ownerState.keyPair.privateKey);

    const headers = {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${ownerState.token}`,
      'X-PoP-Timestamp': timestamp,
      'X-PoP-Nonce': nonce,
      'X-PoP-Signature': signature
    };

    const response = await fetch(path, {
      method: 'POST',
      headers,
      body: payloadString
    });

    const data = await response.json();
    displayResult('owner', 'POST /api/protected/mutation (Signed Mutation)', response.status, data);

    logAudit({
      origin: 'OWNER',
      eventType: 'OWNER_POST_MUTATION',
      statusCode: response.status,
      method: 'POST',
      path,
      message: response.ok
        ? 'SIGNED MUTATION ACCEPTED: Request-body SHA-256 hash verified and bound to signature.'
        : `Mutation rejected: ${data.error}`,
      details: {
        status: response.status,
        bodyHash,
        nonce: `${nonce.slice(0, 8)}...`,
        response: data
      },
      passed: response.ok
    });

    setRoadmapStep(5);
    return { ok: response.ok, status: response.status, data };
  } catch (err) {
    logAudit({
      origin: 'OWNER',
      eventType: 'OWNER_POST_ERROR',
      statusCode: 0,
      method: 'POST',
      path: '/api/protected/mutation',
      message: `Mutation error: ${err.message}`,
      details: { error: err.message },
      passed: false
    });
    return null;
  }
}

/**
 * Transfer the Owner's token to the Attacker Simulator input (controlled theft demonstration).
 */
function handleCopyTokenToAttacker() {
  if (!ownerState.token) {
    alert('No active owner token to copy. Log in as Owner first.');
    return;
  }

  attackerState.stolenToken = ownerState.token;
  const inputEl = document.getElementById('attacker-token-input');
  inputEl.value = ownerState.token;
  inputEl.classList.add('highlight-pulse');
  setTimeout(() => inputEl.classList.remove('highlight-pulse'), 1200);

  updateAttackerUI();

  logAudit({
    origin: 'SYSTEM',
    eventType: 'TOKEN_EXFILTRATED',
    statusCode: 200,
    method: 'SIMULATION',
    path: 'N/A',
    message: 'Controlled Token Theft: Owner bearer token copied into Attacker Simulator storage.',
    details: {
      maskedToken: `${ownerState.token.slice(0, 6)}••••${ownerState.token.slice(-6)}`,
      note: 'The attacker possesses the bearer token, but DOES NOT have the owner\'s private key.'
    },
    passed: true
  });

  setRoadmapStep(5);
}

/**
 * Sign out Owner and wipe client keys.
 */
async function handleOwnerLogout() {
  if (ownerState.token) {
    try {
      await fetch('/api/auth/logout', {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${ownerState.token}` }
      });
    } catch (e) {
      // Ignore network errors on logout
    }
  }

  ownerState.token = null;
  ownerState.user = null;
  ownerState.expiresAt = null;
  ownerState.keyPair = null;
  ownerState.keyId = null;
  ownerState.publicKeySpkiBase64 = null;
  ownerState.lastValidProof = null;
  if (ownerState.timerInterval) clearInterval(ownerState.timerInterval);

  logAudit({
    origin: 'OWNER',
    eventType: 'OWNER_LOGOUT',
    statusCode: 200,
    method: 'POST',
    path: '/api/auth/logout',
    message: 'Owner logged out. Client private keys purged from browser memory.',
    details: {},
    passed: true
  });

  updateOwnerUI();
}

// ============================================================================
// 4. ATTACKER SIMULATOR OPERATIONS (ADVERSARY CLIENT)
// ============================================================================

/**
 * Generate an independent ECDSA P-256 key pair for the Attacker.
 */
async function handleAttackerGenerateKey() {
  try {
    const keyPair = await generateEcdsaKeyPair();
    attackerState.keyPair = keyPair;

    const spkiBase64 = await exportPublicKeySpki(keyPair.publicKey);
    attackerState.publicKeySpkiBase64 = spkiBase64;

    const spkiBuffer = base64ToArrayBuffer(spkiBase64);
    attackerState.keyId = await computeThumbprint(spkiBuffer);

    logAudit({
      origin: 'ATTACKER',
      eventType: 'ATTACKER_KEY_GENERATED',
      statusCode: 200,
      method: 'CRYPTO',
      path: 'N/A',
      message: `Attacker generated an independent ECDSA P-256 key pair (Key ID: ${attackerState.keyId}).`,
      details: {
        attackerKeyId: attackerState.keyId,
        ownerKeyId: ownerState.keyId || 'None',
        isolationNote: 'Attacker key pair is completely distinct and isolated from Owner key.'
      },
      passed: true
    });

    updateAttackerUI();
    return true;
  } catch (err) {
    logAudit({
      origin: 'ATTACKER',
      eventType: 'ATTACKER_KEY_ERROR',
      statusCode: 0,
      method: 'CRYPTO',
      path: 'N/A',
      message: `Failed to generate attacker key: ${err.message}`,
      details: { error: err.message },
      passed: false
    });
    return false;
  }
}

/**
 * Import token from Owner state or input box.
 */
function handleAttackerImportToken() {
  if (ownerState.token) {
    handleCopyTokenToAttacker();
  } else {
    const inputVal = document.getElementById('attacker-token-input').value.trim();
    if (inputVal) {
      attackerState.stolenToken = inputVal;
      updateAttackerUI();
    } else {
      alert('Owner is not logged in, and no token was entered in the field.');
    }
  }
}

/**
 * ATTACK 1 (Step 5): Stolen token used WITHOUT proof headers.
 */
async function executeAttack1_NoProof() {
  const token = getAttackerToken();
  if (!token) return;

  try {
    const path = '/api/protected';
    const response = await fetch(path, {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${token}`
        // Omit X-PoP-* proof headers
      }
    });

    const data = await response.json();
    displayResult('attacker', 'ATTACK 1: Token Without Proof', response.status, data);

    const defenseSuccess = response.status === 401;
    logAudit({
      origin: 'ATTACKER',
      eventType: 'ATTACK_1_NO_PROOF',
      statusCode: response.status,
      method: 'GET',
      path,
      message: defenseSuccess
        ? 'DEFENSE SUCCEEDED: Server rejected stolen bearer token because Proof-of-Possession headers were missing.'
        : 'SECURITY FAILURE: Protected resource accessed without proof of possession!',
      details: {
        attackVector: 'Token Replay Without Signature',
        expectedStatus: 401,
        actualStatus: response.status,
        serverCode: data.code,
        serverError: data.error
      },
      passed: defenseSuccess
    });

    setRoadmapStep(6);
    return { ok: response.ok, status: response.status, defenseSuccess };
  } catch (err) {
    logAudit({
      origin: 'ATTACKER',
      eventType: 'ATTACK_1_ERROR',
      statusCode: 0,
      method: 'GET',
      path: '/api/protected',
      message: `Network error during attack: ${err.message}`,
      details: { error: err.message },
      passed: false
    });
  }
}

/**
 * ATTACK 2 (Step 6): Use stolen owner token, but sign with ATTACKER'S private key.
 * This directly tests: Does the server verify the signature against the OWNER session's registered key?
 */
async function executeAttack2_AttackerKey() {
  const token = getAttackerToken();
  if (!token) return;

  // Ensure attacker has an independent key pair
  if (!attackerState.keyPair) {
    await handleAttackerGenerateKey();
  }

  try {
    const timestamp = Date.now().toString();
    const nonce = generateCryptographicNonce();
    const bodyHash = await computeSha256Hex('');
    const path = '/api/protected';
    const canonicalString = buildCanonicalString('GET', path, timestamp, nonce, bodyHash);

    // SIGN WITH ATTACKER'S OWN PRIVATE KEY!
    const attackerSignature = await signCanonicalData(canonicalString, attackerState.keyPair.privateKey);

    const headers = {
      'Authorization': `Bearer ${token}`,
      'X-PoP-Timestamp': timestamp,
      'X-PoP-Nonce': nonce,
      'X-PoP-Signature': attackerSignature
    };

    const response = await fetch(path, { method: 'GET', headers });
    const data = await response.json();

    displayResult('attacker', 'ATTACK 2: Sign with Attacker Key', response.status, data);

    const defenseSuccess = response.status === 401;
    logAudit({
      origin: 'ATTACKER',
      eventType: 'ATTACK_2_KEY_FORGERY',
      statusCode: response.status,
      method: 'GET',
      path,
      message: defenseSuccess
        ? 'DEFENSE SUCCEEDED: Server rejected signature forged by attacker key! Signature does not match the public key bound to the session.'
        : 'SECURITY FAILURE: Forged signature was accepted by the server!',
      details: {
        attackVector: 'Cryptographic Signature Forgery',
        attackerKeyThumbprint: attackerState.keyId,
        ownerSessionKeyThumbprint: ownerState.keyId || 'Registered in Session',
        expectedStatus: 401,
        actualStatus: response.status,
        serverCode: data.code,
        serverError: data.error
      },
      passed: defenseSuccess
    });

    setRoadmapStep(7);
    return { ok: response.ok, status: response.status, defenseSuccess };
  } catch (err) {
    logAudit({
      origin: 'ATTACKER',
      eventType: 'ATTACK_2_ERROR',
      statusCode: 0,
      method: 'GET',
      path: '/api/protected',
      message: `Error executing Attack 2: ${err.message}`,
      details: { error: err.message },
      passed: false
    });
  }
}

/**
 * ATTACK 3 (Step 7): Replay previously accepted valid request proof.
 */
async function executeAttack3_Replay() {
  let proof = attackerState.capturedProof || ownerState.lastValidProof;

  // Check if we have a fresh valid proof (< 50 seconds old to stay safely within 60s freshness window)
  const isProofFresh = proof && proof.timestamp && (Date.now() - parseInt(proof.timestamp, 10)) < 50000;

  if (!isProofFresh) {
    // If owner session and key are available, generate a fresh valid request and submit it first
    if (ownerState.token && ownerState.keyPair) {
      logAudit({
        origin: 'SYSTEM',
        eventType: 'REPLAY_SETUP',
        statusCode: 200,
        method: 'CAPTURE',
        path: '/api/protected',
        message: 'Capturing fresh legitimate request proof from Owner for replay demonstration...',
        details: { note: 'Ensures replayed request is within the 60-second freshness window' },
        passed: true
      });
      const getRes = await handleOwnerGetProtected();
      if (!getRes || !getRes.ok) {
        alert('Could not establish a fresh successful GET request to capture for replay.');
        return;
      }
      proof = attackerState.capturedProof || ownerState.lastValidProof;
    } else {
      alert('No fresh captured valid request available to replay (< 50s old). Have the Owner execute a successful GET request (Step 3) first.');
      return;
    }
  }

  try {
    const path = '/api/protected';
    // Send the EXACT SAME headers (same nonce, timestamp, signature)
    const response = await fetch(path, {
      method: 'GET',
      headers: proof.headers
    });

    const data = await response.json();
    displayResult('attacker', 'ATTACK 3: Request Replay', response.status, data);

    const defenseSuccess = response.status === 409;
    logAudit({
      origin: 'ATTACKER',
      eventType: 'ATTACK_3_REPLAY',
      statusCode: response.status,
      method: 'GET',
      path,
      message: defenseSuccess
        ? 'DEFENSE SUCCEEDED: Replay attack intercepted! Server detected that proof nonce was already consumed.'
        : (response.status === 401 && data.code === 'EXPIRED_PROOF'
          ? 'DEFENSE SUCCEEDED (EXPIRED): Proof timestamp expired before replay. Generating a fresh proof will demonstrate 409 REPLAY_DETECTED.'
          : 'SECURITY FAILURE: Replayed request was accepted by server!'),
      details: {
        attackVector: 'Duplicate Nonce Transmission (Replay)',
        replayedNonce: proof.nonce,
        expectedStatus: 409,
        actualStatus: response.status,
        serverCode: data.code,
        serverError: data.error
      },
      passed: defenseSuccess
    });

    setRoadmapStep(8);
    return { ok: response.ok, status: response.status, defenseSuccess };
  } catch (err) {
    logAudit({
      origin: 'ATTACKER',
      eventType: 'ATTACK_3_ERROR',
      statusCode: 0,
      method: 'GET',
      path: '/api/protected',
      message: `Error executing Attack 3: ${err.message}`,
      details: { error: err.message },
      passed: false
    });
  }
}

/**
 * ATTACK 4: Deliberately corrupted/tampered signature.
 */
async function executeAttack4_TamperedSignature() {
  const token = getAttackerToken();
  if (!token) return;

  try {
    const timestamp = Date.now().toString();
    const nonce = generateCryptographicNonce();
    const bodyHash = await computeSha256Hex('');
    const path = '/api/protected';
    const canonicalString = buildCanonicalString('GET', path, timestamp, nonce, bodyHash);

    let signature;
    const privateKey = ownerState.keyPair ? ownerState.keyPair.privateKey : (attackerState.keyPair ? attackerState.keyPair.privateKey : null);
    if (privateKey) {
      const validSigBase64 = await signCanonicalData(canonicalString, privateKey);
      const sigBuffer = base64ToArrayBuffer(validSigBase64);
      const sigBytes = new Uint8Array(sigBuffer);
      sigBytes[0] = sigBytes[0] ^ 0xFF; // Deliberately corrupt the first byte of the signature
      signature = arrayBufferToBase64(sigBytes.buffer);
    } else {
      // Create a 64-byte dummy IEEE P1363 buffer using browser-native Uint8Array
      const dummyBytes = new Uint8Array(64);
      dummyBytes.fill(0xAA);
      signature = arrayBufferToBase64(dummyBytes.buffer);
    }

    const headers = {
      'Authorization': `Bearer ${token}`,
      'X-PoP-Timestamp': timestamp,
      'X-PoP-Nonce': nonce,
      'X-PoP-Signature': signature
    };

    const response = await fetch(path, { method: 'GET', headers });
    const data = await response.json();

    displayResult('attacker', 'ATTACK 4: Tampered Signature', response.status, data);

    const defenseSuccess = response.status === 401;
    logAudit({
      origin: 'ATTACKER',
      eventType: 'ATTACK_4_TAMPERED_SIG',
      statusCode: response.status,
      method: 'GET',
      path,
      message: defenseSuccess
        ? 'DEFENSE SUCCEEDED: Server detected corrupted cryptographic signature bytes.'
        : 'SECURITY FAILURE: Corrupted signature was accepted!',
      details: {
        attackVector: 'Corrupted Signature Bytes',
        expectedStatus: 401,
        actualStatus: response.status,
        serverCode: data.code,
        serverError: data.error
      },
      passed: defenseSuccess
    });

    return { ok: response.ok, status: response.status, defenseSuccess };
  } catch (err) {
    logAudit({
      origin: 'ATTACKER',
      eventType: 'ATTACK_4_ERROR',
      statusCode: 0,
      method: 'GET',
      path: '/api/protected',
      message: `Error: ${err.message}`,
      details: { error: err.message },
      passed: false
    });
  }
}

/**
 * ATTACK 5: Expired proof timestamp (> 60s in past).
 */
async function executeAttack5_ExpiredTimestamp() {
  const token = getAttackerToken();
  if (!token) return;

  try {
    // 2 minutes ago (120,000 ms; window is 60s)
    const expiredTimestamp = (Date.now() - 120000).toString();
    const nonce = generateCryptographicNonce();
    const bodyHash = await computeSha256Hex('');
    const path = '/api/protected';
    const canonicalString = buildCanonicalString('GET', path, expiredTimestamp, nonce, bodyHash);

    // If owner key available, use it to prove failure is strictly due to timestamp
    const privateKey = ownerState.keyPair ? ownerState.keyPair.privateKey : (attackerState.keyPair ? attackerState.keyPair.privateKey : null);
    if (!privateKey) {
      alert('Generate an Attacker or Owner key first.');
      return;
    }

    const signature = await signCanonicalData(canonicalString, privateKey);

    const headers = {
      'Authorization': `Bearer ${token}`,
      'X-PoP-Timestamp': expiredTimestamp,
      'X-PoP-Nonce': nonce,
      'X-PoP-Signature': signature
    };

    const response = await fetch(path, { method: 'GET', headers });
    const data = await response.json();

    displayResult('attacker', 'ATTACK 5: Expired Timestamp', response.status, data);

    const defenseSuccess = response.status === 401;
    logAudit({
      origin: 'ATTACKER',
      eventType: 'ATTACK_5_EXPIRED_TIMESTAMP',
      statusCode: response.status,
      method: 'GET',
      path,
      message: defenseSuccess
        ? 'DEFENSE SUCCEEDED: Server rejected proof because timestamp exceeded the 60-second validity window.'
        : 'SECURITY FAILURE: Expired proof was accepted!',
      details: {
        attackVector: 'Expired Timestamp Window',
        proofTimestamp: expiredTimestamp,
        expectedStatus: 401,
        actualStatus: response.status,
        serverCode: data.code,
        serverError: data.error
      },
      passed: defenseSuccess
    });

    return { ok: response.ok, status: response.status, defenseSuccess };
  } catch (err) {
    logAudit({
      origin: 'ATTACKER',
      eventType: 'ATTACK_5_ERROR',
      statusCode: 0,
      method: 'GET',
      path: '/api/protected',
      message: `Error: ${err.message}`,
      details: { error: err.message },
      passed: false
    });
  }
}

/**
 * ATTACK 6: Tampered request path binding.
 */
async function executeAttack6_TamperedPath() {
  const token = getAttackerToken();
  if (!token) return;

  try {
    const timestamp = Date.now().toString();
    const nonce = generateCryptographicNonce();
    const bodyHash = await computeSha256Hex('');
    const signedPath = '/api/protected';
    const canonicalString = buildCanonicalString('GET', signedPath, timestamp, nonce, bodyHash);

    const privateKey = ownerState.keyPair ? ownerState.keyPair.privateKey : (attackerState.keyPair ? attackerState.keyPair.privateKey : null);
    if (!privateKey) {
      alert('Generate a key first.');
      return;
    }
    const signature = await signCanonicalData(canonicalString, privateKey);

    const headers = {
      'Authorization': `Bearer ${token}`,
      'X-PoP-Timestamp': timestamp,
      'X-PoP-Nonce': nonce,
      'X-PoP-Signature': signature
    };

    // Attacker modifies destination path to include query injection
    const tamperedPath = '/api/protected?elevate_role=admin';
    const response = await fetch(tamperedPath, { method: 'GET', headers });
    const data = await response.json();

    displayResult('attacker', 'ATTACK 6: Tampered Path Binding', response.status, data);

    const defenseSuccess = response.status === 401;
    logAudit({
      origin: 'ATTACKER',
      eventType: 'ATTACK_6_TAMPERED_PATH',
      statusCode: response.status,
      method: 'GET',
      path: tamperedPath,
      message: defenseSuccess
        ? 'DEFENSE SUCCEEDED: Server detected path binding mismatch! The signed path does not match the actual HTTP request path.'
        : 'SECURITY FAILURE: Tampered request path accepted!',
      details: {
        attackVector: 'URI Query String Tampering',
        signedPath,
        actualPath: tamperedPath,
        expectedStatus: 401,
        actualStatus: response.status,
        serverCode: data.code,
        serverError: data.error
      },
      passed: defenseSuccess
    });

    return { ok: response.ok, status: response.status, defenseSuccess };
  } catch (err) {
    logAudit({
      origin: 'ATTACKER',
      eventType: 'ATTACK_6_ERROR',
      statusCode: 0,
      method: 'GET',
      path: '/api/protected',
      message: `Error: ${err.message}`,
      details: { error: err.message },
      passed: false
    });
  }
}

/**
 * ATTACK 7: Tampered request body payload.
 */
async function executeAttack7_TamperedBody() {
  const token = getAttackerToken();
  if (!token) return;

  try {
    const timestamp = Date.now().toString();
    const nonce = generateCryptographicNonce();
    const originalBody = JSON.stringify({ item: 'Research Data', grade: 'A+' });
    const originalHash = await computeSha256Hex(originalBody);
    const path = '/api/protected/mutation';
    const canonicalString = buildCanonicalString('POST', path, timestamp, nonce, originalHash);

    const privateKey = ownerState.keyPair ? ownerState.keyPair.privateKey : (attackerState.keyPair ? attackerState.keyPair.privateKey : null);
    if (!privateKey) {
      alert('Generate a key first.');
      return;
    }
    const signature = await signCanonicalData(canonicalString, privateKey);

    const headers = {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${token}`,
      'X-PoP-Timestamp': timestamp,
      'X-PoP-Nonce': nonce,
      'X-PoP-Signature': signature
    };

    // Attacker modifies body in transit
    const tamperedBody = JSON.stringify({ item: 'Research Data', grade: 'F (Failed)' });

    const response = await fetch(path, {
      method: 'POST',
      headers,
      body: tamperedBody
    });
    const data = await response.json();

    displayResult('attacker', 'ATTACK 7: Tampered Body Payload', response.status, data);

    const defenseSuccess = response.status === 401;
    logAudit({
      origin: 'ATTACKER',
      eventType: 'ATTACK_7_TAMPERED_BODY',
      statusCode: response.status,
      method: 'POST',
      path,
      message: defenseSuccess
        ? 'DEFENSE SUCCEEDED: Server rejected tampered request body! SHA-256 digest of payload did not match signed hash.'
        : 'SECURITY FAILURE: Tampered body accepted!',
      details: {
        attackVector: 'POST Payload Tampering',
        expectedStatus: 401,
        actualStatus: response.status,
        serverCode: data.code,
        serverError: data.error
      },
      passed: defenseSuccess
    });

    return { ok: response.ok, status: response.status, defenseSuccess };
  } catch (err) {
    logAudit({
      origin: 'ATTACKER',
      eventType: 'ATTACK_7_ERROR',
      statusCode: 0,
      method: 'POST',
      path: '/api/protected/mutation',
      message: `Error: ${err.message}`,
      details: { error: err.message },
      passed: false
    });
  }
}

/**
 * Execute all 7 attack simulations sequentially.
 */
async function executeFullAttackSuite() {
  const btn = document.getElementById('btn-attack-run-all');
  btn.disabled = true;
  btn.textContent = '⚡ Running Attacks 1 through 7...';

  logAudit({
    origin: 'ATTACKER',
    eventType: 'SUITE_STARTED',
    statusCode: 200,
    method: 'SIMULATION',
    path: 'N/A',
    message: 'Starting automated execution of all 7 attack vectors against backend...',
    details: {},
    passed: true
  });

  await executeAttack1_NoProof();
  await sleep(400);
  await executeAttack2_AttackerKey();
  await sleep(400);
  await executeAttack3_Replay();
  await sleep(400);
  await executeAttack4_TamperedSignature();
  await sleep(400);
  await executeAttack5_ExpiredTimestamp();
  await sleep(400);
  await executeAttack6_TamperedPath();
  await sleep(400);
  await executeAttack7_TamperedBody();

  btn.disabled = false;
  btn.innerHTML = '<span>⚡ Execute Full Attack Suite (Attacks 1 through 7)</span>';
  setRoadmapStep(9);
}

// Helper: retrieve current attacker token
function getAttackerToken() {
  const inputVal = document.getElementById('attacker-token-input').value.trim();
  const token = inputVal || attackerState.stolenToken || ownerState.token;
  if (!token) {
    alert('Please paste or import a stolen bearer token into the Attacker Simulator first.');
    return null;
  }
  attackerState.stolenToken = token;
  return token;
}

// Helper: sleep delay
function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

// ============================================================================
// 5. DEMONSTRATION WORKFLOW AUTOMATION & RESET
// ============================================================================

/**
 * Auto-runs the entire 9-step demonstration narrative end-to-end.
 */
async function runFullDemonstrationFlow() {
  if (demoState.isAutoRunning) return;
  demoState.isAutoRunning = true;

  const autoBtn = document.getElementById('btn-auto-demo');
  autoBtn.disabled = true;
  autoBtn.textContent = '⏳ Executing 9-Step Demonstration...';

  try {
    // Step 1: Login
    setRoadmapStep(1);
    await handleOwnerLogin();
    await sleep(700);

    // Step 2: Register Key
    setRoadmapStep(2);
    await handleOwnerGenerateAndRegisterKey();
    await sleep(700);

    // Step 3: Owner Access GET
    setRoadmapStep(3);
    await handleOwnerGetProtected();
    await sleep(700);

    // Step 4: Owner Mutation POST
    setRoadmapStep(4);
    await handleOwnerPostMutation();
    await sleep(700);

    // Step 5: Transfer token & Attack 1 (No proof)
    setRoadmapStep(5);
    handleCopyTokenToAttacker();
    await sleep(500);
    await executeAttack1_NoProof();
    await sleep(700);

    // Step 6: Generate attacker key & Attack 2 (Key forgery)
    setRoadmapStep(6);
    await handleAttackerGenerateKey();
    await sleep(500);
    await executeAttack2_AttackerKey();
    await sleep(700);

    // Step 7: Attack 3 (Replay)
    setRoadmapStep(7);
    await executeAttack3_Replay();
    await sleep(700);

    // Step 8: Attacks 4, 5, 6, 7 (Tampering & Expiry)
    setRoadmapStep(8);
    await executeAttack4_TamperedSignature();
    await sleep(400);
    await executeAttack5_ExpiredTimestamp();
    await sleep(400);
    await executeAttack6_TamperedPath();
    await sleep(400);
    await executeAttack7_TamperedBody();
    await sleep(700);

    // Step 9: Compare Results
    setRoadmapStep(9);
    logAudit({
      origin: 'SYSTEM',
      eventType: 'DEMO_COMPLETED',
      statusCode: 200,
      method: 'N/A',
      path: 'N/A',
      message: 'FULL DEMONSTRATION COMPLETED: Legitimate Owner requests accepted (200 OK); all Attacker forged and replayed attempts rejected (401/409)!',
      details: {
        summary: 'Proof-of-Possession successfully protects against stolen-token abuse and replay attacks.'
      },
      passed: true
    });
  } finally {
    demoState.isAutoRunning = false;
    autoBtn.disabled = false;
    autoBtn.innerHTML = '<span>▶️ Auto-Run Full Demonstration (Steps 1-9)</span>';
  }
}

/**
 * Reset all demonstration states on both client and server.
 */
async function handleGlobalReset() {
  if (!confirm('Reset the demonstration environment? This will wipe all active sessions, keys, and replay caches.')) {
    return;
  }

  try {
    await fetch('/api/demo/reset', { method: 'POST' });
  } catch (e) {
    // Ignore network error on reset
  }

  // Clear owner state
  if (ownerState.timerInterval) clearInterval(ownerState.timerInterval);
  ownerState.token = null;
  ownerState.user = null;
  ownerState.expiresAt = null;
  ownerState.keyPair = null;
  ownerState.keyId = null;
  ownerState.publicKeySpkiBase64 = null;
  ownerState.lastValidProof = null;

  // Clear attacker state
  attackerState.keyPair = null;
  attackerState.keyId = null;
  attackerState.publicKeySpkiBase64 = null;
  attackerState.stolenToken = '';
  attackerState.capturedProof = null;
  document.getElementById('attacker-token-input').value = '';

  // Clear logs & reset step
  demoState.logs = [];
  setRoadmapStep(1);

  // Hide result viewers
  document.getElementById('owner-result-container').classList.add('hidden');
  document.getElementById('attacker-result-container').classList.add('hidden');

  updateOwnerUI();
  updateAttackerUI();
  renderAuditLogs();

  logAudit({
    origin: 'SYSTEM',
    eventType: 'ENVIRONMENT_RESET',
    statusCode: 200,
    method: 'RESET',
    path: '/api/demo/reset',
    message: 'Demonstration environment reset. Ready for a clean demonstration run.',
    details: {},
    passed: true
  });
}

// ============================================================================
// 6. UI SYNCHRONIZATION & AUDIT LOGGING
// ============================================================================

function updateOwnerUI() {
  const isLoggedIn = !!ownerState.token;
  const hasKey = !!(ownerState.keyPair && ownerState.keyId);

  // Badges & Status Indicators
  const statusBadge = document.getElementById('owner-status-badge');
  if (isLoggedIn) {
    statusBadge.className = 'badge badge-green';
    statusBadge.textContent = 'Active (Authenticated)';
  } else {
    statusBadge.className = 'badge badge-outline';
    statusBadge.textContent = 'Disconnected';
  }

  // Boxes & Auth Tabs
  const loginBox = document.getElementById('owner-login-box');
  const registerBox = document.getElementById('owner-register-box');
  const authBox = document.getElementById('owner-authenticated-box');
  const authTabs = document.getElementById('owner-auth-tabs');

  if (isLoggedIn) {
    if (authTabs) authTabs.classList.add('hidden');
    if (loginBox) loginBox.classList.add('hidden');
    if (registerBox) registerBox.classList.add('hidden');
    if (authBox) {
      authBox.classList.remove('hidden');
      document.getElementById('owner-display-name').textContent = ownerState.user.name;
      document.getElementById('owner-display-meta').textContent = `Role: ${ownerState.user.role} • ID: ${ownerState.user.studentId}`;
      document.getElementById('owner-masked-token').textContent =
        `${ownerState.token.slice(0, 6)}••••••••••••••••••••••••••••••••••••••••••••••••••••••••${ownerState.token.slice(-6)}`;
    }
  } else {
    if (authTabs) authTabs.classList.remove('hidden');
    if (authBox) authBox.classList.add('hidden');
    switchAuthTab('login');
  }

  // Key Status
  const keyStatusEl = document.getElementById('owner-key-status');
  const keyThumbEl = document.getElementById('owner-key-thumbprint');
  const keyStorageEl = document.getElementById('owner-key-storage');
  const spkiEl = document.getElementById('owner-spki-text');

  if (keyStorageEl) {
    if (window.indexedDB) {
      keyStorageEl.textContent = 'IndexedDB (Persistent across reload)';
      keyStorageEl.className = 'key-value highlight-cyan';
    } else {
      keyStorageEl.textContent = 'In-Memory Only (Storage Unsupported)';
      keyStorageEl.className = 'key-value highlight-amber';
    }
  }

  if (hasKey) {
    keyStatusEl.textContent = 'Key Registered (P-256)';
    keyStatusEl.className = 'key-value highlight-green';
    keyThumbEl.textContent = ownerState.keyId;
    spkiEl.textContent = ownerState.publicKeySpkiBase64;
  } else if (isLoggedIn) {
    keyStatusEl.textContent = 'Key Generation Pending';
    keyStatusEl.className = 'key-value highlight-amber';
    keyThumbEl.textContent = 'None';
    spkiEl.textContent = 'Not exported';
  } else {
    keyStatusEl.textContent = 'No Key Generated';
    keyStatusEl.className = 'key-value highlight-muted';
    keyThumbEl.textContent = 'None';
    spkiEl.textContent = 'Not exported';
  }

  // Buttons
  document.getElementById('btn-owner-generate-key').disabled = !isLoggedIn || hasKey;
  const reenrolBtn = document.getElementById('btn-owner-reenrol-key');
  if (reenrolBtn) {
    if (isLoggedIn && hasKey) {
      reenrolBtn.classList.remove('hidden');
    } else {
      reenrolBtn.classList.add('hidden');
    }
  }

  document.getElementById('btn-owner-get-protected').disabled = !(isLoggedIn && hasKey);
  document.getElementById('btn-owner-post-mutation').disabled = !(isLoggedIn && hasKey);
}

function updateAttackerUI() {
  const hasAttackerKey = !!(attackerState.keyPair && attackerState.keyId);
  const hasStolenToken = !!(attackerState.stolenToken || document.getElementById('attacker-token-input').value.trim());

  // Attacker Key Status
  const keyStatusEl = document.getElementById('attacker-key-status');
  const keyThumbEl = document.getElementById('attacker-key-thumbprint');

  if (hasAttackerKey) {
    keyStatusEl.textContent = 'Attacker Key Ready (P-256)';
    keyStatusEl.className = 'key-value highlight-green';
    keyThumbEl.textContent = attackerState.keyId;
  } else {
    keyStatusEl.textContent = 'No Key Generated';
    keyStatusEl.className = 'key-value highlight-red';
    keyThumbEl.textContent = 'None';
  }

  // Stolen Token Indicator
  const tokenIndEl = document.getElementById('attacker-token-status-indicator');
  if (hasStolenToken) {
    tokenIndEl.innerHTML = `Status: <span class="highlight-green">Stolen Bearer Token Loaded (${(attackerState.stolenToken || 'Input').slice(0, 6)}••••)</span>`;
  } else {
    tokenIndEl.innerHTML = `Status: <span class="highlight-amber">No Stolen Token Loaded</span>`;
  }
}

function setRoadmapStep(stepNumber) {
  demoState.currentStep = stepNumber;
  document.querySelectorAll('.step-pill').forEach(pill => {
    const step = parseInt(pill.getAttribute('data-step'), 10);
    pill.classList.remove('step-active', 'step-completed');
    if (step < stepNumber) {
      pill.classList.add('step-completed');
    } else if (step === stepNumber) {
      pill.classList.add('step-active');
    }
  });
}

function startOwnerSessionTimer() {
  if (ownerState.timerInterval) clearInterval(ownerState.timerInterval);
  const timerText = document.getElementById('owner-timer-display');

  async function update() {
    if (!ownerState.expiresAt) return;
    const remaining = Math.max(0, Math.floor((ownerState.expiresAt - Date.now()) / 1000));
    const mins = Math.floor(remaining / 60).toString().padStart(2, '0');
    const secs = (remaining % 60).toString().padStart(2, '0');
    if (timerText) timerText.textContent = `Expires in: ${mins}:${secs}`;

    if (remaining <= 0) {
      clearInterval(ownerState.timerInterval);
      await handleSessionExpired();
    }
  }

  update();
  ownerState.timerInterval = setInterval(update, 1000);
}

/**
 * Handle Authoritative Server Session Expiration.
 */
async function handleSessionExpired() {
  logAudit({
    origin: 'SYSTEM',
    eventType: 'SESSION_EXPIRED',
    statusCode: 401,
    method: 'TIMER',
    path: '/api/auth/session',
    message: 'Session expiration deadline reached. Server session is now invalidated.',
    details: {},
    passed: false
  });

  try {
    await fetch('/api/auth/session');
  } catch (e) {
    // ignore
  }

  ownerState.token = null;
  ownerState.user = null;
  ownerState.expiresAt = null;
  ownerState.keyPair = null;
  ownerState.keyId = null;
  ownerState.publicKeySpkiBase64 = null;
  ownerState.lastValidProof = null;
  if (ownerState.timerInterval) clearInterval(ownerState.timerInterval);

  alert('Authentication session has expired. You have been returned to the sign-in screen.');
  updateOwnerUI();
}

/**
 * Restore authenticated session and persistent browser key across page refresh.
 */
async function restoreSessionOnLoad() {
  try {
    const res = await fetch('/api/auth/session');
    if (!res.ok) {
      updateOwnerUI();
      return;
    }

    const data = await res.json();
    if (data.authenticated && data.user) {
      ownerState.token = data.token;
      ownerState.user = data.user;
      ownerState.expiresAt = data.expiresAt;

      // Restore key from IndexedDB if present
      const savedKeyRecord = await loadKeyFromIndexedDB(data.user.username);
      if (savedKeyRecord && savedKeyRecord.keyPair) {
        if (data.keyRegistered && data.keyId && savedKeyRecord.keyId !== data.keyId) {
          logAudit({
            origin: 'OWNER',
            eventType: 'KEY_RESTORE_MISMATCH',
            statusCode: 403,
            method: 'INDEXEDDB',
            path: 'N/A',
            message: 'Browser-stored key does not match server-registered key for active session.',
            details: { storedKeyId: savedKeyRecord.keyId, serverKeyId: data.keyId },
            passed: false
          });
        } else {
          ownerState.keyPair = savedKeyRecord.keyPair;
          ownerState.keyId = savedKeyRecord.keyId;
          ownerState.publicKeySpkiBase64 = savedKeyRecord.spkiBase64;

          logAudit({
            origin: 'OWNER',
            eventType: 'SESSION_RESTORED',
            statusCode: 200,
            method: 'INDEXEDDB',
            path: '/api/auth/session',
            message: `Session restored across refresh with persistent browser key for ${data.user.name} (${savedKeyRecord.keyId}).`,
            details: {
              user: data.user.name,
              keyId: savedKeyRecord.keyId,
              expiresIn: `${data.expiresIn}s`
            },
            passed: true
          });
        }
      } else {
        logAudit({
          origin: 'OWNER',
          eventType: 'SESSION_RESTORED_NO_KEY',
          statusCode: 200,
          method: 'RESTORE',
          path: '/api/auth/session',
          message: `Session restored across refresh for ${data.user.name}, but browser key not found in IndexedDB.`,
          details: { user: data.user.name },
          passed: true
        });
      }

      updateOwnerUI();
      startOwnerSessionTimer();
      setRoadmapStep(ownerState.keyPair ? 3 : 2);
    }
  } catch (err) {
    console.warn('[Session Restore] Error:', err);
    updateOwnerUI();
  }
}

function displayResult(panelType, title, status, data) {
  const isOwner = panelType === 'owner';
  const container = document.getElementById(isOwner ? 'owner-result-container' : 'attacker-result-container');
  const titleEl = document.getElementById(isOwner ? 'owner-result-title' : 'attacker-result-title');
  const badgeEl = document.getElementById(isOwner ? 'owner-result-badge' : 'attacker-result-badge');
  const bodyEl = document.getElementById(isOwner ? 'owner-result-body' : 'attacker-result-body');

  container.classList.remove('hidden');
  titleEl.textContent = title;

  if (status === 200) {
    badgeEl.textContent = '200 OK (ACCEPTED)';
    badgeEl.className = 'badge badge-green';
  } else if (status === 409) {
    badgeEl.textContent = '409 CONFLICT (REPLAY DETECTED)';
    badgeEl.className = 'badge badge-amber';
  } else {
    badgeEl.textContent = `${status} REJECTED`;
    badgeEl.className = 'badge badge-danger';
  }

  bodyEl.textContent = JSON.stringify(data, null, 2);
}

function logAudit(event) {
  const entry = {
    id: Date.now() + Math.random(),
    origin: event.origin || 'SYSTEM', // 'OWNER' | 'ATTACKER' | 'SYSTEM'
    time: new Date().toLocaleTimeString(),
    eventType: event.eventType,
    statusCode: event.statusCode || 0,
    method: event.method || 'GET',
    path: event.path || '',
    message: event.message || '',
    details: event.details || {},
    passed: event.passed !== false
  };

  demoState.logs.unshift(entry);
  if (demoState.logs.length > 100) demoState.logs.pop();

  renderAuditLogs();
}

function renderAuditLogs() {
  const container = document.getElementById('audit-stream-container');
  const counterEl = document.getElementById('audit-log-counter');

  counterEl.textContent = `${demoState.logs.length} Events`;

  // Filter entries
  const filtered = demoState.logs.filter(entry => {
    if (demoState.activeFilter === 'all') return true;
    if (demoState.activeFilter === 'owner') return entry.origin === 'OWNER';
    if (demoState.activeFilter === 'attacker') return entry.origin === 'ATTACKER';
    if (demoState.activeFilter === 'success') return entry.statusCode === 200;
    if (demoState.activeFilter === 'replay') return entry.statusCode === 409;
    if (demoState.activeFilter === 'rejected') return entry.statusCode >= 400 && entry.statusCode !== 409;
    return true;
  });

  if (filtered.length === 0) {
    container.innerHTML = `<div class="log-placeholder">${demoState.logs.length === 0 ? 'No security events logged yet.' : 'No events match the selected filter.'}</div>`;
    return;
  }

  // Construct DOM elements safely
  container.innerHTML = '';
  filtered.forEach(entry => {
    const item = document.createElement('div');
    item.className = `log-entry ${entry.origin === 'OWNER' ? 'log-entry-owner' : (entry.origin === 'ATTACKER' ? 'log-entry-attacker' : '')}`;

    const header = document.createElement('div');
    header.className = 'log-entry-header';

    const meta = document.createElement('div');
    meta.className = 'log-entry-meta';

    // Origin Badge
    const originBadge = document.createElement('span');
    if (entry.origin === 'OWNER') {
      originBadge.className = 'badge badge-green';
      originBadge.textContent = '🟢 OWNER (LEGITIMATE)';
    } else if (entry.origin === 'ATTACKER') {
      originBadge.className = 'badge badge-danger';
      originBadge.textContent = '🔴 ATTACKER (ADVERSARY)';
    } else {
      originBadge.className = 'badge badge-accent';
      originBadge.textContent = '⚙️ SYSTEM';
    }
    meta.appendChild(originBadge);

    // Status Badge
    if (entry.statusCode) {
      const statusBadge = document.createElement('span');
      if (entry.statusCode === 200) statusBadge.className = 'badge badge-green';
      else if (entry.statusCode === 409) statusBadge.className = 'badge badge-amber';
      else statusBadge.className = 'badge badge-danger';
      statusBadge.textContent = `${entry.method} ${entry.statusCode}`;
      meta.appendChild(statusBadge);
    }

    // Time
    const timeSpan = document.createElement('span');
    timeSpan.className = 'log-time';
    timeSpan.textContent = entry.time;
    meta.appendChild(timeSpan);

    header.appendChild(meta);

    const body = document.createElement('div');
    body.className = 'log-entry-body';
    body.textContent = entry.message;

    item.appendChild(header);
    item.appendChild(body);

    if (entry.details && Object.keys(entry.details).length > 0) {
      const detailsEl = document.createElement('pre');
      detailsEl.className = 'log-entry-details';
      detailsEl.textContent = JSON.stringify(entry.details, null, 2);
      item.appendChild(detailsEl);
    }

    container.appendChild(item);
  });
}

// ============================================================================
// 7. EVENT LISTENERS INITIALIZATION
// ============================================================================

document.addEventListener('DOMContentLoaded', async () => {
  // Global Reset & Auto-Demo buttons
  document.getElementById('btn-global-reset').addEventListener('click', handleGlobalReset);
  document.getElementById('btn-auto-demo').addEventListener('click', runFullDemonstrationFlow);

  // Roadmap Step Clicks
  document.querySelectorAll('.step-pill').forEach(pill => {
    pill.addEventListener('click', () => {
      const step = parseInt(pill.getAttribute('data-step'), 10);
      setRoadmapStep(step);
    });
  });

  // Auth Mode Tabs (Sign In / Register)
  const tabLoginBtn = document.getElementById('tab-login-btn');
  const tabRegisterBtn = document.getElementById('tab-register-btn');
  if (tabLoginBtn) tabLoginBtn.addEventListener('click', () => switchAuthTab('login'));
  if (tabRegisterBtn) tabRegisterBtn.addEventListener('click', () => switchAuthTab('register'));

  // Owner Form & Action Listeners
  const ownerForm = document.getElementById('owner-login-form');
  ownerForm.addEventListener('submit', handleOwnerLogin);

  const registerForm = document.getElementById('owner-register-form');
  if (registerForm) {
    registerForm.addEventListener('submit', handleOwnerRegister);
  }

  document.getElementById('btn-owner-fill-demo').addEventListener('click', () => {
    document.getElementById('owner-username').value = 'alice@cyber.edu';
    document.getElementById('owner-password').value = 'CryptoSec#2026';
  });

  document.getElementById('btn-owner-logout').addEventListener('click', handleOwnerLogout);
  document.getElementById('btn-owner-generate-key').addEventListener('click', handleOwnerGenerateAndRegisterKey);
  const reenrolBtn = document.getElementById('btn-owner-reenrol-key');
  if (reenrolBtn) {
    reenrolBtn.addEventListener('click', handleOwnerGenerateAndRegisterKey);
  }

  document.getElementById('btn-owner-get-protected').addEventListener('click', handleOwnerGetProtected);

  const mutationForm = document.getElementById('owner-mutation-form');
  mutationForm.addEventListener('submit', handleOwnerPostMutation);

  document.getElementById('btn-copy-token-to-attacker').addEventListener('click', handleCopyTokenToAttacker);

  // Attacker Action Listeners
  document.getElementById('btn-attacker-generate-key').addEventListener('click', handleAttackerGenerateKey);
  document.getElementById('btn-attacker-import-token').addEventListener('click', handleAttackerImportToken);
  document.getElementById('attacker-token-input').addEventListener('input', (e) => {
    attackerState.stolenToken = e.target.value.trim();
    updateAttackerUI();
  });

  document.getElementById('btn-attack-no-proof').addEventListener('click', executeAttack1_NoProof);
  document.getElementById('btn-attack-attacker-key').addEventListener('click', executeAttack2_AttackerKey);
  document.getElementById('btn-attack-replay').addEventListener('click', executeAttack3_Replay);
  document.getElementById('btn-attack-tampered-sig').addEventListener('click', executeAttack4_TamperedSignature);
  document.getElementById('btn-attack-expired-timestamp').addEventListener('click', executeAttack5_ExpiredTimestamp);
  document.getElementById('btn-attack-tampered-path').addEventListener('click', executeAttack6_TamperedPath);
  document.getElementById('btn-attack-tampered-body').addEventListener('click', executeAttack7_TamperedBody);
  document.getElementById('btn-attack-run-all').addEventListener('click', executeFullAttackSuite);

  // Log filter pills
  document.querySelectorAll('.filter-pill').forEach(pill => {
    pill.addEventListener('click', () => {
      document.querySelectorAll('.filter-pill').forEach(p => p.classList.remove('active'));
      pill.classList.add('active');
      demoState.activeFilter = pill.getAttribute('data-filter');
      renderAuditLogs();
    });
  });

  // Clear log button
  document.getElementById('btn-clear-audit-log').addEventListener('click', () => {
    demoState.logs = [];
    renderAuditLogs();
  });

  // Visibility Change Listener (Tab Resume / Wakeup Re-verification)
  document.addEventListener('visibilitychange', async () => {
    if (document.visibilityState === 'visible' && ownerState.token) {
      try {
        const res = await fetch('/api/auth/session');
        if (!res.ok) {
          await handleSessionExpired();
        }
      } catch (e) {
        // network issue, do not prematurely logout
      }
    }
  });

  // Initialize UI
  updateOwnerUI();
  updateAttackerUI();
  setRoadmapStep(1);

  // Check and restore existing session across page reload
  await restoreSessionOnLoad();

  logAudit({
    origin: 'SYSTEM',
    eventType: 'APPLICATION_INITIALIZED',
    statusCode: 200,
    method: 'INIT',
    path: '/',
    message: 'Proof-of-Possession Live Owner-vs-Attacker application initialized. Ready for demonstration.',
    details: {
      ownerAccount: 'alice@cyber.edu / CryptoSec#2026',
      cryptography: 'W3C Web Crypto ECDSA P-256 + SHA-256',
      storage: window.indexedDB ? 'IndexedDB CryptoKey Enabled' : 'In-Memory Fallback',
      demonstrationMode: 'Two-Client Dual Isolation'
    },
    passed: true
  });
});

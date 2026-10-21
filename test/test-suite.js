/**
 * Automated Verification & Security Test Suite
 * Proof-of-Possession Authentication & Replay Prevention
 * 
 * Executes full cryptographic workflow using Web Crypto API standards against Express backend.
 * Covers: Valid requests, Replay prevention, Delimiter injection, Body tampering, Key binding,
 * Concurrency atomicity, and Session expiration.
 */

import http from 'node:http';
import crypto from 'node:crypto';
import { app } from '../server.js';

const { subtle } = crypto.webcrypto;

// Helper to run express app on an ephemeral port for testing
function startTestServer() {
  return new Promise((resolve) => {
    const server = http.createServer(app);
    server.listen(0, '127.0.0.1', () => {
      const port = server.address().port;
      resolve({ server, port, baseUrl: `http://127.0.0.1:${port}` });
    });
  });
}

// Helper to make HTTP requests
async function httpRequest(url, options = {}) {
  const parsed = new URL(url);
  const opts = {
    hostname: parsed.hostname,
    port: parsed.port,
    path: parsed.pathname + parsed.search,
    method: options.method || 'GET',
    headers: options.headers || {}
  };

  return new Promise((resolve, reject) => {
    const req = http.request(opts, (res) => {
      let data = '';
      res.on('data', chunk => { data += chunk; });
      res.on('end', () => {
        let json = null;
        try {
          json = JSON.parse(data);
        } catch (e) {
          json = null;
        }
        resolve({
          statusCode: res.statusCode,
          headers: res.headers,
          body: data,
          json
        });
      });
    });

    req.on('error', reject);

    if (options.body) {
      req.write(typeof options.body === 'string' ? options.body : JSON.stringify(options.body));
    }
    req.end();
  });
}

// Helpers for Web Crypto operations in test runner
async function generateTestKeyPair() {
  return await subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true, // extractable for test setup
    ['sign', 'verify']
  );
}

async function exportSpkiBase64(publicKey) {
  const buffer = await subtle.exportKey('spki', publicKey);
  return Buffer.from(buffer).toString('base64');
}

function computeSha256Hex(textOrBuffer) {
  return crypto.createHash('sha256').update(textOrBuffer || '').digest('hex');
}

function buildCanonicalString(method, path, timestamp, nonce, bodyHash) {
  return [
    method.toUpperCase(),
    path,
    timestamp.toString(),
    nonce,
    bodyHash
  ].join('\n');
}

async function signData(canonicalString, privateKey) {
  const data = Buffer.from(canonicalString, 'utf-8');
  const sigBuffer = await subtle.sign(
    { name: 'ECDSA', hash: { name: 'SHA-256' } },
    privateKey,
    data
  );
  return Buffer.from(sigBuffer).toString('base64');
}

// Main test execution runner
async function runAllTests() {
  console.log('===============================================================');
  console.log(' STARTING AUTOMATED SECURITY VERIFICATION TEST SUITE');
  console.log('===============================================================\n');

  const { server, baseUrl } = await startTestServer();
  const testResults = [];

  function record(testName, passed, details = '') {
    testResults.push({ testName, passed, details });
    const mark = passed ? '[\x1b[32mPASS\x1b[0m]' : '[\x1b[31mFAIL\x1b[0m]';
    console.log(`${mark} ${testName} ${details ? '- ' + details : ''}`);
  }

  try {
    // ------------------------------------------------------------------------
    // Check 1: Frontend Static Assets Loading
    // ------------------------------------------------------------------------
    const rootRes = await httpRequest(`${baseUrl}/`);
    const cssRes = await httpRequest(`${baseUrl}/styles.css`);
    const jsRes = await httpRequest(`${baseUrl}/app.js`);
    const staticPass = rootRes.statusCode === 200 &&
                       cssRes.statusCode === 200 &&
                       jsRes.statusCode === 200 &&
                       rootRes.body.includes('Web Crypto API Proof-of-Possession');
    record('1. Frontend Static Assets Loading', staticPass, `index.html, styles.css, app.js HTTP 200`);

    // ------------------------------------------------------------------------
    // Check 2: Demo Authentication Login Flow
    // ------------------------------------------------------------------------
    const loginRes = await httpRequest(`${baseUrl}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: 'alice@cyber.edu', password: 'CryptoSec#2026' })
    });

    const loginPass = loginRes.statusCode === 200 &&
                      loginRes.json?.success === true &&
                      typeof loginRes.json?.token === 'string' &&
                      loginRes.json.token.length === 64; // 32 bytes hex = 64 chars
    record('2. User Login & Token Issuance', loginPass, `Token received (length: ${loginRes.json?.token?.length})`);

    const bearerToken = loginRes.json.token;

    // ------------------------------------------------------------------------
    // Check 3: Protected Request Fails Before Key Registration
    // ------------------------------------------------------------------------
    const preRegRes = await httpRequest(`${baseUrl}/api/protected`, {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${bearerToken}`,
        'X-PoP-Timestamp': Date.now().toString(),
        'X-PoP-Nonce': crypto.randomBytes(16).toString('hex'),
        'X-PoP-Signature': Buffer.alloc(64).toString('base64')
      }
    });
    const preRegPass = preRegRes.statusCode === 403 && preRegRes.json?.code === 'KEY_NOT_REGISTERED';
    record('3. Token-Binding Enforcement (No Key Registered)', preRegPass, `HTTP 403 KEY_NOT_REGISTERED`);

    // ------------------------------------------------------------------------
    // Check 4: Key Registration Without Bearer Token Fails
    // ------------------------------------------------------------------------
    const clientKeyPair = await generateTestKeyPair();
    const clientSpkiBase64 = await exportSpkiBase64(clientKeyPair.publicKey);

    const unauthRegRes = await httpRequest(`${baseUrl}/api/auth/register-key`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ publicKeySpki: clientSpkiBase64 })
    });
    const unauthRegPass = unauthRegRes.statusCode === 401;
    record('4. Unauthenticated Key Registration Rejected', unauthRegPass, `HTTP ${unauthRegRes.statusCode}`);

    // ------------------------------------------------------------------------
    // Check 5: Client Key Registration & Binding
    // ------------------------------------------------------------------------
    const regRes = await httpRequest(`${baseUrl}/api/auth/register-key`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${bearerToken}`
      },
      body: JSON.stringify({ publicKeySpki: clientSpkiBase64 })
    });

    const regPass = regRes.statusCode === 200 &&
                    regRes.json?.success === true &&
                    regRes.json?.algorithm === 'ECDSA P-256 (prime256v1)' &&
                    typeof regRes.json?.keyId === 'string';
    record('5. Client Key Registration & Binding', regPass, `Key ID: ${regRes.json?.keyId}`);

    // ------------------------------------------------------------------------
    // Check 6: Key Replacement on Active Session Prohibited
    // ------------------------------------------------------------------------
    const rogueKeyPair = await generateTestKeyPair();
    const rogueSpki = await exportSpkiBase64(rogueKeyPair.publicKey);
    const replaceRes = await httpRequest(`${baseUrl}/api/auth/register-key`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${bearerToken}`
      },
      body: JSON.stringify({ publicKeySpki: rogueSpki })
    });
    const replacePass = replaceRes.statusCode === 409 && replaceRes.json?.code === 'KEY_ALREADY_REGISTERED';
    record('6. Key Replacement Attack Prohibited', replacePass, `HTTP 409 KEY_ALREADY_REGISTERED`);

    // ------------------------------------------------------------------------
    // TEST A: Valid Signed Request (GET /api/protected)
    // ------------------------------------------------------------------------
    const timestampA = Date.now().toString();
    const nonceA = crypto.randomBytes(16).toString('hex');
    const bodyHashA = computeSha256Hex('');
    const canonicalA = buildCanonicalString('GET', '/api/protected', timestampA, nonceA, bodyHashA);
    const signatureA = await signData(canonicalA, clientKeyPair.privateKey);

    const testARes = await httpRequest(`${baseUrl}/api/protected`, {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${bearerToken}`,
        'X-PoP-Timestamp': timestampA,
        'X-PoP-Nonce': nonceA,
        'X-PoP-Signature': signatureA
      }
    });

    const testAPass = testARes.statusCode === 200 && testARes.json?.status === 'SUCCESS';
    record('TEST A: Valid Signed Request', testAPass, `HTTP ${testARes.statusCode} - Access granted`);

    // ------------------------------------------------------------------------
    // TEST B: Token Without Signed Proof Headers
    // ------------------------------------------------------------------------
    const testBRes = await httpRequest(`${baseUrl}/api/protected`, {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${bearerToken}`
      }
    });

    const testBPass = testBRes.statusCode === 401 && testBRes.json?.code === 'MISSING_PROOF';
    record('TEST B: Missing Proof Headers', testBPass, `HTTP ${testBRes.statusCode} - Blocked: ${testBRes.json?.error}`);

    // ------------------------------------------------------------------------
    // TEST C: Invalid Cryptographic Signature
    // ------------------------------------------------------------------------
    const timestampC = Date.now().toString();
    const nonceC = crypto.randomBytes(16).toString('hex');
    const canonicalC = buildCanonicalString('GET', '/api/protected', timestampC, nonceC, bodyHashA);
    const realSigC = await signData(canonicalC, clientKeyPair.privateKey);
    // Corrupt signature buffer
    const sigBuf = Buffer.from(realSigC, 'base64');
    sigBuf[0] = sigBuf[0] ^ 0xFF; // Flip byte 0
    const tamperedSigC = sigBuf.toString('base64');

    const testCRes = await httpRequest(`${baseUrl}/api/protected`, {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${bearerToken}`,
        'X-PoP-Timestamp': timestampC,
        'X-PoP-Nonce': nonceC,
        'X-PoP-Signature': tamperedSigC
      }
    });

    const testCPass = testCRes.statusCode === 401 && testCRes.json?.code === 'SIGNATURE_INVALID';
    record('TEST C: Invalid Signature', testCPass, `HTTP ${testCRes.statusCode} - Detected signature mismatch`);

    // ------------------------------------------------------------------------
    // TEST C2: Stolen Token Signed With Attacker's Independent Private Key
    // Attacker possesses the legitimate bearer token, but attempts to forge
    // the signature using their own independent ECDSA key pair.
    // ------------------------------------------------------------------------
    const attackerKeyPair = await generateTestKeyPair();
    const timestampC2 = Date.now().toString();
    const nonceC2 = crypto.randomBytes(16).toString('hex');
    const canonicalC2 = buildCanonicalString('GET', '/api/protected', timestampC2, nonceC2, bodyHashA);
    // Attacker signs using ATTACKER private key
    const attackerSig = await signData(canonicalC2, attackerKeyPair.privateKey);

    const testC2Res = await httpRequest(`${baseUrl}/api/protected`, {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${bearerToken}`,
        'X-PoP-Timestamp': timestampC2,
        'X-PoP-Nonce': nonceC2,
        'X-PoP-Signature': attackerSig
      }
    });

    const testC2Pass = testC2Res.statusCode === 401 && testC2Res.json?.code === 'SIGNATURE_INVALID';
    record('TEST C2: Stolen Token with Attacker Key Rejected', testC2Pass, `HTTP ${testC2Res.statusCode} - Attacker key signature rejected against owner session`);

    // ------------------------------------------------------------------------
    // TEST D: Replay Attack (Send Valid, then Replay Exact Same Headers)
    // ------------------------------------------------------------------------
    const timestampD = Date.now().toString();
    const nonceD = crypto.randomBytes(16).toString('hex');
    const canonicalD = buildCanonicalString('GET', '/api/protected', timestampD, nonceD, bodyHashA);
    const signatureD = await signData(canonicalD, clientKeyPair.privateKey);

    const replayHeaders = {
      'Authorization': `Bearer ${bearerToken}`,
      'X-PoP-Timestamp': timestampD,
      'X-PoP-Nonce': nonceD,
      'X-PoP-Signature': signatureD
    };

    // First attempt: must succeed
    const firstAttempt = await httpRequest(`${baseUrl}/api/protected`, {
      method: 'GET',
      headers: replayHeaders
    });

    // Replay attempt: exact same nonce and signature
    const replayAttempt = await httpRequest(`${baseUrl}/api/protected`, {
      method: 'GET',
      headers: replayHeaders
    });

    const testDPass = firstAttempt.statusCode === 200 &&
                      replayAttempt.statusCode === 409 &&
                      replayAttempt.json?.code === 'REPLAY_DETECTED';
    record('TEST D: Replay Attack Prevention', testDPass, `1st HTTP ${firstAttempt.statusCode} OK -> 2nd HTTP ${replayAttempt.statusCode} REPLAY DETECTED`);

    // ------------------------------------------------------------------------
    // TEST E: Expired Proof Timestamp (> 60 seconds old)
    // ------------------------------------------------------------------------
    const expiredTimestamp = (Date.now() - 120000).toString(); // 2 minutes ago
    const nonceE = crypto.randomBytes(16).toString('hex');
    const canonicalE = buildCanonicalString('GET', '/api/protected', expiredTimestamp, nonceE, bodyHashA);
    const signatureE = await signData(canonicalE, clientKeyPair.privateKey);

    const testERes = await httpRequest(`${baseUrl}/api/protected`, {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${bearerToken}`,
        'X-PoP-Timestamp': expiredTimestamp,
        'X-PoP-Nonce': nonceE,
        'X-PoP-Signature': signatureE
      }
    });

    const testEPass = testERes.statusCode === 401 && testERes.json?.code === 'EXPIRED_PROOF';
    record('TEST E: Expired Proof Timestamp', testEPass, `HTTP ${testERes.statusCode} - Expired timestamp rejected`);

    // ------------------------------------------------------------------------
    // TEST F: Modified Request / Tampered Path Binding
    // ------------------------------------------------------------------------
    const timestampF = Date.now().toString();
    const nonceF = crypto.randomBytes(16).toString('hex');
    // Signed for '/api/protected'
    const canonicalF = buildCanonicalString('GET', '/api/protected', timestampF, nonceF, bodyHashA);
    const signatureF = await signData(canonicalF, clientKeyPair.privateKey);

    // Request actually sent to '/api/protected?tampered_param=true'
    const testFRes = await httpRequest(`${baseUrl}/api/protected?tampered_param=true`, {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${bearerToken}`,
        'X-PoP-Timestamp': timestampF,
        'X-PoP-Nonce': nonceF,
        'X-PoP-Signature': signatureF
      }
    });

    const testFPass = testFRes.statusCode === 401 && testFRes.json?.code === 'SIGNATURE_INVALID';
    record('TEST F: Tampered Request Binding', testFPass, `HTTP ${testFRes.statusCode} - Path alteration detected`);

    // ------------------------------------------------------------------------
    // TEST G1: Invalid or Unknown Bearer Token
    // ------------------------------------------------------------------------
    const timestampG = Date.now().toString();
    const nonceG = crypto.randomBytes(16).toString('hex');
    const canonicalG = buildCanonicalString('GET', '/api/protected', timestampG, nonceG, bodyHashA);
    const signatureG = await signData(canonicalG, clientKeyPair.privateKey);

    const testGRes = await httpRequest(`${baseUrl}/api/protected`, {
      method: 'GET',
      headers: {
        'Authorization': 'Bearer deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef',
        'X-PoP-Timestamp': timestampG,
        'X-PoP-Nonce': nonceG,
        'X-PoP-Signature': signatureG
      }
    });

    const testGPass = testGRes.statusCode === 401 && testGRes.json?.code === 'INVALID_TOKEN';
    record('TEST G1: Invalid Bearer Token', testGPass, `HTTP ${testGRes.statusCode} - Unrecognized token rejected`);

    // ------------------------------------------------------------------------
    // TEST G2: Expired Bearer Token Rejection
    // ------------------------------------------------------------------------
    // Create an expired session directly or test expired token response
    const expiredLoginRes = await httpRequest(`${baseUrl}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: 'alice@cyber.edu', password: 'CryptoSec#2026' })
    });
    const expToken = expiredLoginRes.json.token;
    // Register key
    await httpRequest(`${baseUrl}/api/auth/register-key`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${expToken}` },
      body: JSON.stringify({ publicKeySpki: clientSpkiBase64 })
    });

    // Invalidate/expire session by logging out (which removes session from active store)
    await httpRequest(`${baseUrl}/api/auth/logout`, {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${expToken}` }
    });

    const expPoPRes = await httpRequest(`${baseUrl}/api/protected`, {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${expToken}`,
        'X-PoP-Timestamp': Date.now().toString(),
        'X-PoP-Nonce': crypto.randomBytes(16).toString('hex'),
        'X-PoP-Signature': signatureG
      }
    });
    const expPass = expPoPRes.statusCode === 401;
    record('TEST G2: Inactive/Invalidated Token', expPass, `HTTP ${expPoPRes.statusCode} - Inactive token rejected`);

    // ------------------------------------------------------------------------
    // TEST H1: Protected POST Mutation with Request Body Hash Verification
    // ------------------------------------------------------------------------
    const timestampH = Date.now().toString();
    const nonceH = crypto.randomBytes(16).toString('hex');
    const postBody = JSON.stringify({ item: 'Research Data', grade: 'A+' });
    const bodyHashH = computeSha256Hex(postBody);
    const canonicalH = buildCanonicalString('POST', '/api/protected/mutation', timestampH, nonceH, bodyHashH);
    const signatureH = await signData(canonicalH, clientKeyPair.privateKey);

    const testHRes = await httpRequest(`${baseUrl}/api/protected/mutation`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${bearerToken}`,
        'X-PoP-Timestamp': timestampH,
        'X-PoP-Nonce': nonceH,
        'X-PoP-Signature': signatureH
      },
      body: postBody
    });

    const testHPass = testHRes.statusCode === 200 && testHRes.json?.status === 'SUCCESS';
    record('TEST H1: Signed POST Body Verification', testHPass, `HTTP ${testHRes.statusCode} - Body SHA-256 bound and verified`);

    // ------------------------------------------------------------------------
    // TEST H2: Modified Request Body (Body Tampering Detected)
    // ------------------------------------------------------------------------
    const timestampH2 = Date.now().toString();
    const nonceH2 = crypto.randomBytes(16).toString('hex');
    const originalBody = JSON.stringify({ transferAmount: 100 });
    const originalHash = computeSha256Hex(originalBody);
    // Signature created for original body
    const canonicalH2 = buildCanonicalString('POST', '/api/protected/mutation', timestampH2, nonceH2, originalHash);
    const signatureH2 = await signData(canonicalH2, clientKeyPair.privateKey);

    // Attacker modifies body in transit
    const tamperedBody = JSON.stringify({ transferAmount: 99999 });
    const testH2Res = await httpRequest(`${baseUrl}/api/protected/mutation`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${bearerToken}`,
        'X-PoP-Timestamp': timestampH2,
        'X-PoP-Nonce': nonceH2,
        'X-PoP-Signature': signatureH2
      },
      body: tamperedBody
    });

    const testH2Pass = testH2Res.statusCode === 401 && testH2Res.json?.code === 'SIGNATURE_INVALID';
    record('TEST H2: Request Body Tampering Detected', testH2Pass, `HTTP ${testH2Res.statusCode} - Body modification rejected`);

    // ------------------------------------------------------------------------
    // TEST J: Concurrent Duplicate Requests (Atomicity Test)
    // ------------------------------------------------------------------------
    const timestampJ = Date.now().toString();
    const nonceJ = crypto.randomBytes(16).toString('hex');
    const canonicalJ = buildCanonicalString('GET', '/api/protected', timestampJ, nonceJ, bodyHashA);
    const signatureJ = await signData(canonicalJ, clientKeyPair.privateKey);

    const concurrentHeaders = {
      'Authorization': `Bearer ${bearerToken}`,
      'X-PoP-Timestamp': timestampJ,
      'X-PoP-Nonce': nonceJ,
      'X-PoP-Signature': signatureJ
    };

    // Dispatch 5 concurrent requests with the exact same nonce & signature
    const concurrentResponses = await Promise.all([
      httpRequest(`${baseUrl}/api/protected`, { method: 'GET', headers: concurrentHeaders }),
      httpRequest(`${baseUrl}/api/protected`, { method: 'GET', headers: concurrentHeaders }),
      httpRequest(`${baseUrl}/api/protected`, { method: 'GET', headers: concurrentHeaders }),
      httpRequest(`${baseUrl}/api/protected`, { method: 'GET', headers: concurrentHeaders }),
      httpRequest(`${baseUrl}/api/protected`, { method: 'GET', headers: concurrentHeaders })
    ]);

    const successCount = concurrentResponses.filter(r => r.statusCode === 200).length;
    const replayCount = concurrentResponses.filter(r => r.statusCode === 409).length;
    const testJPass = successCount === 1 && replayCount === 4;
    record('TEST J: Concurrent Duplicate Replay Atomicity', testJPass, `${successCount} Accepted (200), ${replayCount} Replay Blocked (409)`);

    // ------------------------------------------------------------------------
    // TEST K: Failed Signature Does Not Consume Nonce
    // ------------------------------------------------------------------------
    const timestampK = Date.now().toString();
    const nonceK = crypto.randomBytes(16).toString('hex');
    const canonicalK = buildCanonicalString('GET', '/api/protected', timestampK, nonceK, bodyHashA);
    const validSignatureK = await signData(canonicalK, clientKeyPair.privateKey);

    // 1st request with corrupted signature
    const badSigBuf = Buffer.from(validSignatureK, 'base64');
    badSigBuf[1] = badSigBuf[1] ^ 0xFF;
    const badSig = badSigBuf.toString('base64');

    const failRes = await httpRequest(`${baseUrl}/api/protected`, {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${bearerToken}`,
        'X-PoP-Timestamp': timestampK,
        'X-PoP-Nonce': nonceK,
        'X-PoP-Signature': badSig
      }
    });

    // 2nd request with the SAME nonce but VALID signature
    const retryRes = await httpRequest(`${baseUrl}/api/protected`, {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${bearerToken}`,
        'X-PoP-Timestamp': timestampK,
        'X-PoP-Nonce': nonceK,
        'X-PoP-Signature': validSignatureK
      }
    });

    const testKPass = failRes.statusCode === 401 && retryRes.statusCode === 200;
    record('TEST K: Failed Verification Does Not Consume Nonce', testKPass, `1st Failed (401) -> 2nd with same nonce Succeeded (200)`);

    // ------------------------------------------------------------------------
    // TEST L: Delimiter Injection Attack (Malformed Nonce / Non-Alphanumeric)
    // ------------------------------------------------------------------------
    const maliciousNonce = `nonce;with:delimiters/and spaces=12345`;
    const injectRes = await httpRequest(`${baseUrl}/api/protected`, {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${bearerToken}`,
        'X-PoP-Timestamp': Date.now().toString(),
        'X-PoP-Nonce': maliciousNonce,
        'X-PoP-Signature': signatureA
      }
    });

    const testLPass = injectRes.statusCode === 400 && injectRes.json?.code === 'MALFORMED_NONCE';
    record('TEST L: Canonical Delimiter Injection Prevented', testLPass, `HTTP ${injectRes.statusCode} MALFORMED_NONCE`);

    // ------------------------------------------------------------------------
    // TEST M: Multi-Session Token-to-Key Association Isolation
    // Verifies that two distinct user sessions remain completely isolated
    // and cannot use each other's keys.
    // ------------------------------------------------------------------------
    // Login as Bob
    const bobLoginRes = await httpRequest(`${baseUrl}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: 'bob@cyber.edu', password: 'CryptoSec#2026' })
    });
    const bobToken = bobLoginRes.json.token;
    const bobKeyPair = await generateTestKeyPair();
    const bobSpki = await exportSpkiBase64(bobKeyPair.publicKey);
    await httpRequest(`${baseUrl}/api/auth/register-key`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${bobToken}` },
      body: JSON.stringify({ publicKeySpki: bobSpki })
    });

    // Bob uses Bob's token + Bob's key -> 200 OK
    const bobTimestamp = Date.now().toString();
    const bobNonce = crypto.randomBytes(16).toString('hex');
    const bobCanonical = buildCanonicalString('GET', '/api/protected', bobTimestamp, bobNonce, bodyHashA);
    const bobSig = await signData(bobCanonical, bobKeyPair.privateKey);
    const bobValidRes = await httpRequest(`${baseUrl}/api/protected`, {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${bobToken}`,
        'X-PoP-Timestamp': bobTimestamp,
        'X-PoP-Nonce': bobNonce,
        'X-PoP-Signature': bobSig
      }
    });

    // Cross-session attempt: Alice's token with Bob's signature
    const crossNonce = crypto.randomBytes(16).toString('hex');
    const crossCanonical = buildCanonicalString('GET', '/api/protected', bobTimestamp, crossNonce, bodyHashA);
    const crossSig = await signData(crossCanonical, bobKeyPair.privateKey); // Signed with Bob's key
    const crossRes = await httpRequest(`${baseUrl}/api/protected`, {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${bearerToken}`, // Alice's token
        'X-PoP-Timestamp': bobTimestamp,
        'X-PoP-Nonce': crossNonce,
        'X-PoP-Signature': crossSig
      }
    });

    const testMPass = bobValidRes.statusCode === 200 && crossRes.statusCode === 401 && crossRes.json?.code === 'SIGNATURE_INVALID';
    record('TEST M: Multi-Session Key Association Isolation', testMPass, `Bob session valid (200), cross-session key misuse rejected (401)`);

    // ------------------------------------------------------------------------
    // TEST I: Educational Comparison Endpoint (Ordinary Bearer)
    // ------------------------------------------------------------------------
    const bearerOnlyRes = await httpRequest(`${baseUrl}/api/vulnerable-bearer`, {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${bearerToken}`
      }
    });

    const testIPass = bearerOnlyRes.statusCode === 200 && bearerOnlyRes.json?.warning !== undefined;
    record('TEST I: Ordinary Bearer Comparison Endpoint', testIPass, `HTTP ${bearerOnlyRes.statusCode} - Demonstrates raw bearer vulnerability`);

    // ========================================================================
    // NEW REGISTRATION, PASSWORD SECURITY & PERSISTENT SESSION TESTS
    // ========================================================================

    // ------------------------------------------------------------------------
    // Check 7: Local Account Registration
    // ------------------------------------------------------------------------
    const testUserEmail = `student_${Date.now()}@cyber.edu`;
    const testUserPassword = 'SecureStudent#2026';

    const accountRegRes = await httpRequest(`${baseUrl}/api/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: testUserEmail,
        password: testUserPassword,
        confirmPassword: testUserPassword
      })
    });

    const accountRegPass = accountRegRes.statusCode === 201 &&
                           accountRegRes.json?.success === true &&
                           accountRegRes.json?.email === testUserEmail;
    record('Check 7: Local Account Registration', accountRegPass, `HTTP 201 Created for ${testUserEmail}`);

    // ------------------------------------------------------------------------
    // Check 8: Duplicate Account Registration Rejected
    // ------------------------------------------------------------------------
    const dupRes = await httpRequest(`${baseUrl}/api/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: testUserEmail,
        password: testUserPassword,
        confirmPassword: testUserPassword
      })
    });

    const dupPass = dupRes.statusCode === 409 && dupRes.json?.code === 'EMAIL_ALREADY_EXISTS';
    record('Check 8: Duplicate Account Registration Rejected', dupPass, `HTTP 409 EMAIL_ALREADY_EXISTS`);

    // ------------------------------------------------------------------------
    // Check 9: Password Policy Enforcement (Weak Password Rejected)
    // ------------------------------------------------------------------------
    const weakRes = await httpRequest(`${baseUrl}/api/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: `weak_${Date.now()}@cyber.edu`,
        password: 'weakpassword',
        confirmPassword: 'weakpassword'
      })
    });

    const weakPass = weakRes.statusCode === 400 && weakRes.json?.code === 'WEAK_PASSWORD';
    record('Check 9: Weak Password Policy Enforcement', weakPass, `HTTP 400 WEAK_PASSWORD (no uppercase/number/symbol)`);

    // ------------------------------------------------------------------------
    // Check 10: Password Confirmation Mismatch Rejected
    // ------------------------------------------------------------------------
    const mismatchRes = await httpRequest(`${baseUrl}/api/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: `mismatch_${Date.now()}@cyber.edu`,
        password: 'StrongPassword#1',
        confirmPassword: 'DifferentPassword#2'
      })
    });

    const mismatchPass = mismatchRes.statusCode === 400 && mismatchRes.json?.code === 'PASSWORD_MISMATCH';
    record('Check 10: Password Confirmation Mismatch Rejected', mismatchPass, `HTTP 400 PASSWORD_MISMATCH`);

    // ------------------------------------------------------------------------
    // Check 11: Invalid Email Syntax Rejected
    // ------------------------------------------------------------------------
    const badEmailRes = await httpRequest(`${baseUrl}/api/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: 'not-an-email-at-all',
        password: 'StrongPassword#1',
        confirmPassword: 'StrongPassword#1'
      })
    });

    const badEmailPass = badEmailRes.statusCode === 400 && badEmailRes.json?.code === 'INVALID_EMAIL_FORMAT';
    record('Check 11: Invalid Email Syntax Rejected', badEmailPass, `HTTP 400 INVALID_EMAIL_FORMAT`);

    // ------------------------------------------------------------------------
    // Check 12: Registered Account Login & HttpOnly Cookie Issuance
    // ------------------------------------------------------------------------
    const regLoginRes = await httpRequest(`${baseUrl}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: testUserEmail,
        password: testUserPassword
      })
    });

    const setCookieHeaders = regLoginRes.headers['set-cookie'] || [];
    const sessionCookieHeader = setCookieHeaders.find(c => c.startsWith('pop_session_id='));
    const regLoginPass = regLoginRes.statusCode === 200 &&
                         regLoginRes.json?.success === true &&
                         sessionCookieHeader !== undefined &&
                         sessionCookieHeader.includes('HttpOnly') &&
                         sessionCookieHeader.includes('SameSite=Lax');
    record('Check 12: Registered Account Login & HttpOnly Cookie', regLoginPass, `HTTP 200 - Cookie: HttpOnly; SameSite=Lax`);

    // Extract cookie value for subsequent requests
    const cookieVal = sessionCookieHeader ? sessionCookieHeader.split(';')[0] : '';

    // ------------------------------------------------------------------------
    // Check 13: Invalid Password Rejection on Registered Account
    // ------------------------------------------------------------------------
    const badPassRes = await httpRequest(`${baseUrl}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: testUserEmail,
        password: 'WrongPassword#999'
      })
    });

    const badPassPass = badPassRes.statusCode === 401;
    record('Check 13: Invalid Password Rejection', badPassPass, `HTTP 401 Unauthorized for incorrect password`);

    // ------------------------------------------------------------------------
    // Check 14: Session Restoration via HttpOnly Cookie (Page Reload Simulation)
    // ------------------------------------------------------------------------
    const sessionStatusRes = await httpRequest(`${baseUrl}/api/auth/session`, {
      method: 'GET',
      headers: {
        'Cookie': cookieVal
      }
    });

    const sessionRestorePass = sessionStatusRes.statusCode === 200 &&
                              sessionStatusRes.json?.authenticated === true &&
                              sessionStatusRes.json?.user?.username === testUserEmail;
    record('Check 14: Refresh Persistence via Cookie', sessionRestorePass, `HTTP 200 - Session restored for ${testUserEmail}`);

    // ------------------------------------------------------------------------
    // Check 15: Cookie Invalidation & Session Revocation on Logout
    // ------------------------------------------------------------------------
    const logoutRes = await httpRequest(`${baseUrl}/api/auth/logout`, {
      method: 'POST',
      headers: {
        'Cookie': cookieVal
      }
    });

    const logoutCookies = logoutRes.headers['set-cookie'] || [];
    const clearedCookie = logoutCookies.find(c => c.startsWith('pop_session_id='));
    const logoutPass = logoutRes.statusCode === 200 &&
                       clearedCookie !== undefined &&
                       clearedCookie.includes('Max-Age=0');
    record('Check 15: Manual Logout & Cookie Invalidation', logoutPass, `HTTP 200 - Cookie cleared with Max-Age=0`);

    // ------------------------------------------------------------------------
    // Check 16: Session Restoration Fails After Logout
    // ------------------------------------------------------------------------
    const postLogoutRes = await httpRequest(`${baseUrl}/api/auth/session`, {
      method: 'GET',
      headers: {
        'Cookie': cookieVal
      }
    });

    const postLogoutPass = postLogoutRes.statusCode === 401 && postLogoutRes.json?.authenticated === false;
    record('Check 16: Session Restoration Fails After Logout', postLogoutPass, `HTTP 401 - Revoked session rejected on reload`);

    // ------------------------------------------------------------------------
    // Check 17: Key Enrollment Association across Sessions (Safe Re-login Binding)
    // ------------------------------------------------------------------------
    const reloginRes = await httpRequest(`${baseUrl}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: testUserEmail, password: testUserPassword })
    });
    const reloginToken = reloginRes.json.token;

    // Enroll key
    const studentKeyPair = await generateTestKeyPair();
    const studentSpki = await exportSpkiBase64(studentKeyPair.publicKey);
    const enrollRes = await httpRequest(`${baseUrl}/api/auth/register-key`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${reloginToken}` },
      body: JSON.stringify({ publicKeySpki: studentSpki })
    });

    // Logout
    await httpRequest(`${baseUrl}/api/auth/logout`, {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${reloginToken}` }
    });

    // Re-login after enrollment
    const reloginRes2 = await httpRequest(`${baseUrl}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: testUserEmail, password: testUserPassword })
    });

    const studentTimestamp = Date.now().toString();
    const studentNonce = crypto.randomBytes(16).toString('hex');
    const studentCanonical = buildCanonicalString('GET', '/api/protected', studentTimestamp, studentNonce, bodyHashA);
    const studentSig = await signData(studentCanonical, studentKeyPair.privateKey);

    const enrolledProtectedRes = await httpRequest(`${baseUrl}/api/protected`, {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${reloginRes2.json.token}`,
        'X-PoP-Timestamp': studentTimestamp,
        'X-PoP-Nonce': studentNonce,
        'X-PoP-Signature': studentSig
      }
    });

    const check17Pass = reloginRes2.json?.keyRegistered === true &&
                        reloginRes2.json?.keyId === enrollRes.json?.keyId &&
                        enrolledProtectedRes.statusCode === 200;
    record('Check 17: Account-Enrolled Key Association across Sessions', check17Pass, `HTTP 200 - Enrolled key linked to new session upon re-login`);

    // ------------------------------------------------------------------------
    // Check 18: Future Timestamp Exceeding Clock Skew Rejected
    // ------------------------------------------------------------------------
    const futureTimestamp = (Date.now() + 30000).toString(); // 30s in future (> 10s skew)
    const futureNonce = crypto.randomBytes(16).toString('hex');
    const futureCanonical = buildCanonicalString('GET', '/api/protected', futureTimestamp, futureNonce, bodyHashA);
    const futureSig = await signData(futureCanonical, clientKeyPair.privateKey);

    const futureRes = await httpRequest(`${baseUrl}/api/protected`, {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${bearerToken}`,
        'X-PoP-Timestamp': futureTimestamp,
        'X-PoP-Nonce': futureNonce,
        'X-PoP-Signature': futureSig
      }
    });
    const futurePass = futureRes.statusCode === 401 && futureRes.json?.code === 'FUTURE_TIMESTAMP';
    record('Check 18: Future Timestamp Outside Skew Rejected', futurePass, `HTTP 401 FUTURE_TIMESTAMP`);

    // ------------------------------------------------------------------------
    // Check 19: Malformed Timestamp Non-Integer Syntax Rejected Safely
    // ------------------------------------------------------------------------
    const malformedTimeRes = await httpRequest(`${baseUrl}/api/protected`, {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${bearerToken}`,
        'X-PoP-Timestamp': 'not-a-timestamp-1234!',
        'X-PoP-Nonce': crypto.randomBytes(16).toString('hex'),
        'X-PoP-Signature': signatureA
      }
    });
    const malformedTimePass = malformedTimeRes.statusCode === 400 && malformedTimeRes.json?.code === 'MALFORMED_TIMESTAMP';
    record('Check 19: Malformed Timestamp Rejected Safely', malformedTimePass, `HTTP 400 MALFORMED_TIMESTAMP`);

    // ------------------------------------------------------------------------
    // Check 20: Malformed Signature Format Handled Without Server Crash
    // ------------------------------------------------------------------------
    const malformedSigRes = await httpRequest(`${baseUrl}/api/protected`, {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${bearerToken}`,
        'X-PoP-Timestamp': Date.now().toString(),
        'X-PoP-Nonce': crypto.randomBytes(16).toString('hex'),
        'X-PoP-Signature': 'short-bad-sig'
      }
    });
    const malformedSigPass = malformedSigRes.statusCode === 401 && malformedSigRes.json?.code === 'INVALID_SIGNATURE_ENCODING';
    record('Check 20: Malformed Signature Rejected Safely', malformedSigPass, `HTTP 401 INVALID_SIGNATURE_ENCODING`);

    // ------------------------------------------------------------------------
    // Check 21: Security Audit Log Events Feed Verification
    // ------------------------------------------------------------------------
    const auditEventsRes = await httpRequest(`${baseUrl}/api/security/events`);
    const auditEventsPass = auditEventsRes.statusCode === 200 &&
                            Array.isArray(auditEventsRes.json?.events) &&
                            auditEventsRes.json.events.length > 0;
    record('Check 21: Security Audit Events Feed Verification', auditEventsPass, `HTTP 200 - Logged ${auditEventsRes.json?.events?.length} audit events`);

  } finally {
    server.close();
  }

  console.log('\n===============================================================');
  const allPassed = testResults.every(r => r.passed);
  if (allPassed) {
    console.log(`\x1b[32mALL ${testResults.length} AUTOMATED SECURITY TESTS PASSED SUCCESSFULLY!\x1b[0m`);
  } else {
    console.log(`\x1b[31mSOME TESTS FAILED! Review details above.\x1b[0m`);
  }
  console.log('===============================================================\n');

  if (!allPassed) {
    process.exit(1);
  }
}

runAllTests().catch(err => {
  console.error('Fatal test error:', err);
  process.exit(1);
});

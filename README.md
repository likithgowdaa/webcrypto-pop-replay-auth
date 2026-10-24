# Web Crypto API-Based Proof-of-Possession Authentication for Replay-Resistant Token Security

**Subject:** Cryptography and Network Security  
**Project Classification:** Undergraduate Capstone / Mini-Project Educational Prototype  
**Environment:** 100% Localhost Execution (Zero Cloud Dependencies & Zero Cost)  
**Demonstration Mode:** Live Side-by-Side Owner vs. Attacker Simulator Dashboard  

---

## 1. Abstract

Modern web applications predominantly authenticate API requests using bearer tokens such as OAuth 2.0 access tokens or JSON Web Tokens (JWTs). However, bearer tokens follow a "possession-equals-authorization" model: any entity holding the token can use it, rendering systems vulnerable to token theft via network eavesdropping, compromised client storage, server log aggregation, or proxy inspection.

This project implements an interactive educational cybersecurity prototype of **Proof-of-Possession (PoP) Authentication** combined with **Cryptographic Replay Attack Prevention**. Built using the native W3C **Browser Web Crypto API** and a **Node.js/Express** backend, the application features an interactive dual-client interface: a legitimate **Owner Client (Alice / Registered Student)** and an independent **Attacker Simulator Client (Mallory)**.

The owner generates a non-extractable asymmetric Elliptic Curve key pair (`ECDSA` over NIST curve `P-256`) in browser memory, persists it securely across page reloads via **IndexedDB**, and registers its public key (`SPKI` format) with an authenticated session managed via **HttpOnly cookies**. For each protected request, the browser generates a deterministic canonical string binding the HTTP verb, target URI, millisecond timestamp, cryptographically random nonce, and body SHA-256 digest, signing it with its private key.

When the bearer token is exfiltrated to the Attacker Simulator, the dashboard demonstrates mathematically why the stolen token is completely useless to an adversary without possession of the owner's private key. The server validates signatures against the session's registered public key, enforces an authoritative timestamp freshness window (60 seconds), tracks unique nonces in an atomic cache to reject replayed and tampered requests, and automatically enforces server-side session expiration.

---

## 2. Problem Statement

In standard web architectures, bearer tokens function like digital hotel keycards:
1. **Token Theft Exploitation:** If an adversary intercepts or steals a bearer token, they can replay it from any device or IP address without restriction.
2. **Lack of Cryptographic Channel Binding:** The server cannot verify whether the sender of the token is the legitimate client to whom the token was originally issued.
3. **Susceptibility to Replay Attacks:** Without request freshness guarantees and single-use nonces, captured requests can be re-transmitted maliciously to trigger unintended duplicate actions.
4. **Vulnerability Comparison:** On unhardened bearer endpoints (`/api/vulnerable-bearer`), a stolen token grants full unauthorized access; on PoP-hardened endpoints (`/api/protected`), the stolen token is blocked.

---

## 3. Technology Stack

- **Frontend:**
  - HTML5 & CSS3 (Custom Dark Navy/Charcoal Theme, Emerald Owner vs. Crimson Attacker Layout)
  - Vanilla JavaScript (ECMAScript 2022, zero client-side frameworks or bundling tools)
  - W3C Web Crypto API (`window.crypto.subtle`) for ECDSA key generation, signing, and SHA-256 hashing
  - IndexedDB for persistent browser-held `CryptoKey` storage across page refreshes
- **Backend:**
  - Node.js (v18+ / v20+ / v24+)
  - Express.js (Minimalist HTTP server & static file host)
  - Native Node.js `node:crypto` module for CSPRNG, public key parsing, IEEE P1363 signature verification, and **scrypt password hashing** with random salts
- **Cryptography Standards:**
  - Algorithm: ECDSA (Elliptic Curve Digital Signature Algorithm)
  - Elliptic Curve: NIST P-256 / secp256r1 / prime256v1
  - Hash Function: SHA-256 (FIPS PUB 180-4)
  - Password Hash: scrypt (`N=16384, r=8, p=1`, 64-byte key)
  - Key Encoding: SubjectPublicKeyInfo (SPKI) DER / Base64
  - Signature Format: IEEE P1363 (64-byte raw `r || s`)
- **Storage:**
  - In-memory data structures (`Map`) for sessions, registered users, replay cache, and audit events.
  - Zero database required; 100% self-contained on localhost.

---

## 4. System Architecture: Owner vs. Attacker Model

```
+-------------------------------------------------------------------------------------------------------------+
|                                              CLIENT BROWSER                                                 |
|                                                                                                             |
|  +--------------------------------------------+            +---------------------------------------------+  |
|  |           OWNER CLIENT (Alice)             |            |      ATTACKER SIMULATOR (Mallory)           |  |
|  | - Authenticates with credentials           |            | - Operates with independent client state    |  |
|  | - HttpOnly Cookie (pop_session_id)         |            | - Receives stolen Bearer Token              |  |
|  | - Holds valid session Bearer Token         |            | - Generates independent ECDSA Key Pair      |  |
|  | - Generates ECDSA P-256 Key Pair           |   TOKEN    | - Executes 7 distinct attack vectors:       |  |
|  |   (extractable: false, in IndexedDB)       |  EXFIL     |   1. Token only (no PoP proof)              |  |
|  | - Registers SPKI Public Key with Server    | ---------> |   2. Forged signature with attacker key     |  |
|  | - Signs canonical requests with           |            |   3. Exact replay of captured proof         |  |
|  |   Private Key                              |            |   4. Tampered signature bytes               |  |
|  | - Survives page reload via IndexedDB       |            |   5. Expired timestamp proof                |  |
|  | - GET /api/protected (200 OK)              |            |   6. Tampered request path                  |  |
|  | - POST /api/protected/mutation (200 OK)    |            |   7. Tampered request payload body          |  |
|  +---------------------+----------------------+            |   (Never accesses Owner's private key)      |  |
|                        |                                   +----------------------+----------------------+  |
|                        |                                                          |                         |
|                        |  Valid Signed Request                                    | Attack Requests         |
|                        |  (Token + Signature)                                     | (Exploits & Replays)    |
|                        v                                                          v                         |
+-------------------------------------------------------------------------------------------------------------+
                                                 |
                                     HTTP Requests to Express API
                                                 |
+------------------------------------------------v------------------------------------------------------------+
|                                           NODE.JS SERVER                                                    |
|                                                                                                             |
|   1. Authenticate via Bearer Token or HttpOnly Cookie (Active & Unexpired)                                  |
|   2. Check Registered Public Key for Session                                                                |
|   3. Freshness Check: Server Time - 60s <= X-PoP-Timestamp <= Server Time + 10s                             |
|   4. Replay Check: Verify `sessionKeyId:nonce` is NOT present in Replay Cache                               |
|   5. Canonicalize Request: METHOD\nPATH\nTIMESTAMP\nNONCE\nBODY_SHA256_HEX                                  |
|   6. Verify Digital Signature: `crypto.verify(null, canonical, registeredPublicKey, signature)`             |
|   7. Atomic Insertion: Add `sessionKeyId:nonce` to Replay Cache (TTL = 60s)                                 |
|   8. Outcome:                                                                                               |
|      - Legitimate Owner Request  ===> 200 OK (Confidential Record Returned)                                 |
|      - Attacker Token Only       ===> 401 Unauthorized (MISSING_PROOF)                                      |
|      - Attacker Forged Key       ===> 401 Unauthorized (SIGNATURE_INVALID: Key mismatch!)                   |
|      - Replayed Captured Proof   ===> 409 Conflict (REPLAY_DETECTED: Nonce already consumed!)               |
|      - Tampered Path/Payload     ===> 401 Unauthorized (SIGNATURE_INVALID: Canonical hash mismatch!)        |
+-------------------------------------------------------------------------------------------------------------+
```

---

## 5. Local Account Registration vs. Google Authentication

The application features local account registration:
- **Email Address as Identifier:** Users can register using any email address (e.g., `alice@cyber.edu` or a personal Gmail address).
- **IMPORTANT CLARIFICATION:** Entering a Gmail address creates a **local account** in the application's user database. It is **NOT** Google OAuth, Google Sign-In, or inbox verification. It does not send verification emails or contact Google servers.
- **Password Policy:** Enforces at least 8 characters, at least 1 uppercase letter, 1 lowercase letter, 1 digit, and 1 special symbol (`!@#$%^&*`).
- **Cryptographic Storage:** Passwords are never stored in plaintext. They are hashed using **Node.js `crypto.scrypt`** with unique 16-byte cryptographically secure random salts. Plaintext passwords and hashes are never logged or exposed in API responses.

---

## 6. Server-Managed Sessions & Refresh Persistence

### 6.1 HttpOnly Session Cookies
Upon login, the server establishes a session and issues an `HttpOnly` cookie:
```http
Set-Cookie: pop_session_id=<token>; Path=/; HttpOnly; SameSite=Lax; Max-Age=900
```
- **HttpOnly:** Prevents client-side scripts from reading or exfiltrating the cookie.
- **SameSite=Lax:** Mitigates Cross-Site Request Forgery (CSRF).
- **Development vs. Production:** In development on `localhost` over HTTP, `Secure` is omitted so browsers accept the cookie. In production, `process.env.NODE_ENV === 'production'` enables `Secure;`, requiring HTTPS.

### 6.2 Browser-Held Key Persistence via IndexedDB
- Browsers cannot serialize `CryptoKey` objects into `localStorage`.
- This application uses the W3C **IndexedDB Structured Clone** capability to store the non-extractable (`extractable: false`) ECDSA P-256 private key and public key under the user's account name.
- **On Page Reload:**
  1. The browser calls `GET /api/auth/session` (sending the `pop_session_id` cookie automatically).
  2. If the session is valid, the client retrieves the enrolled `CryptoKey` from IndexedDB.
  3. The client computes the public key thumbprint and verifies it matches the server's registered `keyId`.
  4. The authenticated Owner dashboard is restored without needing to re-login or re-register keys!

---

## 7. Session Expiration & Automatic Logout

- **Configurable Lifetime:** Server default is 15 minutes (`900` seconds), configurable via `SESSION_LIFETIME_MS`.
- **Authoritative Server Expiration:** The server computes `expiresAt = Date.now() + TOKEN_LIFETIME_MS` upon session creation. Every endpoint independently rejects expired sessions with `401 EXPIRED_TOKEN`.
- **Live Countdown Display:** The Owner dashboard displays a live countdown derived directly from `expiresAt`.
- **Automatic Logout:** When the countdown reaches 0:
  1. The frontend queries `GET /api/auth/session` to confirm server-side expiry.
  2. In-memory tokens and keys are purged.
  3. The user is returned to the sign-in screen with an alert notification.
- **Tab Resume / Sleep Handling:** When the user switches back to an inactive browser tab (`visibilitychange`), the client immediately re-verifies session status with the server.

---

## 8. Manual Logout & Server-Side Revocation

Clicking **"Sign Out"** in the Owner panel:
1. Sends `POST /api/auth/logout`.
2. The server deletes the session from the active `sessions` Map.
3. The server clears the cookie via `Set-Cookie: pop_session_id=; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT`.
4. In-memory owner state and countdown intervals are cleared.
5. Any subsequent request presenting that session token or cookie is rejected (**401 `INVALID_TOKEN`**).
6. **Isolation:** The Attacker Simulator's independent state is preserved so instructors can demonstrate that revoking Alice's session also renders the stolen token completely useless!

---

## 9. Deterministic Canonicalization Specification

To guarantee that the client and server compute signatures over identical byte sequences, both sides format the request into a canonical string:

```
METHOD\n
PATH\n
TIMESTAMP\n
NONCE\n
BODY_SHA256_HEX
```

### Field Definitions:
- `METHOD`: Uppercase HTTP verb (e.g., `GET`, `POST`).
- `PATH`: Exact request path including query parameters (e.g., `/api/protected` or `/api/protected/mutation`).
- `TIMESTAMP`: Millisecond Unix epoch integer string (e.g., `1771234567890`).
- `NONCE`: 32-character hexadecimal string generated via CSPRNG (`^[A-Za-z0-9_-]{16,128}$`).
- `BODY_SHA256_HEX`: Lowercase hexadecimal SHA-256 digest of the raw request payload. If the request has no body (such as a standard GET), the SHA-256 digest of an empty string is used (`e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`).

---

## 10. Installation & Startup Instructions

### Prerequisites
- Node.js v18.0.0 or higher
- npm v9.0.0 or higher

### Step 1: Open the Project Directory
```powershell
cd d:\Downloads\Cryptography
```

### Step 2: Install Dependencies
```powershell
npm install
```
*(Dependencies: only `express`)*

### Step 3: Run the Application
```powershell
npm start
```

### Step 4: Access the Dashboard
Open your web browser and navigate to:
```
http://localhost:3000
```

---

## 11. Demonstration Credentials

> **Notice:** These credentials are for educational prototype demonstration on localhost only.

| Role | Username / Email | Password | Description |
| :--- | :--- | :--- | :--- |
| **Authorized Owner** | `alice@cyber.edu` | `CryptoSec#2026` | Pre-configured demo account with scrypt password hashing. |
| **Authorized Peer** | `bob@cyber.edu` | `CryptoSec#2026` | Secondary account for multi-session cross-token isolation tests. |
| **New Local User** | *(Register via UI)* | *(Min 8 chars, mixed)* | Create any local account using the "Register New Account" tab. |

*A one-click **"Autofill Demo Account"** button is provided in the web interface for convenience.*

---

## 12. Automated Security Test Suite (37 Tests)

The application includes an automated test script (`npm test`) exercising 37 distinct verification scenarios:

```powershell
npm test
```

### Test Coverage Table:

| Test # | Identifier | Scenario Description | Target Endpoint | Expected Status | Security Invariant Verified |
| :---: | :--- | :--- | :--- | :---: | :--- |
| 1 | **Check 1** | Static Assets Availability | `GET /`, `/styles.css`, `/app.js` | **200 OK** | Frontend UI assets serve correctly. |
| 2 | **Check 2** | Owner Authentication & Token Issuance | `POST /api/auth/login` | **200 OK** | 256-bit CSPRNG bearer token issued. |
| 3 | **Check 3** | Pre-Registration Binding Defense | `GET /api/protected` | **403 Forbidden** | Protected resource inaccessible before key registration (`KEY_NOT_REGISTERED`). |
| 4 | **Check 4** | Unauthenticated Key Registration Attempt | `POST /api/auth/register-key` | **401 Unauthorized** | Public key cannot be registered without active session token. |
| 5 | **Check 5** | Public Key Registration | `POST /api/auth/register-key` | **200 OK** | Client ECDSA P-256 SPKI public key bound to session. |
| 6 | **Check 6** | Key Replacement Prohibition | `POST /api/auth/register-key` | **409 Conflict** | Session key cannot be overwritten or replaced once registered (`KEY_ALREADY_REGISTERED`). |
| 7 | **Test A** | Legitimate Owner Signed GET Request | `GET /api/protected` | **200 OK** | Valid token + valid signature + fresh timestamp + unique nonce succeeds. |
| 8 | **Test B** | Token Theft: Missing PoP Proof | `GET /api/protected` | **401 Unauthorized** | Stolen token alone without PoP headers is rejected (`MISSING_PROOF`). |
| 9 | **Test C** | Tampered Signature Verification | `GET /api/protected` | **401 Unauthorized** | Corrupted signature bytes rejected (`SIGNATURE_INVALID`). |
| 10 | **Test C2** | Stolen Token with Attacker's Independent Key | `GET /api/protected` | **401 Unauthorized** | Signature created with attacker's private key fails verification against owner's registered public key (`SIGNATURE_INVALID`). |
| 11 | **Test D** | Exact Replay Attack Detection | `GET /api/protected` | **409 Conflict** | Intercepted proof resubmitted is rejected; duplicate nonce detected (`REPLAY_DETECTED`). |
| 12 | **Test E** | Expired Proof Freshness Window | `GET /api/protected` | **401 Unauthorized** | Timestamp older than 60s rejected (`EXPIRED_PROOF`). |
| 13 | **Test F** | Tampered Request Path Binding | `GET /api/protected?tampered=true` | **401 Unauthorized** | Proof signed for path A cannot be reused on path B (`SIGNATURE_INVALID`). |
| 14 | **Test G1** | Forged / Unknown Bearer Token | `GET /api/protected` | **401 Unauthorized** | Unknown bearer token rejected (`INVALID_TOKEN`). |
| 15 | **Test G2** | Inactive Session Token (Post-Logout) | `GET /api/protected` | **401 Unauthorized** | Invalidated bearer token rejected (`INVALID_TOKEN`). |
| 16 | **Test H1** | Legitimate Signed POST Mutation | `POST /api/protected/mutation` | **200 OK** | SHA-256 body hash matches payload; mutation accepted. |
| 17 | **Test H2** | Tampered Request Body Payload | `POST /api/protected/mutation` | **401 Unauthorized** | Modified payload alters body hash, failing signature verification (`SIGNATURE_INVALID`). |
| 18 | **Test J** | High-Concurrency Atomic Replay Race (5x) | `GET /api/protected` | **1x 200, 4x 409** | 5 concurrent identical requests yield exactly 1 success and 4 replay rejections. |
| 19 | **Test K** | Nonce Conservation on Verification Failure | `GET /api/protected` | **1st 401, 2nd 200** | Failed signature does not burn the nonce; subsequent valid signature with that nonce succeeds. |
| 20 | **Test L** | Delimiter & Injection Nonce Defense | `GET /api/protected` | **400 Bad Request** | Nonce containing illegal characters rejected by regex validation (`MALFORMED_NONCE`). |
| 21 | **Test M** | Multi-Session Token-to-Key Isolation | `GET /api/protected` | **401 Unauthorized** | Bob cannot use Alice's bearer token signed with Bob's private key (`SIGNATURE_INVALID`). |
| 22 | **Test I** | Unhardened Bearer Baseline Comparison | `GET /api/vulnerable-bearer` | **200 OK** | Standard bearer endpoint accepts stolen token without PoP proof. |
| 23 | **Check 7** | Local Account Registration | `POST /api/auth/register` | **201 Created** | Valid registration with password hashed via scrypt with random salt. |
| 24 | **Check 8** | Duplicate Registration Rejection | `POST /api/auth/register` | **409 Conflict** | Rejects registration with existing email (`EMAIL_ALREADY_EXISTS`). |
| 25 | **Check 9** | Weak Password Policy Enforcement | `POST /api/auth/register` | **400 Bad Request** | Rejects passwords failing length or complexity requirements (`WEAK_PASSWORD`). |
| 26 | **Check 10** | Password Confirmation Mismatch | `POST /api/auth/register` | **400 Bad Request** | Rejects when password and confirmPassword differ (`PASSWORD_MISMATCH`). |
| 27 | **Check 11** | Invalid Email Format Rejection | `POST /api/auth/register` | **400 Bad Request** | Rejects malformed email syntax (`INVALID_EMAIL_FORMAT`). |
| 28 | **Check 12** | Registered Account Login & Cookie Issuance | `POST /api/auth/login` | **200 OK** | Logs in registered user and sets HttpOnly, SameSite=Lax cookie. |
| 29 | **Check 13** | Invalid Password Rejection on Registered Account | `POST /api/auth/login` | **401 Unauthorized** | Verifies scrypt hash and timing-safe comparison on invalid password. |
| 30 | **Check 14** | Refresh Persistence via HttpOnly Cookie | `GET /api/auth/session` | **200 OK** | Simulates page reload; session restored using cookie credentials. |
| 31 | **Check 15** | Cookie Invalidation on Logout | `POST /api/auth/logout` | **200 OK** | Session revoked on server and cookie cleared with `Max-Age=0`. |
| 32 | **Check 16** | Session Restoration Blocked Post-Logout | `GET /api/auth/session` | **401 Unauthorized** | Expired/cleared cookie rejected on subsequent reload. |
| 33 | **Check 17** | Account Key Enrollment Across Sessions | `GET /api/protected` | **200 OK** | Enrolled key preserved for user account and bound upon re-login. |
| 34 | **Check 18** | Future Timestamp Outside Skew Rejected | `GET /api/protected` | **401 Unauthorized** | Timestamps >10s in future rejected (`FUTURE_TIMESTAMP`). |
| 35 | **Check 19** | Malformed Timestamp Non-Integer Rejected | `GET /api/protected` | **400 Bad Request** | Non-numeric or control-character timestamps rejected (`MALFORMED_TIMESTAMP`). |
| 36 | **Check 20** | Malformed Signature Handled Without Server Crash | `GET /api/protected` | **401 Unauthorized** | Truncated or invalid signature strings safely rejected (`INVALID_SIGNATURE_ENCODING`). |
| 37 | **Check 21** | Security Audit Log Feed Verification | `GET /api/security/events` | **200 OK** | Server audit stream endpoint returns chronological security verification logs. |

---

## 13. Step-by-Step Demonstration Instructions

### A. How to Register and Login
1. Open `http://localhost:3000`.
2. In the Owner panel, click **"Register New Account"**.
3. Enter an email (e.g. `student@cyber.edu` or your Gmail address), and password meeting policy (e.g. `StrongPass#2026`).
4. Click **"Register Local Account"**. A success message will appear and switch to the Sign In tab.
5. Click **"Sign In as Owner"** to establish the authenticated session.

### B. How to Verify Refresh Persistence (IndexedDB)
1. After signing in, click **"Generate & Register Owner Key"**.
2. Notice the status displays `IndexedDB (Persistent across reload)` and the thumbprint is displayed.
3. Click **"Execute Signed GET"** — access is granted (**200 OK**).
4. Now **refresh your web browser page** (F5 / Ctrl+R).
5. Notice that you **remain logged in**, the session countdown continues from the server time, and the browser-held cryptographic key is automatically restored from IndexedDB!

### C. How to Verify Automatic Logout
1. Observe the **"Expires in: MM:SS"** countdown.
2. For demonstration, session lifetime can be adjusted via environment variable:
   ```powershell
   $env:SESSION_LIFETIME_MS="10000"; npm start
   ```
   *(Sets lifetime to 10 seconds)*.
3. When the countdown hits `00:00`, an alert notifies you that the session has expired on the server, and the UI cleanly resets to the sign-in form.

### D. How to Demonstrate Live Attacks
1. Click **"⚠️ Copy Stolen Token to Attacker Simulator"**.
2. Run **Attack 1 (No Proof)**: Server rejects stolen token alone with `401 MISSING_PROOF`.
3. Run **Attack 2 (Forged Attacker Key)**: Attacker generates their own key pair and signs the request. Server checks against Alice's public key and rejects with `401 SIGNATURE_INVALID`.
4. Run **Attack 3 (Replay Attack)**: Attacker captures Alice's valid request and resends it. Server detects consumed nonce and rejects with `409 REPLAY_DETECTED`.
5. Run **Attacks 4–7**: Demonstrates rejection of corrupted signatures, expired timestamps (>60s), tampered URL paths, and modified POST payloads.
6. Contrast with `/api/vulnerable-bearer`: Attacker submits stolen token alone; server grants access (**200 OK**), proving why standard bearer tokens are insecure against token theft.

---

## 14. Viva / Oral Examination Questions & Answers

### Q1: What is the primary vulnerability of standard OAuth 2.0 bearer tokens?
**Answer:** Bearer tokens follow a possession-based security model. Any party that obtains the token (via interception, logging, or proxy leakage) can use it to access protected endpoints without proving their identity.

### Q2: How does Proof-of-Possession (PoP) mitigate bearer token theft?
**Answer:** PoP cryptographically binds the bearer token to an asymmetric key pair. The client signs each request using its private key. If an adversary steals only the bearer token, they cannot forge the required digital signature without possessing the client's private key.

### Q3: Why does signing with the attacker's own private key fail?
**Answer:** The server does not verify the signature against whatever public key the client sends during the request. Instead, the server retrieves the public key **registered during Alice's initial authenticated session**. When the server runs `crypto.verify(..., alicesPublicKey, attackersSignature)`, the mathematical relationship between the attacker's signature and Alice's public key evaluates to `false`.

### Q4: How is key persistence implemented without exposing private keys?
**Answer:** The private key is created using Web Crypto API with `extractable: false`, which prevents JavaScript from exporting or inspecting the raw key material. Modern browsers support storing `CryptoKey` objects directly in IndexedDB via structured cloning without serialization into plaintext or strings.

### Q5: What is the difference between HttpOnly cookies and localStorage for session storage?
**Answer:** `localStorage` is accessible to any JavaScript running on the page, making tokens stored there vulnerable to exfiltration via Cross-Site Scripting (XSS). An `HttpOnly` cookie cannot be read by JavaScript, providing transport-level protection for the session credential.

---

## 15. Limitations and Future Improvements

- **Localhost Scope & HTTPS Requirement:** In this development prototype running over HTTP on localhost, the session cookie is configured with `SameSite=Lax` and `HttpOnly`, but `Secure` is conditional. In production, HTTPS is mandatory, and cookies must have the `Secure` flag.
- **In-Memory Storage:** The prototype stores sessions and nonces in memory. In a distributed multi-server environment, replay caches must be coordinated across nodes using a distributed memory store such as Redis or a shared cluster cache.
- **XSS Considerations:** While non-extractable keys prevent an attacker from reading the raw private key bytes, an in-browser Cross-Site Scripting (XSS) vulnerability could still allow a malicious script to instruct `subtle.sign()` to sign unauthorized requests during an active session. Full isolation requires Web Workers or WebAuthn hardware keys.

---

## 16. License & Academic Integrity Notice

This project is developed solely for educational and academic assessment purposes as part of an undergraduate Computer Science / Cybersecurity curriculum. It is intended to run locally on `localhost:3000`.

this project was demonstrated on 23rd october cryptography & N/W security project expo

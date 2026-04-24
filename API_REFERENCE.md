# CatPhish Security API Reference

## Table of Contents
1. [URL Engine API](#url-engine-api)
2. [Storage Manager API](#storage-manager-api)
3. [Crypto Utilities API](#crypto-utilities-api)
4. [Authentication API](#authentication-api)
5. [Error Codes](#error-codes)

---

## URL Engine API

### URLHasher Class

#### Constructor
```javascript
const hasher = new URLHasher(hashPrefixLength = 16);
```

#### Methods

##### `hashURL(url: string): Promise<Object>`
Hash a URL using SHA-256 and return only the prefix for K-anonymity.

```javascript
const result = await hasher.hashURL('https://example.com/page');
// Returns:
{
  prefix: '3d4f1a2b...',        // First N hex chars (sent to backend)
  fullHash: '3d4f1a2b...',       // Complete hash (kept in memory)
  length: 16,                    // Prefix length
  timestamp: 1234567890
}
```

##### `getHashPrefix(url: string): Promise<string>`
Get only the hash prefix from a URL.

```javascript
const prefix = await hasher.getHashPrefix('https://example.com');
// Returns: '3d4f1a2b...'
```

##### `verifyURLPrefix(url: string, expectedPrefix: string): Promise<boolean>`
Verify if a URL matches a hash prefix.

```javascript
const matches = await hasher.verifyURLPrefix('https://example.com', '3d4f1a2b...');
// Returns: true or false
```

##### `clearCache(): void`
Clear the hash cache.

```javascript
hasher.clearCache();
```

##### `getCacheStats(): Object`
Get cache statistics for debugging.

```javascript
const stats = hasher.getCacheStats();
// Returns:
{
  size: 5,                    // Number of cached hashes
  keys: ['hash1', 'hash2'],   // Cached URL hashes
  prefixLength: 16            // Current prefix length
}
```

---

### URLEngine Class

#### Constructor
```javascript
const engine = new URLEngine();
engine.init(urlHasher);  // Initialize with hasher instance
```

#### Methods

##### `analyzeURL(url: string): Promise<Object>`
Perform comprehensive URL analysis with entropy-based detection.

```javascript
const analysis = await engine.analyzeURL('https://suspicious-site.com');
// Returns:
{
  hashPrefix: '3d4f1a2b...',
  timestamp: 1234567890,
  riskFactors: [
    {
      type: 'HIGH_ENTROPY_SUBDOMAIN',
      severity: 'MEDIUM',
      message: 'Subdomain "asd123f" has unusually high entropy (4.7)',
      evidence: 'High entropy may indicate randomly generated subdomains'
    }
  ],
  riskScore: 0.65,            // 0-1 scale
  isPhishingLikely: true      // true if score >= threshold
}
```

**Risk Factor Types:**
- `MALFORMED_URL`: URL is invalid
- `HIGH_ENTROPY_SUBDOMAIN`: Random-looking subdomains
- `EXCESSIVE_HYPHENS`: Too many hyphens in domain
- `INVALID_HYPHEN_POSITION`: Hyphen at start/end of domain
- `HOMOGLYPH_DETECTED`: Character confusion (1 vs l, etc.)
- `IP_BASED_URL`: Direct IP address instead of domain
- `EXCESSIVE_URL_LENGTH`: URL longer than 2048 characters
- `SUSPICIOUS_KEYWORD`: Known phishing keywords in subdomain
- `REDIRECT_PARAMETER`: Redirect/goto parameters in query string

##### `setRiskThreshold(threshold: number): void`
Set the risk threshold (0-1) for phishing detection.

```javascript
engine.setRiskThreshold(0.7);  // Only flag URLs with risk > 0.7
```

##### `clearCache(): void`
Clear the analysis cache.

```javascript
engine.clearCache();
```

##### `getCacheStats(): Object`
Get cache statistics.

```javascript
const stats = engine.getCacheStats();
// Returns: { size: 3, threshold: 0.6 }
```

---

## Storage Manager API

### StorageManager Class

#### Constructor
```javascript
const storageManager = new StorageManager();
```

#### Methods

##### `init(masterKey: CryptoKey): Promise<void>`
Initialize the storage manager with an encryption key.

```javascript
const key = await crypto.subtle.generateKey(
  { name: 'AES-GCM', length: 256 },
  false,
  ['encrypt', 'decrypt']
);

await storageManager.init(key);
```

##### `write(key: string, data: Object, backendSignature?: string): Promise<void>`
Write encrypted data to storage with optional backend signature verification.

```javascript
await storageManager.write(
  'analysis_result',
  { riskScore: 0.7, factors: [...] },
  backendSignature  // Optional: guard condition for data integrity
);
```

**Guard Condition:** If `backendSignature` is provided, it's verified before writing. If verification fails:
- Data is NOT written
- Cache is wiped
- Error is thrown

##### `read(key: string): Promise<Object|null>`
Read and decrypt data from storage.

```javascript
const data = await storageManager.read('analysis_result');
// Returns: { riskScore: 0.7, factors: [...] } or null if not found
```

**Decryption Verification:**
- GCM authentication tag is checked
- If tampering detected:
  - Error is thrown
  - Data is deleted
  - Cache is wiped

##### `delete(key: string): Promise<void>`
Delete data from storage and cache.

```javascript
await storageManager.delete('analysis_result');
```

##### `wipeCache(): Promise<void>`
Wipe all cached data and storage.

```javascript
await storageManager.wipeCache();
```

##### `getCacheStats(): Object`
Get cache statistics.

```javascript
const stats = storageManager.getCacheStats();
// Returns:
{
  isInitialized: true,
  cacheSize: 5,
  keys: ['key1', 'key2', 'key3']
}
```

##### `setSignatureKey(signatureKey: CryptoKey): void`
Set the HMAC key for backend signature verification.

```javascript
storageManager.setSignatureKey(hmacKey);
```

---

## Crypto Utilities API

### Functions

#### `generateEncryptionKey(): Promise<CryptoKey>`
Generate a new AES-256-GCM encryption key.

```javascript
const key = await generateEncryptionKey();
// Key is non-extractable and cannot be exported
```

#### `deriveKeyFromPassword(password: string, salt: Uint8Array): Promise<CryptoKey>`
Derive an encryption key from a password using PBKDF2.

```javascript
const salt = generateSalt();
const key = await deriveKeyFromPassword('user-password', salt);
```

#### `encrypt(key: CryptoKey, plaintext: string): Promise<Object>`
Encrypt data using AES-256-GCM.

```javascript
const encrypted = await encrypt(key, 'sensitive data');
// Returns: { iv, ciphertext, tag, timestamp }
```

#### `decrypt(key: CryptoKey, encrypted: Object): Promise<string>`
Decrypt data using AES-256-GCM with tamper detection.

```javascript
const plaintext = await decrypt(key, encrypted);
// Throws if GCM tag verification fails (data was tampered)
```

#### `sha256Hash(data: string): Promise<string>`
Compute SHA-256 hash of data.

```javascript
const hash = await sha256Hash('some data');
// Returns: hex-encoded hash (64 characters)
```

#### `generateSalt(): Uint8Array`
Generate a random salt for key derivation.

```javascript
const salt = generateSalt();  // 16 bytes
```

#### `verifySignature(key: CryptoKey, data: string, signature: string): Promise<boolean>`
Verify HMAC signature.

```javascript
const isValid = await verifySignature(key, 'data', 'base64-signature');
// Returns: true or false
```

---

## Authentication API

### Backend Endpoints

#### POST /api/auth/register
Register a new user.

**Request:**
```json
{
  "email": "user@example.com",
  "password": "SecurePass@123",
  "role": "user"
}
```

**Response (200 - Always returns 200 to prevent enumeration):**
```json
{
  "success": true,
  "message": "Check your email for verification link"
}
```

**Roles:**
- `user`: End User (default)
- `admin`: Security Admin with elevated permissions

**Password Requirements:**
- Minimum 8 characters
- Maximum 128 characters
- At least one uppercase letter
- At least one lowercase letter
- At least one digit
- At least one special character

---

#### POST /api/auth/login
User login with email and password.

**Request:**
```json
{
  "email": "user@example.com",
  "password": "SecurePass@123"
}
```

**Response (200):**
```json
{
  "success": true,
  "accessToken": "eyJhbGc...",
  "role": "user",
  "expiresIn": 900,
  "message": "Login successful"
}
```

**Response (401):**
```json
{
  "success": false,
  "error": "Invalid email or password"
}
```

**Response (429 - Too Many Attempts):**
```json
{
  "success": false,
  "error": "Too many failed attempts. Please try again later."
}
```

**Account Lockout:**
- Triggered after 5 failed login attempts per IP
- Duration: 15 minutes
- Lockout applies per IP address

---

#### POST /api/auth/verify-email
Verify user email address.

**Request:**
```json
{
  "email": "user@example.com",
  "token": "verification-token-from-email"
}
```

**Response (200):**
```json
{
  "success": true,
  "message": "Email verified successfully"
}
```

---

#### POST /api/auth/refresh
Refresh access token using refresh token.

**Headers:**
```
Authorization: Bearer {accessToken}
Cookie: refreshToken={httpOnly}
```

**Response (200):**
```json
{
  "success": true,
  "accessToken": "new-access-token",
  "expiresIn": 900
}
```

**Note:** 
- Refresh token is rotated (old token invalidated)
- New refresh token returned in httpOnly cookie
- If old token is reused, it signals possible compromise

---

#### POST /api/auth/logout
Logout user and revoke refresh token.

**Headers:**
```
Authorization: Bearer {accessToken}
```

**Response (200):**
```json
{
  "success": true,
  "message": "Logged out successfully"
}
```

---

#### GET /api/auth/me
Get current authenticated user info.

**Headers:**
```
Authorization: Bearer {accessToken}
```

**Response (200):**
```json
{
  "success": true,
  "user": {
    "id": "user-id-123",
    "email": "user@example.com",
    "role": "user"
  }
}
```

---

#### POST /api/auth/change-password
Change user password (authenticated).

**Headers:**
```
Authorization: Bearer {accessToken}
```

**Request:**
```json
{
  "currentPassword": "OldPass@123",
  "newPassword": "NewPass@456"
}
```

**Response (200):**
```json
{
  "success": true,
  "message": "Password changed successfully"
}
```

---

#### POST /api/url-analysis/report
Report URL analysis to backend (requires auth).

**Headers:**
```
Authorization: Bearer {accessToken}
```

**Request:**
```json
{
  "hashPrefix": "3d4f1a2b7c9e...",
  "clientRiskScore": 0.75,
  "riskFactors": [
    {
      "type": "HIGH_ENTROPY_SUBDOMAIN",
      "severity": "MEDIUM"
    }
  ],
  "timestamp": 1234567890
}
```

**Response (200):**
```json
{
  "success": true,
  "threatLevel": "HIGH",
  "signature": "base64-hmac-signature",
  "recommendations": [...]
}
```

**Note:** Full URL is NEVER sent, only hash prefix for K-anonymity.

---

## Token Format

### Access Token (JWT HS256)
```javascript
{
  "alg": "HS256",
  "typ": "JWT"
}
.
{
  "userId": "123",
  "email": "user@example.com",
  "role": "user",
  "type": "access",
  "iat": 1234567890,
  "exp": 1234568790  // 15 minutes later
}
.
{signature}
```

**Expiry:** 15 minutes

**Transmission:** Authorization header
```
Authorization: Bearer {accessToken}
```

---

### Refresh Token (JWT HS256)
```javascript
{
  "alg": "HS256",
  "typ": "JWT"
}
.
{
  "userId": "123",
  "email": "user@example.com",
  "type": "refresh",
  "jti": "unique-token-id",
  "iat": 1234567890,
  "exp": 1234987890  // 7 days later
}
.
{signature}
```

**Expiry:** 7 days

**Transmission:** httpOnly cookie
```
Set-Cookie: refreshToken={token}; HttpOnly; Secure; SameSite=Strict
```

---

## Error Codes

### HTTP Status Codes

| Code | Meaning | Example |
|------|---------|---------|
| 200 | Success | Successful login |
| 400 | Bad Request | Malformed input |
| 401 | Unauthorized | Invalid credentials |
| 403 | Forbidden | Insufficient permissions |
| 429 | Too Many Requests | Rate limit exceeded |
| 500 | Server Error | Database error |

### Security Errors

| Error | Cause | Action |
|-------|-------|--------|
| Invalid email or password | Wrong credentials | Retry with correct credentials |
| Token expired | Access token too old | Use refresh token to get new access token |
| Token has been revoked | Possible compromise detected | Login again |
| Too many failed attempts | Account lockout | Wait 15 minutes and retry |
| Insufficient permissions | User lacks required role | Contact admin |
| CSRF token missing | Missing security token | Retry request |

---

## Example Integration Flow

```javascript
// 1. User Registration
const registerResponse = await fetch('/api/auth/register', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    email: 'user@example.com',
    password: 'SecurePass@123',
    role: 'user'
  })
});

// 2. User Login
const loginResponse = await fetch('/api/auth/login', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    email: 'user@example.com',
    password: 'SecurePass@123'
  }),
  credentials: 'include'  // Include cookies
});

const { accessToken } = await loginResponse.json();

// 3. URL Analysis
const hasher = new URLHasher(16);
const analysis = await urlEngine.analyzeURL(currentTab.url);

// 4. Report to Backend (with access token)
const reportResponse = await fetch('/api/url-analysis/report', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'Authorization': `Bearer ${accessToken}`
  },
  credentials: 'include',
  body: JSON.stringify({
    hashPrefix: analysis.hashPrefix,
    clientRiskScore: analysis.riskScore,
    riskFactors: analysis.riskFactors,
    timestamp: analysis.timestamp
  })
});

// 5. Token Refresh (automatic on token expiry)
const refreshResponse = await fetch('/api/auth/refresh', {
  method: 'POST',
  credentials: 'include'  // Include refresh token cookie
});

// 6. Logout
const logoutResponse = await fetch('/api/auth/logout', {
  method: 'POST',
  headers: {
    'Authorization': `Bearer ${accessToken}`
  },
  credentials: 'include'
});
```

---

## Debugging Tips

### Enable Debug Logging
```javascript
// In console or popup.js:
chrome.runtime.sendMessage({
  type: 'GET_CACHE_STATS'
}, response => {
  console.log('URL Engine Cache:', response.urlEngine);
  console.log('Storage Manager Cache:', response.storageManager);
});
```

### Check Token Claims
```javascript
// Decode JWT payload (client-side only, for debugging):
function decodeToken(token) {
  const parts = token.split('.');
  const payload = JSON.parse(atob(parts[1]));
  return payload;
}

const claims = decodeToken(accessToken);
console.log('Expires at:', new Date(claims.exp * 1000));
```

### Monitor Network Requests
- Open Developer Tools → Network tab
- Look for POST requests to `/api/auth/login` and `/api/url-analysis/report`
- Verify `Authorization` header contains `Bearer {token}`
- Confirm no full URLs in request body (only hash prefix)

---

Last Updated: 2026-04-22
Version: 1.0.0

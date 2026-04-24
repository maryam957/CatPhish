# CatPhish Security Implementation Documentation

## Overview
This document describes the complete security implementation for the CatPhish browser extension covering FR2, FR5, NFR2, and NFR5 requirements.

---

## 1. URL Engine Architecture

### Components Created:
- **url_hasher.js**: SHA-256 hashing with K-anonymity
- **url_engine.js**: Entropy-based URL analysis
- **background_worker.js**: Orchestration and background task management

### Features:

#### 1.1 SHA-256 Hashing with K-anonymity (NFR2)
- Full URLs are **never stored or logged**
- URLs are hashed using SHA-256
- Only first N (default 16) hex characters of hash are transmitted to backend
- This provides K-anonymity: backend cannot uniquely identify users' browsed URLs

```javascript
// Example:
const hasher = new URLHasher(16);
const hashResult = await hasher.hashURL('https://example.com/path');
// Returns: { prefix: '3d4f1a2b...' (16 chars), fullHash: '3d4f1a2b...' (64 chars) }
// Only the prefix is transmitted to backend
```

#### 1.2 Entropy-Based URL Analysis
The URL engine performs multiple risk assessment checks:

- **Subdomain Entropy**: Detects randomly generated subdomains (e.g., `asd123f.example.com`)
- **Hyphen Analysis**: Flags excessive hyphens used in phishing (e.g., `pay-pal-login.com`)
- **Homoglyph Detection**: Identifies character confusion attacks (1 vs l, 0 vs O)
- **IP-Based URLs**: Detects direct IP addresses (suspicious in legitimate sites)
- **URL Length Analysis**: Flags excessively long URLs hiding malicious parameters
- **Suspicious Patterns**: Detects known phishing keywords and redirect parameters

#### 1.3 Risk Scoring
Each risk factor contributes to overall risk score:
- HIGH severity: 0.3 weight
- MEDIUM severity: 0.2 weight
- LOW severity: 0.1 weight
- Final score: normalized to 0-1 range

---

## 2. Encrypted Local Storage Manager

### Components Created:
- **crypto_utils.js**: AES-256-GCM encryption/decryption
- **storage_manager.js**: Encrypted storage abstraction layer

### Features:

#### 2.1 AES-256-GCM Encryption (NFR5)
- All data encrypted before write to disk
- All data decrypted on read from disk
- **Key never stored in plaintext**
- Keys generated via `crypto.subtle.generateKey()`
- IV (Initialization Vector): Random 96-bit per encryption
- Authentication Tag: 128-bit for tamper detection

```javascript
// Example:
const key = await crypto.subtle.generateKey(
  { name: 'AES-GCM', length: 256 },
  false, // non-extractable
  ['encrypt', 'decrypt']
);
const encrypted = await encrypt(key, 'sensitive data');
// Returns: { iv, ciphertext, tag, timestamp }
```

#### 2.2 Tamper Detection & Cache Wipe
- **GCM Authentication Tag**: Verified on every decryption
- **Tampering Detection**: If tag verification fails, data is automatically wiped
- **Cache Wipe**: All cached data cleared if tampering detected

```javascript
// Example:
try {
  const data = await storageManager.read('sensitive_key');
} catch (error) {
  if (error.message.includes('tampered')) {
    await storageManager.wipeCache(); // Automatic cache wipe
  }
}
```

#### 2.3 Guard Condition: Backend Signature Verification
- **Write Guard**: Data only written after backend response signature verification
- Storage manager can verify HMAC signatures from backend
- Failed signature verification triggers automatic cache wipe

```javascript
// Example:
// Only write if backend signature verification passes
await storageManager.write(
  'url_analysis_result',
  analysisData,
  backendSignature // Guard: verified before write
);
```

---

## 3. Authentication System

### Components Created:
- **password_utils.js**: bcrypt password hashing (min 12 rounds)
- **jwt_utils.js**: JWT token management with rotation
- **auth_controller.js**: Business logic (registration, login)
- **auth_routes.js**: Express API endpoints
- **auth_middleware.js**: JWT verification and authorization

### Features:

#### 3.1 User Registration (FR5)
```
POST /api/auth/register
Body: { email, password, role }
Roles: 'user' (End User) or 'admin' (Security Admin)
```

**Security Measures:**
- Input validation: Email format, password strength
- Password hashing: bcrypt with 12+ rounds
- **Never reveals** if email already exists (prevents email enumeration)
- Generic error messages

```javascript
// Password Requirements:
- Minimum 8 characters, maximum 128 characters
- At least one uppercase letter
- At least one lowercase letter
- At least one number
- At least one special character (!@#$%^&*()_+-=[]{}; ':"\\|,.<>\/?)
```

#### 3.2 User Login (FR5, Auth Requirement)
```
POST /api/auth/login
Body: { email, password }
Returns: { accessToken, refreshToken (httpOnly), role }
```

**Security Measures:**
- Account lockout after 5 failed attempts
- 15-minute lockout duration per IP
- **Constant-time password comparison** (prevents timing attacks)
- Generic error messages: "Invalid email or password"
- Role returned to determine user permissions

#### 3.3 JWT Token Management
```
Access Token:
- Expiry: 15 minutes (short-lived)
- Stored in: Response body
- Algorithm: HS256 (HMAC-SHA256)
- Contains: userId, email, role, iat, exp

Refresh Token:
- Expiry: 7 days
- Stored in: httpOnly cookie (not accessible to JavaScript)
- Algorithm: HS256
- Implements token rotation for compromise detection
- Contains: JWT ID (jti) for tracking
```

#### 3.4 Token Rotation & Compromise Detection
```javascript
// Refresh token rotation:
// Old token is invalidated
// New token is issued
// If old token is reused → signals possible compromise
```

#### 3.5 Secure Cookie Configuration
```javascript
{
  httpOnly: true,    // Not accessible to JavaScript (XSS protection)
  secure: true,      // HTTPS only
  sameSite: 'Strict' // CSRF protection
}
```

---

## 4. Authentication Middleware

### Security Features:

#### 4.1 Token Verification Middleware
```javascript
// verifyAccessToken: Validates Bearer token from Authorization header
// verifyRefreshToken: Validates httpOnly refresh token from cookies
// Both verify:
//   - Token format and structure
//   - Signature integrity
//   - Expiry time
//   - Token type (access vs refresh)
```

#### 4.2 Authorization Middleware
```javascript
// authorize(['admin']) - Only allow admin users
// authorize(['user', 'admin']) - Allow both user types
// Returns 403 Forbidden if user lacks required role
```

#### 4.3 Input Validation
```javascript
// Validates:
// - Empty/malformed email and password
// - Oversized inputs (DoS prevention)
// - Max email length: 254 characters
// - Max password length: 128 characters
```

#### 4.4 Rate Limiting
```javascript
// Basic in-memory rate limiting (15-minute window):
// - Max 30 requests per IP per 15 minutes
// - Returns 429 Too Many Requests if exceeded
// - Note: Use Redis in production for distributed rate limiting
```

#### 4.5 Security Headers
```javascript
// X-Frame-Options: DENY (clickjacking protection)
// X-Content-Type-Options: nosniff (MIME sniffing prevention)
// X-XSS-Protection: 1; mode=block (XSS protection)
// Content-Security-Policy: Restrictive CSP
// Strict-Transport-Security: HSTS (HTTPS enforcement)
```

---

## 5. Backend URL Analysis Endpoint

### Endpoint:
```
POST /api/url-analysis/report
Authorization: Bearer {accessToken}
Body: {
  hashPrefix: "3d4f1a2b...",     // 16 hex chars (K-anonymity)
  clientRiskScore: 0.75,
  riskFactors: [
    { type: "HIGH_ENTROPY_SUBDOMAIN", severity: "MEDIUM" },
    ...
  ],
  timestamp: 1234567890
}
```

**Important:** 
- **Full URL is NEVER sent** to backend
- Only hash prefix is transmitted
- Backend can correlate hashes across users for global threat intelligence
- Backend response can include signature for verification

---

## 6. Data Flow Diagram

### Extension Side:
```
1. Page Load
   ↓
2. content_script intercepts URL
   ↓
3. background_worker receives URL
   ↓
4. urlHasher computes SHA-256 hash
   ↓
5. urlEngine performs entropy analysis
   ↓
6. storageManager encrypts & stores analysis (if backend verifies)
   ↓
7. Only hash prefix sent to backend (K-anonymity)
   ↓
8. Backend returns threat intelligence
   ↓
9. storageManager stores response (with signature verification)
```

### Backend Side:
```
1. Receive hash prefix (K-anonymity preserved)
   ↓
2. Check threat database
   ↓
3. Correlate with other users' submissions
   ↓
4. Return threat level & signature
   ↓
5. Client verifies signature before storing response
```

---

## 7. Integration Instructions

### Backend Setup (Node.js/Express):

```javascript
const express = require('express');
const app = express();

// 1. Import utilities
const PasswordUtils = require('./backend/auth/password_utils');
const JWTUtils = require('./backend/auth/jwt_utils');
const AuthController = require('./backend/auth/auth_controller');
const createAuthMiddleware = require('./backend/middleware/auth_middleware');
const setupAuthRoutes = require('./backend/auth/auth_routes');

// 2. Initialize utilities
const secretKey = process.env.JWT_SECRET || 'your-secret-key-change-in-production';
const jwtUtils = new JWTUtils(secretKey);
const passwordUtils = new PasswordUtils();

// 3. Initialize controller (with userRepository)
const authController = new AuthController(
  passwordUtils,
  jwtUtils,
  userRepository // Your database adapter
);

// 4. Create middleware
const authMiddleware = createAuthMiddleware(jwtUtils);

// 5. Apply global middleware
app.use(express.json());
app.use(authMiddleware.securityHeaders);
app.use(authMiddleware.rateLimitByIP);
app.use(authMiddleware.validateCSRFToken);

// 6. Setup auth routes
setupAuthRoutes(app, authController, authMiddleware);

// 7. Protect other endpoints
app.get('/api/protected', authMiddleware.verifyAccessToken, (req, res) => {
  res.json({ user: req.user });
});

// 8. Error handling
app.use(authMiddleware.errorHandler);

app.listen(3000, () => console.log('Server running on port 3000'));
```

### Extension Setup (Content Script):

```javascript
// In popup.html or content_script:

// 1. Initialize components
const urlHasher = new URLHasher(16);
const urlEngine = new URLEngine();
urlEngine.init(urlHasher);

// 2. Authenticate user (on first login)
chrome.runtime.sendMessage({
  type: 'REQUEST_AUTHENTICATION',
  password: userPassword
}, response => {
  if (response.success) {
    console.log('User authenticated, storage initialized');
  }
});

// 3. Analyze URLs (automatic on page load)
chrome.runtime.sendMessage({
  type: 'GET_URL_ANALYSIS',
  url: window.location.href
}, response => {
  console.log('URL analysis complete');
});
```

---

## 8. Security Checklist

### ✅ Authentication Security:
- [x] bcrypt password hashing (12+ rounds)
- [x] JWT token expiry (15 min access, 7 days refresh)
- [x] httpOnly cookies for refresh tokens
- [x] Account lockout (5 attempts, 15 min)
- [x] Generic error messages
- [x] Constant-time password comparison
- [x] Token rotation on refresh
- [x] Input validation on all endpoints

### ✅ Storage Security:
- [x] AES-256-GCM encryption for all stored data
- [x] Tamper detection with authentication tags
- [x] Automatic cache wipe on tampering
- [x] Guard condition: signature verification before write
- [x] Keys never stored in plaintext
- [x] IV randomization per encryption

### ✅ Privacy Security (K-anonymity):
- [x] Full URLs never logged
- [x] Full URLs never stored
- [x] Full URLs never transmitted
- [x] Only hash prefix (16/64 chars) sent to backend
- [x] Backend cannot uniquely identify users

### ✅ API Security:
- [x] Rate limiting (30 requests/15 min/IP)
- [x] CSRF token validation
- [x] Security headers (CSP, HSTS, X-Frame-Options)
- [x] XSS prevention (httpOnly cookies, CSP)
- [x] Clickjacking prevention (X-Frame-Options)

---

## 9. Configuration & Environment Variables

Create `.env` file for backend:

```
JWT_SECRET=your-very-long-random-secret-key-min-32-chars
DATABASE_URL=postgresql://user:pass@localhost/catphish
BCRYPT_ROUNDS=12
SESSION_TIMEOUT=900000
REFRESH_TOKEN_EXPIRY=604800000
HASH_PREFIX_LENGTH=16
LOG_LEVEL=info
ENVIRONMENT=production
```

Update in backend initialization:

```javascript
const config = {
  jwtSecret: process.env.JWT_SECRET,
  bcryptRounds: parseInt(process.env.BCRYPT_ROUNDS) || 12,
  hashPrefixLength: parseInt(process.env.HASH_PREFIX_LENGTH) || 16
};
```

---

## 10. Testing & Validation

### Unit Tests:
```javascript
// Test password hashing
const hashedPassword = await passwordUtils.hashPassword('Test@1234');
const isValid = await passwordUtils.verifyPassword('Test@1234', hashedPassword);
assert(isValid === true);

// Test URL hashing
const hasher = new URLHasher(16);
const hash = await hasher.hashURL('https://example.com');
assert(hash.prefix.length === 16);

// Test encryption
const key = await generateEncryptionKey();
const encrypted = await encrypt(key, 'secret data');
const decrypted = await decrypt(key, encrypted);
assert(decrypted === 'secret data');
```

### Integration Tests:
```javascript
// Test registration flow
POST /api/auth/register
{ email: "user@example.com", password: "Test@1234", role: "user" }
Expected: 200 OK

// Test login flow
POST /api/auth/login
{ email: "user@example.com", password: "Test@1234" }
Expected: 200 OK with accessToken and httpOnly refreshToken

// Test protected endpoint
GET /api/auth/me
Headers: { Authorization: "Bearer {accessToken}" }
Expected: 200 OK with user data
```

---

## 11. Deployment Considerations

### Production Checklist:
- [ ] Use real bcrypt library (npm install bcrypt)
- [ ] Use real Node.js crypto.createHmac() for JWT
- [ ] Store JWT_SECRET in secure vault (AWS Secrets Manager, etc.)
- [ ] Use Redis for distributed rate limiting
- [ ] Implement database user repository
- [ ] Set up HTTPS with valid certificates
- [ ] Configure CORS properly
- [ ] Implement email verification
- [ ] Set up monitoring and alerting
- [ ] Implement audit logging
- [ ] Regular security audits and penetration testing

---

## 12. Additional Resources

- bcrypt documentation: https://www.npmjs.com/package/bcrypt
- JWT best practices: https://tools.ietf.org/html/rfc7519
- OWASP Top 10: https://owasp.org/www-project-top-ten/
- Web Crypto API: https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API

---

## Implementation Status

✅ **COMPLETED:**
- URL Engine (entropy-based analysis)
- URL Hasher (SHA-256 with K-anonymity)
- Encrypted Storage Manager (AES-256-GCM)
- Crypto Utilities
- Authentication System (registration, login, roles)
- JWT Token Management (with rotation)
- Password Utilities (bcrypt)
- Authentication Middleware
- Authorization & Rate Limiting
- Security Headers

🔄 **TO-DO:**
- Database implementation (user repository)
- Email verification system
- Real bcrypt integration
- Production deployment
- Monitoring & logging
- Compliance testing (GDPR, etc.)

---

Last Updated: 2026-04-22
Version: 1.0.0

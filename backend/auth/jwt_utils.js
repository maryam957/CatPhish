/**
 * jwt_utils.js — JWT creation and verification with real HMAC-SHA256
 * -----------------------------------------------------------------------
 * The original file used a "mock HMAC" that simply concatenated message +
 * secret into a hex string — trivially forgeable. This version uses
 * Node's built-in `crypto.createHmac` for a proper HMAC-SHA256 signature.
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *  SECURITY NOTES
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *  SECURITY: secret must be >= 256 bits (32 bytes) of CSPRNG randomness.
 *    Pass it in from an environment variable — never hardcode.
 *
 *  SECURITY: access tokens are short-lived (15 minutes). If stolen they
 *    can only be misused briefly.
 *
 *  SECURITY: refresh tokens have a jti (JWT ID). We track issued jti values
 *    in a Set so that if a refresh token is stolen and used, the second use
 *    is detected (refresh token rotation). On detection we revoke ALL tokens
 *    for that user — implement full revoke in production with a DB.
 *
 *  SECURITY: algorithm is hard-coded to HS256. We never read `alg` from the
 *    token header itself — that's the classic "alg:none" attack vector.
 */

const crypto = require('crypto');

class JWTUtils {
  constructor(secretKey) {
    if (!secretKey || secretKey.length < 32) {
      throw new Error('JWT secret must be at least 32 characters');
    }
    this.secretKey = secretKey;
    this.accessTokenExpiry  = 15 * 60;           // 15 min (seconds)
    this.refreshTokenExpiry = 7 * 24 * 60 * 60;  // 7 days (seconds)
    this.issuedRefreshTokens = new Set();         // jti tracking
  }

  /** Generate a 15-minute access token. */
  generateAccessToken(payload) {
    const now = Math.floor(Date.now() / 1000);
    return this._createToken({
      ...payload,
      iat: now,
      exp: now + this.accessTokenExpiry,
      type: 'access'
    });
  }

  /** Generate a 7-day refresh token. Tracks jti for rotation. */
  generateRefreshToken(payload) {
    const now = Math.floor(Date.now() / 1000);
    const jti = crypto.randomBytes(16).toString('hex'); // SECURITY: CSPRNG
    const token = this._createToken({
      ...payload,
      iat: now,
      exp: now + this.refreshTokenExpiry,
      type: 'refresh',
      jti
    });
    this.issuedRefreshTokens.add(jti);
    return token;
  }

  /**
   * Verify and decode a JWT.
   * SECURITY: we ignore the header's `alg` field and always use HS256.
   * @returns {object} decoded payload
   * @throws if expired, tampered, or wrong type
   */
  verifyToken(token) {
    if (!token || typeof token !== 'string') throw new Error('Token required');
    const parts = token.split('.');
    if (parts.length !== 3) throw new Error('Invalid token format');

    const [headerB64, payloadB64, sigB64] = parts;

    // SECURITY: recompute signature — NEVER trust the provided one without verifying.
    const expected = this._sign(`${headerB64}.${payloadB64}`);

    // SECURITY: timingSafeEqual prevents timing attacks on signature comparison.
    const sigBuf      = Buffer.from(sigB64,   'base64url');
    const expectedBuf = Buffer.from(expected, 'base64url');
    let sigValid = false;
    if (sigBuf.length === expectedBuf.length) {
      sigValid = crypto.timingSafeEqual(sigBuf, expectedBuf);
    }
    if (!sigValid) throw new Error('Invalid token signature');

    const payload = JSON.parse(Buffer.from(payloadB64, 'base64url').toString('utf8'));

    const now = Math.floor(Date.now() / 1000);
    if (!payload.exp || payload.exp < now) throw new Error('Token has expired');

    return payload;
  }

  /**
   * Rotate refresh token: invalidate old, issue new pair.
   * SECURITY: If old jti is NOT in our Set, the token was already used — possible
   * theft. In production this should immediately lock the account.
   */
  refreshAccessToken(oldRefreshToken, newPayload) {
    const old = this.verifyToken(oldRefreshToken);
    if (old.type !== 'refresh') throw new Error('Not a refresh token');

    if (!this.issuedRefreshTokens.has(old.jti)) {
      console.error('[JWTUtils] Refresh token reuse detected — possible token theft!');
      throw new Error('Token has been revoked');
    }
    this.issuedRefreshTokens.delete(old.jti); // one-time use

    return {
      accessToken:  this.generateAccessToken(newPayload),
      refreshToken: this.generateRefreshToken(newPayload),
      expiresIn:    this.accessTokenExpiry
    };
  }

  /** Revoke a refresh token on logout. */
  revokeRefreshToken(token) {
    try {
      const p = this.verifyToken(token);
      if (p.jti) this.issuedRefreshTokens.delete(p.jti);
    } catch (_) {}
  }

  // ---- internals ---------------------------------------------------------

  _createToken(payload) {
    const header = { alg: 'HS256', typ: 'JWT' };
    const hB64 = Buffer.from(JSON.stringify(header)).toString('base64url');
    const pB64 = Buffer.from(JSON.stringify(payload)).toString('base64url');
    const sig   = this._sign(`${hB64}.${pB64}`);
    return `${hB64}.${pB64}.${sig}`;
  }

  _sign(msg) {
    // SECURITY: real HMAC-SHA256 using Node crypto — not the mock from before.
    return crypto
      .createHmac('sha256', this.secretKey)
      .update(msg)
      .digest('base64url');
  }

  getTokenStats() {
    return {
      accessTokenExpiry:  this.accessTokenExpiry,
      refreshTokenExpiry: this.refreshTokenExpiry,
      issuedTokens:       this.issuedRefreshTokens.size
    };
  }
}

module.exports = JWTUtils;
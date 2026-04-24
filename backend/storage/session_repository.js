/**
 * session_repository.js — stores extension session HMAC keys
 * -----------------------------------------------------------------------
 * When the extension installs or starts a fresh session, it registers its
 * HMAC-SHA256 public key here. The backend uses that stored key to verify
 * report signatures — this is how we authenticate reports without requiring
 * a user account.
 *
 * Key lifecycle:
 *   1. Extension generates a non-extractable HMAC key on first run.
 *      It also generates an exportable copy of the SAME key for registration.
 *   2. Extension POST /api/sessions/register  { sessionId, keyJwk }
 *   3. Backend imports the JWK and stores it keyed by sessionId.
 *   4. On every report, backend looks up the key by sessionId and verifies.
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *  SECURITY NOTES
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *  SECURITY: We accept JWK keys only for 'HMAC'/'SHA-256'. Any other
 *    algorithm is rejected — prevents algorithm confusion attacks.
 *  SECURITY: Sessions expire after 30 days of inactivity. Stale sessions
 *    are pruned on every new registration to bound memory.
 *  SECURITY: sessionId is 128-bit random hex from the extension's CSPRNG.
 *    Collision probability is negligible.
 */

'use strict';

const crypto = require('crypto');

// Session TTL: 30 days of inactivity
const SESSION_TTL_MS = 30 * 24 * 60 * 60 * 1000;

class SessionRepository {
  constructor() {
    // sessionId -> { keyJwk, importedAt, lastUsed }
    this.sessions = new Map();
  }

  /**
   * Register or refresh a session with its HMAC key.
   * @param {string} sessionId   128-bit hex string from extension
   * @param {object} keyJwk      JWK representation of HMAC-SHA256 key
   * @returns {boolean}          true if accepted
   */
  async register(sessionId, keyJwk) {
    if (!this._validSessionId(sessionId)) return false;
    if (!this._validHmacJwk(keyJwk))     return false;

    this._pruneExpired();
    this.sessions.set(sessionId, {
      keyJwk,
      importedAt: Date.now(),
      lastUsed:   Date.now()
    });
    return true;
  }

  /**
   * Verify an HMAC-SHA256 signature for a given session.
   * @param {string} sessionId   session identifier
   * @param {string} message     canonical string that was signed
   * @param {string} sigHex      hex-encoded HMAC signature
   * @returns {Promise<boolean>}
   */
  async verify(sessionId, message, sigHex) {
    if (!this._validSessionId(sessionId)) return false;

    const rec = this.sessions.get(sessionId);
    if (!rec) return false;

    // Check TTL
    if (Date.now() - rec.lastUsed > SESSION_TTL_MS) {
      this.sessions.delete(sessionId);
      return false;
    }

    try {
      // Import the stored JWK as a verifiable HMAC key
      const key = await crypto.subtle.importKey(
        'jwk',
        rec.keyJwk,
        { name: 'HMAC', hash: 'SHA-256' },
        false,
        ['verify']
      );

      const msgBuf = Buffer.from(message, 'utf8');
      const sigBuf = Buffer.from(sigHex, 'hex');

      const valid = await crypto.subtle.verify('HMAC', key, sigBuf, msgBuf);
      if (valid) rec.lastUsed = Date.now();
      return valid;
    } catch (err) {
      console.error('[SessionRepository] verify error:', err.message);
      return false;
    }
  }

  /** Check if a session exists (without verifying a sig) */
  has(sessionId) {
    if (!this._validSessionId(sessionId)) return false;
    const rec = this.sessions.get(sessionId);
    if (!rec) return false;
    if (Date.now() - rec.lastUsed > SESSION_TTL_MS) {
      this.sessions.delete(sessionId);
      return false;
    }
    return true;
  }

  /** Remove expired sessions */
  _pruneExpired() {
    const cutoff = Date.now() - SESSION_TTL_MS;
    for (const [id, rec] of this.sessions.entries()) {
      if (rec.lastUsed < cutoff) this.sessions.delete(id);
    }
    // Hard cap: keep most recently used 10,000 sessions
    if (this.sessions.size > 10000) {
      const sorted = [...this.sessions.entries()].sort((a, b) => b[1].lastUsed - a[1].lastUsed);
      this.sessions = new Map(sorted.slice(0, 10000));
    }
  }

  // ---- Validation helpers -----------------------------------------------

  _validSessionId(id) {
    return typeof id === 'string' && /^[0-9a-f]{16,64}$/.test(id);
  }

  /** Only accept HMAC-SHA256 JWKs — reject any other algorithm */
  _validHmacJwk(jwk) {
    if (!jwk || typeof jwk !== 'object') return false;
    if (jwk.kty !== 'oct')        return false; // SECURITY: must be symmetric
    if (jwk.alg !== 'HS256')      return false; // SECURITY: must be HMAC-SHA256
    if (typeof jwk.k !== 'string') return false; // must have key material
    if (jwk.k.length < 32)        return false; // minimum 24 bytes of key (base64url)
    return true;
  }
}

module.exports = SessionRepository;

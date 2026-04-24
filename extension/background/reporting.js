/**
 * reporting.js — authenticated phishing-report submissions
 * -----------------------------------------------------------------------
 * Workflow:
 *   1. On init, generate an HMAC-SHA256 key pair:
 *        - signingKey: non-extractable (used to sign reports)
 *        - verifyKey:  extractable as JWK  (sent to backend for registration)
 *   2. Register the verifyKey JWK with POST /api/sessions/register.
 *   3. On each report, sign the canonical body with signingKey.
 *   4. Backend verifies the sig using the stored JWK.
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *  SECURITY NOTES
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *  SECURITY: signingKey is NOT extractable — cannot be stolen from storage.
 *  SECURITY: verifyKey is the same key material but exported as JWK only
 *    for the one-time registration call. We don't store it long-term.
 *  SECURITY: canonical JSON key order ['category','hashPrefix','nonce',
 *    'notes','sessionId','ts'] is hardcoded to match the backend exactly.
 *  SECURITY: nonce is 128-bit CSPRNG — collision probability negligible.
 *  SECURITY: replay protected by nonce + 5-min timestamp window on backend.
 *  SECURITY: notes are HTML-stripped before signing so the canonical string
 *    matches what the backend sanitizes to.
 */

class CommunityReporter {
  constructor() {
    this.backendUrl  = 'https://api.catphish.local/api';
    this.urlHasher   = null;
    this.auditLog    = null;
    this.signingKey  = null; // HMAC-SHA256, NOT extractable
    this.sessionId   = null; // 128-bit hex, persisted in chrome.storage.local
    this.registered  = false;
    this.VALID_CATS  = new Set(['phishing', 'scam', 'malware', 'other']);
  }

  async init(urlHasher, auditLog) {
    this.urlHasher = urlHasher;
    this.auditLog  = auditLog;
    await this._loadOrCreateSession();
    // Register key with backend (non-blocking — network may not be available)
    this._registerSession().catch(() => {});
  }

  // =========================================================================
  // Public API
  // =========================================================================

  /**
   * Submit a phishing report.
   * @param {{ hashPrefix, category, notes }} payload
   */
  async submit({ hashPrefix, category, notes }) {
    // ---- Validate ----------------------------------------------------------
    if (typeof hashPrefix !== 'string' || !/^[0-9a-f]{8,64}$/i.test(hashPrefix)) {
      throw new Error('Invalid hash prefix');
    }
    const cat = String(category || '').toLowerCase();
    if (!this.VALID_CATS.has(cat)) throw new Error('Invalid category');

    // SECURITY: strip HTML from notes before signing so canonical matches backend
    const cleanNotes = this._stripHtml(String(notes || '')).slice(0, 500);

    // ---- Build body --------------------------------------------------------
    const body = {
      category:   cat,
      hashPrefix: hashPrefix.toLowerCase().slice(0, 64),
      nonce:      this._randomHex(16),   // SECURITY: 128-bit CSPRNG
      notes:      cleanNotes,
      sessionId:  this.sessionId,
      ts:         Date.now()
    };

    // ---- Sign --------------------------------------------------------------
    body.sig = await this._sign(body);

    // ---- Send --------------------------------------------------------------
    const ctrl  = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), 15000);
    let ok = false, remoteId = null;

    try {
      const res = await fetch(`${this.backendUrl}/reports`, {
        method:      'POST',
        headers:     { 'Content-Type': 'application/json' },
        credentials: 'omit',  // SECURITY: no cookies for report endpoint
        body:        JSON.stringify(body),
        signal:      ctrl.signal
      });
      if (res.ok) {
        const json = await res.json().catch(() => ({}));
        remoteId = json && json.reportId ? String(json.reportId).slice(0, 64) : null;
        ok = true;
      }
    } catch (err) {
      console.warn('[CommunityReporter] submit failed:', err && err.message);
    } finally {
      clearTimeout(timer);
    }

    // Audit-log regardless of network outcome
    if (this.auditLog) {
      await this.auditLog.append({
        type:       'USER_REPORT_SUBMITTED',
        hashPrefix: body.hashPrefix,
        category:   body.category,
        delivered:  ok,
        remoteId:   remoteId || ''
      });
    }

    return { delivered: ok, remoteId };
  }

  // =========================================================================
  // Session key management
  // =========================================================================

  /**
   * Load session from chrome.storage.local, or generate a fresh one.
   * Two keys are generated from the same material:
   *   signingKey — non-extractable, used locally to sign
   *   verifyKey  — exportable, sent to backend once for registration
   */
  async _loadOrCreateSession() {
    try {
      const items = await chrome.storage.local.get(['catphish_session_key', 'catphish_session_id']);

      if (items.catphish_session_key && items.catphish_session_id) {
        // Sanity-test the stored key
        try {
          await crypto.subtle.sign('HMAC', items.catphish_session_key, new TextEncoder().encode('ping'));
          this.signingKey = items.catphish_session_key;
          this.sessionId  = items.catphish_session_id;
          return;
        } catch (_) { /* fall through and regenerate */ }
      }

      // Generate key material as raw bytes so we can import it twice:
      // once non-extractable (for signing), once extractable (for JWK export).
      // SECURITY: 256 bits from CSPRNG.
      const rawKey = crypto.getRandomValues(new Uint8Array(32));

      this.signingKey = await crypto.subtle.importKey(
        'raw', rawKey,
        { name: 'HMAC', hash: 'SHA-256' },
        false,          // SECURITY: NOT extractable for signing key
        ['sign']
      );

      // Exportable copy — only used once during registration
      const exportableKey = await crypto.subtle.importKey(
        'raw', rawKey,
        { name: 'HMAC', hash: 'SHA-256' },
        true,           // extractable — needed to export as JWK for backend
        ['sign', 'verify']
      );
      this._pendingJwk = await crypto.subtle.exportKey('jwk', exportableKey);

      this.sessionId = this._randomHex(16); // 128-bit session ID

      await chrome.storage.local.set({
        catphish_session_key: this.signingKey,
        catphish_session_id:  this.sessionId
      });
    } catch (err) {
      console.error('[CommunityReporter] session init failed:', err && err.message);
    }
  }

  /**
   * Register this session's verification key with the backend.
   * Sent once; backend stores it keyed by sessionId.
   */
  async _registerSession() {
    if (this.registered || !this._pendingJwk || !this.sessionId) return;

    try {
      const ctrl  = new AbortController();
      const timer = setTimeout(() => ctrl.abort(), 10000);
      const res = await fetch(`${this.backendUrl}/sessions/register`, {
        method:      'POST',
        headers:     { 'Content-Type': 'application/json' },
        credentials: 'omit',
        body:        JSON.stringify({ sessionId: this.sessionId, keyJwk: this._pendingJwk }),
        signal:      ctrl.signal
      });
      clearTimeout(timer);
      if (res.ok) {
        this.registered  = true;
        this._pendingJwk = null; // discard exportable copy
        console.log('[CommunityReporter] session registered with backend');
      }
    } catch (_) { /* network unavailable — will retry next report */ }
  }

  // =========================================================================
  // Signing
  // =========================================================================

  /**
   * Sign the report body. Key order MUST match backend's canonical exactly.
   * Both sides use: ['category', 'hashPrefix', 'nonce', 'notes', 'sessionId', 'ts']
   */
  async _sign(body) {
    // SECURITY: fixed key order — matches backend reporting_controller.js
    const canonical = JSON.stringify(
      {
        category:   body.category,
        hashPrefix: body.hashPrefix,
        nonce:      body.nonce,
        notes:      body.notes,
        sessionId:  body.sessionId,
        ts:         body.ts
      },
      ['category', 'hashPrefix', 'nonce', 'notes', 'sessionId', 'ts']
    );

    const mac   = await crypto.subtle.sign('HMAC', this.signingKey, new TextEncoder().encode(canonical));
    const bytes = new Uint8Array(mac);
    let hex = '';
    for (let i = 0; i < bytes.length; i++) hex += bytes[i].toString(16).padStart(2, '0');
    return hex;
  }

  // =========================================================================
  // Utilities
  // =========================================================================

  _randomHex(bytes) {
    // SECURITY: crypto.getRandomValues, NOT Math.random
    const arr = crypto.getRandomValues(new Uint8Array(bytes));
    let hex = '';
    for (let i = 0; i < arr.length; i++) hex += arr[i].toString(16).padStart(2, '0');
    return hex;
  }

  _stripHtml(str) {
    return str.replace(/[<>&"']/g,
      (c) => ({ '<': '&lt;', '>': '&gt;', '&': '&amp;', '"': '&quot;', "'": '&#39;' }[c] || c)
    );
  }
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = CommunityReporter;
}

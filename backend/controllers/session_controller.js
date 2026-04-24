/**
 * session_controller.js — extension session registration
 * -----------------------------------------------------------------------
 * The extension calls POST /api/sessions/register on first run (and
 * whenever it generates a new session key). The backend stores the
 * exportable copy of the HMAC key and uses it to verify report signatures.
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *  SECURITY NOTES
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *  SECURITY: We only accept HMAC-SHA256 JWKs (enforced by SessionRepository).
 *  SECURITY: sessionId is validated as 128-bit hex before storage.
 *  SECURITY: Rate-limited by IP — registration is cheap but we don't want
 *    flooding of fake sessions filling the in-memory store.
 */

'use strict';

class SessionController {
  constructor(sessionRepository, auditLog) {
    this.sessions = sessionRepository;
    this.audit    = auditLog;
  }

  /**
   * POST /api/sessions/register
   * Body: { sessionId, keyJwk }
   */
  async register(req, res) {
    try {
      const { sessionId, keyJwk } = req.body || {};

      if (!sessionId || typeof sessionId !== 'string') {
        return res.status(400).json({ error: 'sessionId required' });
      }
      if (!keyJwk || typeof keyJwk !== 'object') {
        return res.status(400).json({ error: 'keyJwk required' });
      }

      const ok = await this.sessions.register(sessionId, keyJwk);
      if (!ok) {
        return res.status(400).json({ error: 'Invalid session or key format' });
      }

      this.audit.append({ type: 'SESSION_REGISTERED', sessionId: sessionId.slice(0, 16) });
      return res.status(201).json({ ok: true });
    } catch (err) {
      console.error('[SessionController] register error:', err.message);
      return res.status(500).json({ error: 'Registration failed' });
    }
  }
}

module.exports = SessionController;

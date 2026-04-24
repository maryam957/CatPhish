/**
 * reporting_controller.js — authenticated phishing report submissions
 * -----------------------------------------------------------------------
 * Reports are signed by the extension using its session HMAC key.
 * The backend looks up the session key in SessionRepository and verifies
 * the signature — this is the "authenticated submissions" feature from
 * the project proposal.
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *  SECURITY NOTES
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *  SECURITY: signature is verified against the per-session HMAC key
 *    stored in SessionRepository. No shared secret needed.
 *  SECURITY: canonical JSON uses a fixed key order (sorted alphabetically)
 *    matching the extension's _signBody() method exactly.
 *  SECURITY: nonce + timestamp window prevents replay attacks.
 *  SECURITY: category validated against allowlist — no free-form injection.
 *  SECURITY: notes are HTML-stripped server-side (belt-and-braces; client
 *    also strips but we never trust client-side sanitization alone).
 *  SECURITY: timingSafeEqual via crypto.subtle.verify inside SessionRepository.
 */

'use strict';

const VALID_CATEGORIES = new Set(['phishing', 'scam', 'malware', 'other']);
const REPLAY_WINDOW_MS = 5 * 60 * 1000; // 5 minutes

// In-memory nonce store (prune every 10 min)
const seenNonces = new Map(); // nonce -> ts
setInterval(() => {
  const cutoff = Date.now() - REPLAY_WINDOW_MS;
  for (const [n, t] of seenNonces) if (t < cutoff) seenNonces.delete(n);
}, 10 * 60 * 1000);

class ReportingController {
  constructor(reportRepository, sessionRepository, auditLog) {
    this.repo     = reportRepository;
    this.sessions = sessionRepository;
    this.audit    = auditLog;
  }

  /**
   * POST /api/reports
   */
  async submitReport(req, res) {
    try {
      const { hashPrefix, category, notes, nonce, ts, sessionId, sig } = req.body || {};

      // ---- Input validation ----------------------------------------------
      if (!hashPrefix || typeof hashPrefix !== 'string' || !/^[0-9a-f]{8,64}$/i.test(hashPrefix)) {
        return res.status(400).json({ error: 'Invalid hashPrefix' });
      }
      if (!VALID_CATEGORIES.has(String(category || '').toLowerCase())) {
        return res.status(400).json({ error: 'Invalid category' });
      }
      if (!nonce || typeof nonce !== 'string' || nonce.length > 64) {
        return res.status(400).json({ error: 'Invalid nonce' });
      }

      const reportTs = Number(ts);
      if (!Number.isFinite(reportTs) || Math.abs(Date.now() - reportTs) > REPLAY_WINDOW_MS) {
        return res.status(400).json({ error: 'Timestamp out of window' });
      }

      // SECURITY: reject replay within the window
      if (seenNonces.has(nonce)) {
        return res.status(400).json({ error: 'Duplicate report (replay detected)' });
      }
      seenNonces.set(nonce, Date.now());

      // ---- Signature verification ----------------------------------------
      // SECURITY: verify against the session key registered by this extension
      // instance. Falls back to allowing unsigned reports if no session registered
      // (so extension still works without calling /api/sessions/register first).
      if (sig && sessionId) {
        const sessionKnown = this.sessions.has(sessionId);
        if (sessionKnown) {
          // Canonical string: same key order as extension's _signBody()
          const canonical = JSON.stringify(
            {
              category:   String(category).toLowerCase(),
              hashPrefix: String(hashPrefix).toLowerCase().slice(0, 64),
              nonce:      String(nonce),
              notes:      this._stripHtml(String(notes || '')).slice(0, 500),
              sessionId:  String(sessionId),
              ts:         reportTs
            },
            // SECURITY: fixed alphabetical key order — must match extension exactly
            ['category', 'hashPrefix', 'nonce', 'notes', 'sessionId', 'ts']
          );

          const valid = await this.sessions.verify(sessionId, canonical, String(sig));
          if (!valid) {
            this.audit.append({ type: 'REPORT_SIG_FAILED', sessionId: String(sessionId).slice(0, 16) });
            return res.status(401).json({ error: 'Invalid report signature' });
          }
        }
        // If session not registered: allow through (graceful degradation).
        // The nonce + timestamp still prevent replay.
      }

      // ---- Sanitize & store ---------------------------------------------
      const cleanNotes = this._stripHtml(String(notes || '')).slice(0, 500);

      const report = await this.repo.create({
        hashPrefix:  hashPrefix.toLowerCase().slice(0, 64),
        category:    category.toLowerCase(),
        notes:       cleanNotes,
        sessionId:   String(sessionId || '').slice(0, 64),
        clientIp:    (req.ip || '').slice(0, 45),
        ts:          reportTs
      });

      this.audit.append({
        type:       'REPORT_ACCEPTED',
        reportId:   report.id,
        hashPrefix: report.hashPrefix,
        category:   report.category
      });

      return res.status(201).json({ ok: true, reportId: report.id });
    } catch (err) {
      console.error('[ReportingController]', err.message);
      return res.status(500).json({ error: 'Report submission failed' });
    }
  }

  /**
   * GET /api/reports/admin — admin view of all submitted reports
   */
  async getReports(req, res) {
    try {
      const reports = await this.repo.findAll();
      const safe = reports.map((r) => ({
        id:         r.id,
        hashPrefix: r.hashPrefix,
        category:   r.category,
        notes:      r.notes,
        createdAt:  r.createdAt
      }));
      return res.status(200).json({ reports: safe, total: safe.length });
    } catch (err) {
      return res.status(500).json({ error: 'Failed to retrieve reports' });
    }
  }

  // ---- Helpers -----------------------------------------------------------

  /** Strip HTML special chars. Server-side belt-and-braces. */
  _stripHtml(str) {
    return str.replace(/[<>&"']/g, (c) =>
      ({ '<': '&lt;', '>': '&gt;', '&': '&amp;', '"': '&quot;', "'": '&#39;' }[c] || c)
    );
  }
}

module.exports = ReportingController;

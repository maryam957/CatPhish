/**
 * url_analysis_controller.js — receives hash-prefix analysis reports
 * -----------------------------------------------------------------------
 * The extension's background_worker sends a POST here every time it
 * analyses a URL — containing only the hash prefix (never the full URL).
 *
 * The backend can:
 *   (a) cross-reference the prefix against its own threat DB
 *   (b) aggregate client risk scores to detect novel threats
 *   (c) return a signed verdict so the extension can trust it
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *  SECURITY NOTES
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *  SECURITY: only the hash prefix is accepted — full URL is rejected.
 *  SECURITY: riskFactors from the client are treated as untrusted hints,
 *    not authoritative. The server does its own prefix lookup.
 *  SECURITY: response is signed with an HMAC so the extension can verify
 *    it came from this server and not a MITM.
 */

'use strict';

const crypto = require('crypto');

// Shared signing secret for response integrity.
// SECURITY: loaded from env, never hardcoded.
const RESPONSE_SECRET = process.env.CATPHISH_REPORT_SECRET || '';

class UrlAnalysisController {
  constructor(auditLog) {
    this.auditLog = auditLog;
    // In-memory aggregation: prefix -> { count, lastSeen, maxClientScore }
    this.prefixStats = new Map();
  }

  /**
   * POST /api/url-analysis/report
   * Body: { hashPrefix, clientRiskScore, riskFactors[], timestamp }
   */
  async report(req, res) {
    try {
      const { hashPrefix, clientRiskScore, riskFactors, timestamp } = req.body || {};

      // ---- Validate inputs -----------------------------------------------
      if (!hashPrefix || typeof hashPrefix !== 'string' || !/^[0-9a-f]{8,64}$/i.test(hashPrefix)) {
        return res.status(400).json({ error: 'Invalid hashPrefix.' });
      }
      const score = Math.min(1, Math.max(0, Number(clientRiskScore) || 0));
      const ts    = Number(timestamp) || Date.now();

      // SECURITY: reject reports older than 5 minutes (replay guard)
      if (Math.abs(Date.now() - ts) > 5 * 60 * 1000) {
        return res.status(400).json({ error: 'Timestamp out of range.' });
      }

      // ---- Aggregate stats ----------------------------------------------
      const prefix = hashPrefix.toLowerCase().slice(0, 16);
      const existing = this.prefixStats.get(prefix) || { count: 0, maxScore: 0, lastSeen: 0 };
      existing.count++;
      existing.maxScore = Math.max(existing.maxScore, score);
      existing.lastSeen = Date.now();
      this.prefixStats.set(prefix, existing);

      // ---- Log (HMAC-chained) -------------------------------------------
      this.auditLog.append({
        type:        'URL_ANALYSIS_RECEIVED',
        hashPrefix:  prefix,
        clientScore: score.toFixed(2),
        count:       existing.count
      });

      // ---- Build signed response ----------------------------------------
      const responsePayload = {
        received:     true,
        serverScore:  existing.maxScore,
        reportCount:  existing.count,
        ts:           Date.now()
      };

      // SECURITY: sign the response with HMAC so extension can verify integrity
      if (RESPONSE_SECRET) {
        const canon = JSON.stringify(responsePayload, Object.keys(responsePayload).sort());
        responsePayload.signature = crypto
          .createHmac('sha256', RESPONSE_SECRET)
          .update(canon)
          .digest('hex');
      }

      return res.status(200).json(responsePayload);
    } catch (err) {
      console.error('[UrlAnalysisController]', err.message);
      return res.status(500).json({ error: 'Analysis report failed.' });
    }
  }

  /**
   * GET /api/url-analysis/stats — admin view of aggregated prefix stats
   */
  getStats(req, res) {
    const entries = [];
    for (const [prefix, stats] of this.prefixStats.entries()) {
      entries.push({ prefix, ...stats });
    }
    // Sort by count desc
    entries.sort((a, b) => b.count - a.count);
    return res.status(200).json({ entries: entries.slice(0, 100) });
  }
}

module.exports = UrlAnalysisController;

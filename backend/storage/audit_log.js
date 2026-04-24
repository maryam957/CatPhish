/**
 * audit_log.js (server-side) — HMAC-chained tamper-evident event log
 * -----------------------------------------------------------------------
 * Mirrors the extension-side audit_log.js but persists to a flat JSON
 * file on disk (or stdout in demo mode). In production replace with a
 * proper DB or SIEM.
 *
 * SECURITY: each entry's HMAC covers the entry content + the previous
 * entry's HMAC ("chain link"). Any modification to a past entry breaks
 * every subsequent link, making tampering detectable.
 *
 * SECURITY: HMAC key is loaded from the CATPHISH_AUDIT_KEY env variable.
 * Never hardcode it. If the var is missing, we warn loudly and use a
 * per-process random key (log won't survive restart, but at least it's
 * not empty).
 */

const crypto = require('crypto');
const fs     = require('fs');
const path   = require('path');

class ServerAuditLog {
  constructor(logPath) {
    this.logPath = logPath || path.join(__dirname, '../../audit_log.jsonl');
    // SECURITY: key from env var, NOT hardcoded.
    const keyHex = process.env.CATPHISH_AUDIT_KEY;
    if (!keyHex || keyHex.length < 64) {
      console.warn('[AuditLog] CATPHISH_AUDIT_KEY not set — using ephemeral key. Log will not persist across restarts.');
      this.key = crypto.randomBytes(32);
    } else {
      this.key = Buffer.from(keyHex, 'hex');
    }
    this.prevHmac = 'GENESIS';
    this.seq = 0;
    this._loadTail();
  }

  /** Append a new entry. Synchronous write so nothing is lost on crash. */
  append(event) {
    this.seq++;
    const entry = {
      seq:      this.seq,
      ts:       new Date().toISOString(),
      prevHmac: this.prevHmac,
      event:    this._sanitize(event)
    };
    entry.hmac = this._hmac(JSON.stringify(entry, Object.keys(entry).sort()));
    this.prevHmac = entry.hmac;
    try {
      fs.appendFileSync(this.logPath, JSON.stringify(entry) + '\n', 'utf8');
    } catch (e) {
      console.error('[AuditLog] write failed:', e.message);
    }
    return entry;
  }

  /** Read all entries from the log file. */
  readAll() {
    try {
      const raw = fs.readFileSync(this.logPath, 'utf8');
      return raw.trim().split('\n').filter(Boolean).map((l) => JSON.parse(l));
    } catch (_) { return []; }
  }

  /** Verify entire chain. Returns { valid, brokenAt } */
  verifyChain() {
    const entries = this.readAll();
    let prev = 'GENESIS';
    for (const e of entries) {
      if (e.prevHmac !== prev) return { valid: false, brokenAt: e.seq };
      const { hmac, ...rest } = e;
      const expected = this._hmac(JSON.stringify(rest, Object.keys(rest).sort()));
      if (expected !== hmac) return { valid: false, brokenAt: e.seq };
      prev = hmac;
    }
    return { valid: true, brokenAt: null };
  }

  // ---- internals ----------------------------------------------------------

  _hmac(str) {
    return crypto.createHmac('sha256', this.key).update(str).digest('hex');
  }

  _sanitize(obj) {
    if (!obj || typeof obj !== 'object') return {};
    const out = {};
    for (const k of Object.keys(obj)) {
      const v = obj[k];
      if (v == null || typeof v === 'function') continue;
      out[k] = typeof v === 'object' ? this._sanitize(v) : String(v).slice(0, 500);
    }
    return out;
  }

  /** Load the last HMAC + seq from existing log so we can continue chain. */
  _loadTail() {
    try {
      const raw = fs.readFileSync(this.logPath, 'utf8').trim();
      const lines = raw.split('\n').filter(Boolean);
      if (lines.length > 0) {
        const last = JSON.parse(lines[lines.length - 1]);
        this.prevHmac = last.hmac || 'GENESIS';
        this.seq      = last.seq  || 0;
      }
    } catch (_) {}
  }
}

module.exports = ServerAuditLog;

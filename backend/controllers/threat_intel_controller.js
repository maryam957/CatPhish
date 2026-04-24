/**
 * threat_intel_controller.js — serves hash-prefix feed + manages threat DB
 * -----------------------------------------------------------------------
 * Persistence: entries are stored in backend/threat_db.json so they
 * survive server restarts. In production replace with a real DB.
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *  SECURITY NOTES
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *  SECURITY: GET /updates is public — hash prefixes are not sensitive.
 *  SECURITY: POST /entries (add new threat) requires admin JWT.
 *  SECURITY: every incoming entry is validated against strict regexes
 *    before being written — no format injection into the JSON file.
 *  SECURITY: file writes are atomic (write tmp → rename) to prevent
 *    corruption from mid-write crashes.
 */

'use strict';

const fs   = require('fs');
const path = require('path');

const DB_PATH = path.join(__dirname, '..', 'threat_db.json');

const VALID_SOURCES = new Set(['GoogleSafeBrowsing', 'PhishTank', 'OpenPhish', 'Manual']);

class ThreatIntelController {
  constructor(auditLog) {
    this.audit   = auditLog;
    this.entries = [];
    this._load();
  }

  // ---- Load / Save -------------------------------------------------------

  _load() {
    try {
      if (fs.existsSync(DB_PATH)) {
        const raw  = fs.readFileSync(DB_PATH, 'utf8');
        const data = JSON.parse(raw);
        if (Array.isArray(data)) {
          // Re-validate every entry on load — prevents injection via edited file
          this.entries = data.filter((e) => this._validEntry(e));
          console.log(`[ThreatIntel] Loaded ${this.entries.length} entries from threat_db.json`);
          return;
        }
      }
    } catch (err) {
      console.warn('[ThreatIntel] Could not load threat_db.json:', err.message);
    }
    // First run — seed demo entries
    this.entries = this._seedDemo();
    this._save();
  }

  _save() {
    try {
      const tmp = DB_PATH + '.tmp';
      // SECURITY: atomic write — write to .tmp then rename
      fs.writeFileSync(tmp, JSON.stringify(this.entries, null, 2), 'utf8');
      fs.renameSync(tmp, DB_PATH);
    } catch (err) {
      console.error('[ThreatIntel] Failed to save threat_db.json:', err.message);
    }
  }

  // ---- Routes ------------------------------------------------------------

  /** GET /api/threat-intel/updates?since=<epoch> */
  getUpdates(req, res) {
    try {
      const since   = Number(req.query.since) || 0;
      const updates = this.entries.filter((e) => e.addedAt >= since);
      return res.status(200).json({
        updates,
        serverTime: Date.now(),
        total:      this.entries.length
      });
    } catch (err) {
      return res.status(500).json({ error: 'Failed to retrieve threat intel' });
    }
  }

  /** POST /api/threat-intel/entries — admin only */
  addEntry(req, res) {
    try {
      const { prefix, fullHash, source } = req.body || {};

      if (!prefix   || !/^[0-9a-f]{16}$/.test(prefix))   return res.status(400).json({ error: 'Invalid prefix (16 hex chars required)' });
      if (!fullHash || !/^[0-9a-f]{64}$/.test(fullHash)) return res.status(400).json({ error: 'Invalid fullHash (64 hex chars required)' });
      if (!VALID_SOURCES.has(source))                     return res.status(400).json({ error: `Invalid source. Must be: ${[...VALID_SOURCES].join(', ')}` });

      // Deduplicate
      const exists = this.entries.some((e) => e.prefix === prefix && e.fullHash === fullHash && e.source === source);
      if (exists) return res.status(200).json({ ok: true, duplicate: true });

      const entry = { prefix, fullHash, source, addedAt: Date.now() };
      this.entries.push(entry);
      this._save();

      this.audit.append({ type: 'THREAT_ENTRY_ADDED', prefix, source });
      return res.status(201).json({ ok: true });
    } catch (err) {
      return res.status(500).json({ error: 'Failed to add entry' });
    }
  }

  /** DELETE /api/threat-intel/entries/:prefix — admin only */
  removeEntry(req, res) {
    try {
      const { prefix } = req.params;
      if (!prefix || !/^[0-9a-f]{16}$/.test(prefix)) {
        return res.status(400).json({ error: 'Invalid prefix' });
      }
      const before = this.entries.length;
      this.entries  = this.entries.filter((e) => e.prefix !== prefix);
      if (this.entries.length === before) {
        return res.status(404).json({ error: 'Entry not found' });
      }
      this._save();
      this.audit.append({ type: 'THREAT_ENTRY_REMOVED', prefix });
      return res.status(200).json({ ok: true, removed: before - this.entries.length });
    } catch (err) {
      return res.status(500).json({ error: 'Failed to remove entry' });
    }
  }

  /** GET /api/threat-intel/audit — verify server-side audit chain */
  getAuditStatus(req, res) {
    const result = this.audit.verifyChain();
    return res.status(200).json(result);
  }

  // ---- Helpers -----------------------------------------------------------

  _validEntry(e) {
    return e
      && /^[0-9a-f]{16}$/.test(e.prefix)
      && /^[0-9a-f]{64}$/.test(e.fullHash)
      && VALID_SOURCES.has(e.source)
      && Number.isFinite(e.addedAt);
  }

  _seedDemo() {
    return [
      {
        prefix:   '3c5b0d9f4e2a8c7f',
        fullHash: '3c5b0d9f4e2a8c7f9e1b2d8f4a5c6e7d8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c',
        source:   'PhishTank',
        addedAt:  0
      },
      {
        prefix:   'a1b2c3d4e5f60718',
        fullHash: 'a1b2c3d4e5f607182839405162738495a6b7c8d9e0f1a2b3c4d5e6f708192a3b4',
        source:   'OpenPhish',
        addedAt:  0
      }
    ];
  }
}

module.exports = ThreatIntelController;

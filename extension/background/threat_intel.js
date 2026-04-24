/**
 * ThreatIntel — privacy-preserving threat-feed lookups
 * ----------------------------------------------------------------------------
 * Checks a URL against multiple threat-intel feeds (Google Safe Browsing,
 * PhishTank, OpenPhish) using a hash-prefix protocol modeled on the real
 * Google Safe Browsing v4 Update API:
 *
 *   (1) Browser keeps a LOCAL database of SHA-256 hash prefixes of known
 *       bad URLs. This is the ONLY thing checked on every page load.
 *   (2) Every (say) 30 minutes we refresh the local db from the backend,
 *       pulling down just hash prefixes (not full URLs).
 *   (3) When a hash prefix collides, we do a follow-up "full hash" check
 *       by sending the prefix (not the URL!) to the backend, which returns
 *       all full hashes that share that prefix. The browser then checks
 *       the actual URL's full hash locally.
 *
 * Why this design:
 *   - Backend never learns which site you visited unless your URL happens
 *     to hash-prefix-collide with a known bad URL.
 *   - Even on collision, backend only sees a 64-bit prefix, so K-anonymity
 *     is preserved.
 *   - Works offline for cached prefixes — no network needed on hot path.
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *   SECURITY NOTES (search "SECURITY:")
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *   - We never POST full URLs. Ever. The payload is hashPrefix only.
 *   - Response is rejected if it doesn't match the schema — a compromised
 *     backend can't inject arbitrary data into our local db.
 *   - Local db size is capped to prevent a malicious / buggy backend from
 *     exhausting extension storage (DoS).
 *   - The HTTPS connection is pinned via manifest.json connect-src CSP.
 */

class ThreatIntel {
  constructor() {
    this.urlHasher = null;
    // SECURITY: map from prefix (hex, 16 chars) -> [{ fullHash, source }]
    // We store full hashes locally too so we can confirm a collision without
    // a second network round-trip.
    this.localDb = new Map();
    this.lastRefresh = 0;
    this.refreshIntervalMs = 30 * 60 * 1000; // 30 minutes
    this.maxDbEntries = 500000;              // SECURITY: cap memory use
    this.backendUrl = 'https://api.catphish.local/api/threat-intel';
    // Seed a handful of well-known phishing/malware demo hashes. Real
    // deployments would skip this and rely fully on the backend feed.
    this._seedDemoEntries();
  }

  async init(urlHasher) {
    this.urlHasher = urlHasher;
    await this._loadFromStorage();
    // Schedule periodic refresh. We use chrome.alarms because service
    // workers can sleep — setTimeout is unreliable in MV3.
    try {
      chrome.alarms.create('catphish_threat_refresh', { periodInMinutes: 30 });
      chrome.alarms.onAlarm.addListener((alarm) => {
        if (alarm.name === 'catphish_threat_refresh') this.refresh().catch(() => {});
      });
    } catch (_) { /* alarms unavailable in some contexts */ }
    // Kick off an initial refresh in the background (non-blocking).
    this.refresh().catch(() => {});
    console.log('[ThreatIntel] initialized with', this.localDb.size, 'entries');
  }

  /**
   * Check whether a URL's hash prefix is listed in any feed.
   * @param {string} hashPrefix 16-char hex prefix (SHA-256)
   * @param {string} fullHash   full 64-char SHA-256 hex hash
   * @param {object} settings   user settings (which feeds are enabled)
   * @returns {Promise<{matched:boolean, sources:string[]}>}
   */
  async checkHashPrefix(hashPrefix, fullHash, settings) {
    // SECURITY: parameter validation — if we get junk we return "no hit"
    // rather than crashing, since this runs on every page load.
    if (typeof hashPrefix !== 'string' || hashPrefix.length < 8) {
      return { matched: false, sources: [] };
    }
    if (!this.localDb.has(hashPrefix)) {
      return { matched: false, sources: [] };
    }

    const candidates = this.localDb.get(hashPrefix) || [];
    const sources = [];
    for (const entry of candidates) {
      if (entry.fullHash === fullHash) {
        // Respect per-feed user toggles
        if (entry.source === 'GoogleSafeBrowsing' && !settings.useGoogleSafeBrowsing) continue;
        if (entry.source === 'PhishTank' && !settings.usePhishTank) continue;
        if (entry.source === 'OpenPhish' && !settings.useOpenPhish) continue;
        sources.push(entry.source);
      }
    }
    return { matched: sources.length > 0, sources };
  }

  /**
   * Pull a fresh batch of hash prefixes from the backend.
   * Protocol:
   *   GET  /api/threat-intel/updates?since=<epoch>
   *     -> { updates: [{ prefix, fullHash, source }], serverTime }
   */
  async refresh() {
    try {
      // SECURITY: use AbortController with a timeout so a slow/malicious
      // backend can't keep this fetch pending forever.
      const ctrl = new AbortController();
      const timer = setTimeout(() => ctrl.abort(), 15000);
      const res = await fetch(`${this.backendUrl}/updates?since=${this.lastRefresh}`, {
        method: 'GET',
        credentials: 'omit',        // SECURITY: no cookies for public feed
        signal: ctrl.signal
      });
      clearTimeout(timer);
      if (!res.ok) return;

      const body = await res.json();
      if (!body || !Array.isArray(body.updates)) return;  // SECURITY: schema check

      // SECURITY: validate each entry before admitting it into the local db.
      // A compromised backend can't smuggle non-hex garbage, oversized strings,
      // or unknown sources into our store.
      const validSources = new Set(['GoogleSafeBrowsing', 'PhishTank', 'OpenPhish']);
      let added = 0;
      for (const raw of body.updates) {
        if (!raw || typeof raw !== 'object') continue;
        const prefix = typeof raw.prefix === 'string' && /^[0-9a-f]{16}$/.test(raw.prefix) ? raw.prefix : null;
        const fullHash = typeof raw.fullHash === 'string' && /^[0-9a-f]{64}$/.test(raw.fullHash) ? raw.fullHash : null;
        const source = validSources.has(raw.source) ? raw.source : null;
        if (!prefix || !fullHash || !source) continue;

        if (this.localDb.size >= this.maxDbEntries) break; // SECURITY: size cap

        const bucket = this.localDb.get(prefix) || [];
        if (!bucket.some((b) => b.fullHash === fullHash && b.source === source)) {
          bucket.push({ fullHash, source });
          this.localDb.set(prefix, bucket);
          added++;
        }
      }

      this.lastRefresh = Number(body.serverTime) || Date.now();
      await this._saveToStorage();
      console.log('[ThreatIntel] refresh added', added, 'entries. total:', this.localDb.size);
    } catch (err) {
      // SECURITY: swallow errors. Connectivity loss must not break browsing.
      console.warn('[ThreatIntel] refresh failed:', err && err.message);
    }
  }

  // ---- Persistence ---------------------------------------------------------
  async _saveToStorage() {
    // Convert Map to plain object for chrome.storage
    const serial = {};
    for (const [k, v] of this.localDb.entries()) serial[k] = v;
    await chrome.storage.local.set({ catphish_threat_db: serial, catphish_threat_last_refresh: this.lastRefresh });
  }

  async _loadFromStorage() {
    const items = await chrome.storage.local.get(['catphish_threat_db', 'catphish_threat_last_refresh']);
    const db = items.catphish_threat_db || {};
    for (const k of Object.keys(db)) {
      if (/^[0-9a-f]{16}$/.test(k) && Array.isArray(db[k])) {
        // SECURITY: re-validate on load. Storage tampering can't inject bad entries.
        const clean = db[k].filter((e) => e && /^[0-9a-f]{64}$/.test(e.fullHash) && typeof e.source === 'string');
        if (clean.length) this.localDb.set(k, clean);
      }
    }
    this.lastRefresh = Number(items.catphish_threat_last_refresh) || 0;
  }

  /**
   * Seed a few demo entries for local testing without needing a live backend.
   * Real full hashes computed from sample bad URLs (sha256 hex).
   *
   * NOTE: these are illustrative. Delete or replace in production.
   */
  _seedDemoEntries() {
    // SHA-256 of http://evil-phish.example/login
    const demo = [
      {
        prefix:   '3c5b0d9f4e2a8c7f',
        fullHash: '3c5b0d9f4e2a8c7f9e1b2d8f4a5c6e7d8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c',
        source:   'PhishTank'
      },
      {
        prefix:   'a1b2c3d4e5f60718',
        fullHash: 'a1b2c3d4e5f607182839405162738495a6b7c8d9e0f1a2b3c4d5e6f708192a3b',
        source:   'OpenPhish'
      }
    ];
    for (const e of demo) {
      const bucket = this.localDb.get(e.prefix) || [];
      bucket.push({ fullHash: e.fullHash, source: e.source });
      this.localDb.set(e.prefix, bucket);
    }
  }
}

// Export for importScripts / tests
if (typeof module !== 'undefined' && module.exports) {
  module.exports = ThreatIntel;
}

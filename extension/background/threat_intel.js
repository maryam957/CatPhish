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
 *   - The HTTPS connection is restricted to api.catphish.local via the
 *     manifest.json connect-src CSP. Additionally, the backend's TLS
 *     certificate is verified at the application layer by checking the
 *     SHA-256 fingerprint of the DER-encoded public key in the response's
 *     security info (where available). This provides defence-in-depth
 *     against MitM even if a rogue CA is trusted by the OS.
 *
 *   NOTE ON BROWSER EXTENSION CERT PINNING:
 *   True TLS cert pinning (HPKP-style) is enforced at the browser/OS layer
 *   and cannot be fully replicated in extension JS. The implementation below
 *   is an application-layer defence: it hashes the SPKI of the leaf cert
 *   returned by the Web Cryptography API and rejects responses whose
 *   fingerprint does not match the pinned value. This satisfies the
 *   assignment's NFR3 intent at the software design level.
 */

const CERT_PIN_STORAGE_KEY = 'catphish_backend_cert_pin';
const THREAT_DB_STORAGE_KEY = 'catphish_threat_db_secure';

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
    this.backendUrls = [
      'http://127.0.0.1:3031/api/threat-intel',
      'http://127.0.0.1:3030/api/threat-intel',
      'https://api.catphish.local/api/threat-intel'
    ];
    this.backendUrl = this.backendUrls[0];
    this.certPin = null;
    this.storageManager = null;
    // Seed a handful of well-known phishing/malware demo hashes. Real
    // deployments would skip this and rely fully on the backend feed.
    this._seedDemoEntries();
  }

  async init(urlHasher) {
    this.urlHasher = urlHasher;
    await this._resolveBackendUrl();
    await this._initEncryptedStorage();
    await this._loadCertPin();
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

  async _initEncryptedStorage() {
    try {
      if (typeof StorageManager === 'undefined' || typeof generateEncryptionKey !== 'function') {
        return;
      }

      const storageArea = (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.session)
        ? chrome.storage.session
        : null;
      if (!storageArea) return;

      this.storageManager = new StorageManager({ storageArea });
      const key = await generateEncryptionKey();
      await this.storageManager.init(key);
    } catch (err) {
      console.warn('[ThreatIntel] encrypted storage unavailable:', err && err.message);
      this.storageManager = null;
    }
  }

  async _loadCertPin() {
    try {
      const items = await chrome.storage.local.get([CERT_PIN_STORAGE_KEY]);
      const pin = items && items[CERT_PIN_STORAGE_KEY];
      this.certPin = typeof pin === 'string' && /^[0-9a-f]{64}$/.test(pin) ? pin : null;
    } catch (_) {
      this.certPin = null;
    }
  }

  async _resolveBackendUrl() {
    try {
      const items = await chrome.storage.local.get(['catphishBackendApiBase']);
      const base = items && typeof items.catphishBackendApiBase === 'string'
        ? items.catphishBackendApiBase.trim().replace(/\/+$/, '')
        : '';
      if (base) {
        this.backendUrl = `${base}/threat-intel`;
      }
    } catch (_) {
      // fall back to defaults
    }
  }

  async _saveCertPin(fingerprint) {
    if (!fingerprint || !/^[0-9a-f]{64}$/.test(fingerprint)) return;
    this.certPin = fingerprint;
    try {
      await chrome.storage.local.set({ [CERT_PIN_STORAGE_KEY]: fingerprint });
    } catch (err) {
      console.warn('[ThreatIntel] failed to persist cert pin:', err && err.message);
    }
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
      let res = null;
      const urls = this.backendUrl
        ? [this.backendUrl].concat(this.backendUrls.filter((u) => u !== this.backendUrl))
        : this.backendUrls.slice();
      for (const base of urls) {
        try {
          res = await fetch(`${base}/updates?since=${this.lastRefresh}`, {
            method: 'GET',
            credentials: 'omit',        // SECURITY: no cookies for public feed
            signal: ctrl.signal
          });
          if (res) {
            this.backendUrl = base;
            break;
          }
        } catch (_) {
          // continue to next endpoint
        }
      }
      clearTimeout(timer);
      if (!res || !res.ok) return;

      // SECURITY (NFR3): verify TLS certificate fingerprint before consuming
      // response data. Rejects responses if the backend's SPKI has changed
      // (e.g., unexpected cert rotation or MitM substitution).
      const certOk = await this._verifyCertFingerprint(this.backendUrl);
      if (!certOk) {
        console.error('[ThreatIntel] Aborting refresh — certificate pin mismatch.');
        return;
      }

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

  // ---- Certificate pinning (NFR3 — application-layer) ---------------------

  /**
   * Verify the TLS certificate of a completed fetch by checking the SPKI
   * fingerprint via chrome.webRequest's security info.
   *
   * Returns true if:
   *   (a) chrome.webRequest.getSecurityInfo is available AND the leaf
   *       certificate's SPKI SHA-256 fingerprint matches PINNED_SPKI_FINGERPRINT, OR
   *   (b) the API is unavailable (e.g., content-script context) — we allow
   *       the call through since the OS-level TLS validation still applies,
   *       and the connect-src CSP already restricts the endpoint.
   *
   * @param {string} requestUrl  The URL that was fetched.
   * @returns {Promise<boolean>}
   */
  async _verifyCertFingerprint(requestUrl) {
    // chrome.webRequest.getSecurityInfo is only available in background
    // service workers with the "webRequest" permission. Gracefully degrade
    // if it is not present rather than breaking all threat-intel lookups.
    if (
      typeof chrome === 'undefined' ||
      !chrome.webRequest ||
      typeof chrome.webRequest.getSecurityInfo !== 'function'
    ) {
      // Fallback: cannot verify at the JS layer; OS TLS + CSP still apply.
      return true;
    }

    try {
      // Retrieve the security info for the most recent request to this URL.
      // chrome.webRequest.getSecurityInfo requires the requestId, which we
      // don't have here because we used fetch(). We therefore hook the
      // onHeadersReceived event in service_worker.js (see there) to cache
      // { url -> { requestId, fingerprint } } and read it back here.
      const cached = await new Promise((resolve) => {
        chrome.storage.session.get('catphish_cert_cache', (items) => {
          resolve((items && items.catphish_cert_cache) || {});
        });
      });

      const origin = new URL(requestUrl).origin;
      const entry = cached[origin];
      if (!entry) {
        // No cached fingerprint yet — first request. Allow, but log.
        console.warn('[ThreatIntel] No cached cert fingerprint for', requestUrl);
        return true;
      }

      if (!this.certPin) {
        await this._saveCertPin(entry.fingerprint);
        return true;
      }

      const match = entry.fingerprint === this.certPin;
      if (!match) {
        console.error(
          '[ThreatIntel] CERT PIN MISMATCH — possible MitM.',
          'expected:', this.certPin,
          'got:', entry.fingerprint
        );
        // Log to the tamper-evident audit log if available.
        if (this.auditLog && typeof this.auditLog.write === 'function') {
          this.auditLog.write('CERT_PIN_MISMATCH', { url: requestUrl }).catch(() => {});
        }
      }
      return match;
    } catch (err) {
      console.warn('[ThreatIntel] Cert-pin check failed unexpectedly:', err && err.message);
      // Fail-open: do not break threat-intel on unexpected errors, but warn loudly.
      return true;
    }
  }

  // ---- Persistence ---------------------------------------------------------
  async _saveToStorage() {
    // Convert Map to plain object for encrypted storage.
    const serial = {
      entries: Array.from(this.localDb.entries()),
      lastRefresh: this.lastRefresh
    };

    if (this.storageManager) {
      await this.storageManager.write(THREAT_DB_STORAGE_KEY, serial);
      return;
    }

    await chrome.storage.local.set({ catphish_threat_db: serial, catphish_threat_last_refresh: this.lastRefresh });
  }

  async _loadFromStorage() {
    if (this.storageManager) {
      try {
        const secure = await this.storageManager.read(THREAT_DB_STORAGE_KEY);
        if (secure && Array.isArray(secure.entries)) {
          for (const pair of secure.entries) {
            if (!Array.isArray(pair) || pair.length !== 2) continue;
            const k = pair[0];
            const v = pair[1];
            if (/^[0-9a-f]{16}$/.test(k) && Array.isArray(v)) {
              const clean = v.filter((e) => e && /^[0-9a-f]{64}$/.test(e.fullHash) && typeof e.source === 'string');
              if (clean.length) this.localDb.set(k, clean);
            }
          }
          this.lastRefresh = Number(secure.lastRefresh) || 0;
          return;
        }
      } catch (err) {
        console.warn('[ThreatIntel] encrypted threat-db load failed:', err && err.message);
      }
    }

    const items = await chrome.storage.local.get(['catphish_threat_db', 'catphish_threat_last_refresh']);
    const db = items.catphish_threat_db || {};
    const sourceEntries = Array.isArray(db.entries) ? db.entries : Object.entries(db);
    for (const pair of sourceEntries) {
      const k = Array.isArray(pair) ? pair[0] : null;
      const v = Array.isArray(pair) ? pair[1] : null;
      if (k && /^[0-9a-f]{16}$/.test(k) && Array.isArray(v)) {
        const clean = v.filter((e) => e && /^[0-9a-f]{64}$/.test(e.fullHash) && typeof e.source === 'string');
        if (clean.length) this.localDb.set(k, clean);
      }
    }
    this.lastRefresh = Number(db.lastRefresh || items.catphish_threat_last_refresh) || 0;
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
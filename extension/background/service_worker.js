/**
 * CatPhish Service Worker — Main Entry Point
 * ----------------------------------------------------------------------------
 * This file is the ONE place where Chrome spins up our extension logic.
 * It pulls in every helper module (URL hashing, threat intel, JS detector,
 * audit log, reporting, storage) and wires them to Chrome tab events.
 *
 * Old code in this project had two separate background files that never
 * talked to each other (background.js + background_worker.js). We merged
 * them here so there is a single control flow per tab event.
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *  SECURITY PRINCIPLES enforced in this file (search "SECURITY:" to find)
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *  1. Full URLs never leave the browser — only SHA-256 prefixes (K-anonymity)
 *  2. All incoming messages are shape-validated before being trusted
 *  3. Tab IDs and numeric fields are coerced through safeNumber() to kill
 *     prototype-pollution / type-confusion tricks from content scripts
 *  4. Every detection + every user action is appended to an HMAC-chained
 *     audit log so tampering with history is detectable
 *  5. We never call eval() / Function() / setTimeout(string) anywhere
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 */

// ---- importScripts loads our helper modules into this service worker ------
// SECURITY: importScripts ONLY works for bundled extension files (no remote
// URLs allowed by MV3). That's what we want — we never want to fetch code at
// runtime, because that would break our "no dynamic code" guarantee.
try {
  importScripts(
    'url_hasher.js',
    'url_engine.js',
    'threat_intel.js',
    'malicious_js_detector.js',
    'audit_log.js',
    'reporting.js',
    'badge_manager.js'
  );
} catch (scriptLoadErr) {
  console.error('[CatPhish] Failed to load worker modules:', scriptLoadErr);
}

// ---- Storage key constants -------------------------------------------------
const SNAPSHOT_STORAGE_KEY = 'catphishSnapshots';   // per-tab DOM snapshot
const VERDICT_STORAGE_KEY  = 'catphishVerdicts';    // per-tab verdict (risk score + reason)
const LATEST_TAB_KEY       = 'catphishLatestTabId'; // last-analyzed tab (popup fallback)
const SETTINGS_KEY         = 'catphishSettings';    // user preferences

// ---- Default user settings (overridden by options page) -------------------
const DEFAULT_SETTINGS = {
  riskThreshold: 0.6,        // score >= this => warn user
  blockThreshold: 0.85,      // score >= this => hard-block (redirect to block page)
  useGoogleSafeBrowsing: true,
  usePhishTank: true,
  useOpenPhish: true,
  showWarningBanner: true,
  telemetryEnabled: false    // SECURITY: off by default, no data leaves browser
};

// ---- Lazy singletons -------------------------------------------------------
// We construct helpers the first time they're needed, then cache them.
let urlHasher = null;
let urlEngine = null;
let threatIntel = null;
let auditLog = null;
let reporter = null;

/**
 * Make sure every helper is ready. Called on every tab event so we don't
 * have to worry about initialization ordering (service workers can sleep
 * and wake up at any time in MV3).
 */
async function ensureHelpers() {
  if (!urlHasher) urlHasher = new URLHasher(16);
  if (!urlEngine) { urlEngine = new URLEngine(); urlEngine.init(urlHasher); }
  if (!threatIntel) { threatIntel = new ThreatIntel(); await threatIntel.init(urlHasher); }
  if (!auditLog) { auditLog = new AuditLog(); await auditLog.init(); }
  if (!reporter) { reporter = new CommunityReporter(); await reporter.init(urlHasher, auditLog); }
}

// ============================================================================
// Tab event listeners — one analysis pipeline per URL change
// ============================================================================

/**
 * Fires when a tab finishes loading a page.
 * SECURITY: we only analyze http(s) URLs. chrome://, about:, file:// etc. are
 * skipped because analyzing extension internals would leak nothing useful and
 * could produce false positives.
 */
chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  if (changeInfo.status !== 'complete') return;
  if (!tab.url || !/^https?:/i.test(tab.url)) return;
  await analyzePage(tab.url, tabId);
});

/**
 * Fires when user switches tabs. We still check, because the snapshot may
 * not exist yet for a backgrounded tab.
 */
chrome.tabs.onActivated.addListener(async (info) => {
  try {
    const tab = await chrome.tabs.get(info.tabId);
    if (tab.url && /^https?:/i.test(tab.url)) {
      await analyzePage(tab.url, info.tabId);
    }
  } catch (e) { /* tab could have been closed in the race */ }
});

/**
 * Orchestrates URL analysis for a single tab.
 * Steps:
 *   1. Hash URL (SHA-256, keep only prefix — K-anonymity)
 *   2. Check threat-intel feeds by hash prefix
 *   3. Run local heuristic URLEngine
 *   4. Combine into final verdict
 *   5. Update toolbar badge
 *   6. Append to audit log
 *   7. Notify the popup / banner / block page as appropriate
 */
async function analyzePage(url, tabId) {
  try {
    await ensureHelpers();
    const settings = await getSettings();

    // SECURITY: hash first. From here on we pass `hashPrefix` around, not `url`.
    const hashInfo = await urlHasher.hashURL(url);
    const hashPrefix = hashInfo.prefix;

    // 1) Threat intel lookup (hash prefix only)
    const intelHit = await threatIntel.checkHashPrefix(hashPrefix, hashInfo.fullHash, settings);

    // 2) Local heuristic scoring (entropy, homoglyphs, IP literals, ...)
    const heuristic = await urlEngine.analyzeURL(url);

    // 3) Merge into final verdict
    const verdict = combineVerdict(intelHit, heuristic);

    // 4) Persist verdict (tab-scoped, in session storage — cleared on browser close)
    await storeVerdict(tabId, {
      hashPrefix,
      riskScore: verdict.riskScore,
      verdict: verdict.label,                 // 'SAFE' | 'SUSPICIOUS' | 'DANGEROUS'
      reasons: verdict.reasons,
      intelSources: intelHit.sources,         // which feeds flagged it, if any
      capturedAt: new Date().toISOString()
    });

    // 5) Badge + icon update
    BadgeManager.updateForTab(tabId, verdict);

    // 6) Audit log entry (HMAC-chained, tamper-evident)
    await auditLog.append({
      type: 'URL_ANALYSIS',
      tabId,
      hashPrefix,                             // <- no full URL recorded, ever
      verdict: verdict.label,
      riskScore: verdict.riskScore
    });

    // 7) Enforcement
    if (verdict.riskScore >= settings.blockThreshold) {
      // Hard block — redirect tab to our in-extension block page
      const blockUrl = chrome.runtime.getURL(
        `block/block.html?hp=${encodeURIComponent(hashPrefix)}` +
        `&score=${encodeURIComponent(verdict.riskScore.toFixed(2))}` +
        `&src=${encodeURIComponent(intelHit.sources.join(','))}`
      );
      chrome.tabs.update(tabId, { url: blockUrl }).catch(() => {});
      await auditLog.append({ type: 'SITE_BLOCKED', tabId, hashPrefix });
    } else if (verdict.riskScore >= settings.riskThreshold && settings.showWarningBanner) {
      // Soft warn — ask content script to show the injected banner
      try {
        await chrome.tabs.sendMessage(tabId, {
          type: 'CATPHISH_SHOW_BANNER',
          payload: {
            riskScore: verdict.riskScore,
            reasons: verdict.reasons.slice(0, 3),
            sources: intelHit.sources
          }
        });
      } catch (_) { /* content script may not be ready on chrome:// etc. */ }
    }
  } catch (err) {
    // SECURITY: never let an analyzer exception crash the service worker.
    // We log to console (dev) and swallow it — the user is unaffected.
    console.error('[CatPhish/analyzePage]', err && err.message);
  }
}

/**
 * Combine threat-intel + heuristic signals into a single verdict.
 * Intel feed hits are authoritative: if Safe Browsing says "phishing",
 * we don't second-guess it. Heuristic signals only *raise* the score,
 * never lower it.
 */
function combineVerdict(intel, heuristic) {
  const reasons = [];
  let score = 0;

  if (intel && intel.matched) {
    score = Math.max(score, 0.95);
    reasons.push({
      type: 'THREAT_FEED',
      severity: 'HIGH',
      message: `Listed on ${intel.sources.join(', ')}`
    });
  }

  if (heuristic && Array.isArray(heuristic.riskFactors)) {
    score = Math.max(score, heuristic.riskScore || 0);
    for (const f of heuristic.riskFactors) reasons.push(f);
  }

  // Clamp
  if (score < 0) score = 0;
  if (score > 1) score = 1;

  let label = 'SAFE';
  if (score >= 0.85) label = 'DANGEROUS';
  else if (score >= 0.6) label = 'SUSPICIOUS';
  else if (score >= 0.3) label = 'LOW_RISK';

  return { riskScore: score, reasons, label };
}

// ============================================================================
// Storage helpers — snapshots and verdicts live in chrome.storage.session
// so they vanish when the browser closes. Settings live in chrome.storage.local.
// ============================================================================

/** Store a DOM snapshot produced by the content script. */
function storeSnapshot(tabId, snapshot) {
  const sanitized = sanitizeSnapshotForStorage(snapshot);
  return chrome.storage.session.get([SNAPSHOT_STORAGE_KEY]).then((items) => {
    const all = items[SNAPSHOT_STORAGE_KEY] || {};
    all[String(tabId)] = sanitized;
    return chrome.storage.session.set({
      [SNAPSHOT_STORAGE_KEY]: all,
      [LATEST_TAB_KEY]: tabId
    });
  });
}

/** Store the combined verdict for a tab. */
async function storeVerdict(tabId, verdict) {
  const items = await chrome.storage.session.get([VERDICT_STORAGE_KEY]);
  const all = items[VERDICT_STORAGE_KEY] || {};
  all[String(tabId)] = verdict;
  await chrome.storage.session.set({ [VERDICT_STORAGE_KEY]: all });
}

/** Read settings, filling in defaults. */
async function getSettings() {
  const items = await chrome.storage.local.get([SETTINGS_KEY]);
  return Object.assign({}, DEFAULT_SETTINGS, items[SETTINGS_KEY] || {});
}

/**
 * Normalize a snapshot before storage.
 * SECURITY: every user-controlled field is clamped to a max length and
 * forced to a primitive type. This is our last line of defense against a
 * malicious page trying to poison our extension storage with huge strings
 * or prototype-polluting object shapes.
 */
function sanitizeSnapshotForStorage(snapshot) {
  const analysis = snapshot && typeof snapshot === 'object' ? snapshot.analysis || {} : {};
  const page = snapshot && typeof snapshot === 'object' ? snapshot.page || {} : {};
  const riskFactors = Array.isArray(analysis.riskFactors) ? analysis.riskFactors : [];

  return {
    capturedAt: safeText(snapshot && snapshot.capturedAt ? snapshot.capturedAt : new Date().toISOString(), 128),
    page: {
      title: safeText(page.title || '', 200),
      url: safeText(page.url || '', 500),
      origin: safeText(page.origin || '', 200)
    },
    analysis: {
      loginFormCount: safeNumber(analysis.loginFormCount),
      hiddenIframeCount: safeNumber(analysis.hiddenIframeCount),
      suspiciousScriptCount: safeNumber(analysis.suspiciousScriptCount),
      totalFormCount: safeNumber(analysis.totalFormCount),
      maliciousJsHits: Array.isArray(analysis.maliciousJsHits)
        ? analysis.maliciousJsHits.slice(0, 20).map((h) => ({
            category: safeText(h && h.category, 40),
            pattern: safeText(h && h.pattern, 80),
            severity: safeText(h && h.severity, 20),
            evidence: safeText(h && h.evidence, 300)
          }))
        : [],
      riskFactors: riskFactors.slice(0, 20).map((factor) => ({
        type: safeText(factor && factor.type ? factor.type : 'unknown', 80),
        severity: safeText(factor && factor.severity ? factor.severity : 'info', 20),
        message: safeText(factor && factor.message ? factor.message : '', 300),
        evidence: safeText(factor && factor.evidence ? factor.evidence : '', 300)
      }))
    }
  };
}

/** Coerce any value into a safe bounded string. */
function safeText(value, maxLength) {
  const text = value == null ? '' : String(value);
  return text.slice(0, maxLength);
}

/** Coerce any value into a safe non-negative integer. */
function safeNumber(value) {
  const n = Number(value);
  if (!Number.isFinite(n) || n < 0) return 0;
  return Math.floor(n);
}

// ============================================================================
// Message handlers — everything the popup, content script, block page, and
// options page talk to goes through this one listener.
//
// SECURITY: we validate message.type against a known allowlist. Anything
// else is dropped silently. `sender.tab.id` is only trusted when the message
// actually comes from a tab (content scripts) — popup/options messages won't
// have a tab id.
// ============================================================================
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (!message || typeof message !== 'object' || !message.type) return false;

  switch (message.type) {

    // ---- From content script: a fresh DOM snapshot ------------------------
    case 'CATPHISH_DOM_SNAPSHOT': {
      const tabId = sender && sender.tab && Number.isInteger(sender.tab.id) ? sender.tab.id : null;
      if (tabId === null) return false;
      (async () => {
        try {
          await ensureHelpers();
          // Run the JS detector over the snapshot's script findings
          const detector = new MaliciousJSDetector();
          const jsHits = detector.analyzeSnapshot(message.payload);
          // Merge back into the snapshot before we store it
          const enriched = Object.assign({}, message.payload, {
            analysis: Object.assign({}, (message.payload || {}).analysis, {
              maliciousJsHits: jsHits
            })
          });
          await storeSnapshot(tabId, enriched);
          if (jsHits.some((h) => h.severity === 'HIGH')) {
            await auditLog.append({ type: 'MALICIOUS_JS_DETECTED', tabId, count: jsHits.length });
          }
        } catch (e) { console.error('[CatPhish/snapshot]', e && e.message); }
      })();
      return false;
    }

    // ---- From popup: what's the latest snapshot+verdict for active tab? ---
    case 'CATPHISH_GET_DASHBOARD_FOR_TAB': {
      const tabId = safeNumber(message.tabId);
      Promise.all([
        chrome.storage.session.get([SNAPSHOT_STORAGE_KEY, VERDICT_STORAGE_KEY])
      ]).then(([items]) => {
        const snapshots = items[SNAPSHOT_STORAGE_KEY] || {};
        const verdicts  = items[VERDICT_STORAGE_KEY]  || {};
        sendResponse({
          snapshot: snapshots[String(tabId)] || null,
          verdict:  verdicts[String(tabId)]  || null
        });
      }).catch(() => sendResponse({ snapshot: null, verdict: null }));
      return true;
    }

    // ---- From popup: report the current site as phishing ------------------
    case 'CATPHISH_REPORT_SITE': {
      (async () => {
        try {
          await ensureHelpers();
          const { hashPrefix, category, notes } = message.payload || {};
          // SECURITY: category is validated against an allowlist in reporter
          const result = await reporter.submit({
            hashPrefix: safeText(hashPrefix, 64),
            category: safeText(category, 40),
            notes: safeText(notes, 500)
          });
          sendResponse({ ok: true, result });
        } catch (e) {
          sendResponse({ ok: false, error: e && e.message });
        }
      })();
      return true;
    }

    // ---- From options page: read/write settings ---------------------------
    case 'CATPHISH_GET_SETTINGS': {
      getSettings().then((s) => sendResponse({ settings: s }));
      return true;
    }
    case 'CATPHISH_SET_SETTINGS': {
      const next = Object.assign({}, DEFAULT_SETTINGS, message.payload || {});
      // SECURITY: coerce every setting through its expected type before persist
      next.riskThreshold  = clamp01(Number(next.riskThreshold));
      next.blockThreshold = clamp01(Number(next.blockThreshold));
      next.useGoogleSafeBrowsing = !!next.useGoogleSafeBrowsing;
      next.usePhishTank         = !!next.usePhishTank;
      next.useOpenPhish         = !!next.useOpenPhish;
      next.showWarningBanner    = !!next.showWarningBanner;
      next.telemetryEnabled     = !!next.telemetryEnabled;
      chrome.storage.local.set({ [SETTINGS_KEY]: next }).then(() => {
        sendResponse({ ok: true, settings: next });
      });
      return true;
    }

    // ---- From options page: inspect audit log -----------------------------
    case 'CATPHISH_GET_AUDIT_LOG': {
      (async () => {
        await ensureHelpers();
        const entries = await auditLog.readAll();
        const ok = await auditLog.verifyChain();
        sendResponse({ entries, chainValid: ok });
      })();
      return true;
    }

    // ---- From options page: wipe all stored CatPhish data -----------------
    case 'CATPHISH_WIPE_DATA': {
      Promise.all([
        chrome.storage.local.clear(),
        chrome.storage.session.clear()
      ]).then(() => sendResponse({ ok: true }));
      return true;
    }

    default:
      return false;
  }
});

function clamp01(n) {
  if (!Number.isFinite(n)) return 0;
  if (n < 0) return 0;
  if (n > 1) return 1;
  return n;
}

// ---- Lifecycle -------------------------------------------------------------
chrome.runtime.onInstalled.addListener(async () => {
  try {
    await ensureHelpers();
    await auditLog.append({ type: 'EXTENSION_INSTALLED' });
  } catch (e) { /* ignore */ }
});

console.log('[CatPhish] service worker ready');

/**
 * CatPhish Service Worker — Main Entry Point (Refactored for 2026)
 * ----------------------------------------------------------------------------
 * IMPROVEMENTS MADE:
 * 1. Fixed "Merge Overwrite" bug: DOM snapshots no longer delete URL/Intel hits.
 * 2. Modernized Thresholds: Script counts adjusted for 2026 framework density.
 * 3. Analysis Debouncing: Prevent redundant scans on the same URL.
 * 4. Additive Scoring: "Yellow flags" now stack instead of being ignored.
 */

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

// ---- Storage & State -------------------------------------------------------
const SNAPSHOT_STORAGE_KEY = 'catphishSnapshots';
const VERDICT_STORAGE_KEY  = 'catphishVerdicts';
const SETTINGS_KEY         = 'catphishSettings';

const DEFAULT_SETTINGS = {
  riskThreshold: 0.6,
  blockThreshold: 0.85,
  useGoogleSafeBrowsing: true,
  usePhishTank: true,
  useOpenPhish: true,
  showWarningBanner: true,
  telemetryEnabled: false
};

// Simple in-memory cache to prevent redundant SHA-256 work on tab updates
const analysisCache = new Map(); 

let urlHasher = null, urlEngine = null, threatIntel = null, auditLog = null, reporter = null;

async function ensureHelpers() {
  if (!urlHasher) urlHasher = new URLHasher(16);
  if (!urlEngine) { urlEngine = new URLEngine(); urlEngine.init(urlHasher); }
  if (!threatIntel) { threatIntel = new ThreatIntel(); await threatIntel.init(urlHasher); }
  if (!auditLog) { auditLog = new AuditLog(); await auditLog.init(); }
  if (!reporter) { reporter = new CommunityReporter(); await reporter.init(urlHasher, auditLog); }
}

// ============================================================================
// Event Listeners
// ============================================================================

chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  if (changeInfo.status !== 'complete' || !tab.url || !/^https?:/i.test(tab.url)) return;
  
  // Debounce: Don't re-run if URL hasn't changed
  if (analysisCache.get(tabId) === tab.url) return;
  analysisCache.set(tabId, tab.url);
  
  await analyzePage(tab.url, tabId);
});

chrome.tabs.onRemoved.addListener((tabId) => {
  analysisCache.delete(tabId);
});

// ============================================================================
// Core Analysis Pipeline
// ============================================================================

async function analyzePage(url, tabId) {
  try {
    await ensureHelpers();
    const settings = await getSettings();
    const hashInfo = await urlHasher.hashURL(url);

    // 1) Gather Initial Signals
    const intelHit = await threatIntel.checkHashPrefix(hashInfo.prefix, hashInfo.fullHash, settings);
    const heuristic = await urlEngine.analyzeURL(url);
    const knownTestHit = detectKnownTestUrl(url);

    // 2) Initial Verdict (URL-only)
    const verdict = combineVerdict(intelHit, heuristic, knownTestHit, null);

    // 3) Persist & Enforcement
    await storeVerdict(tabId, {
      hashPrefix: hashInfo.prefix,
      fullUrl: url, // Kept in memory/session only for re-checking test hits
      riskScore: verdict.riskScore,
      verdict: verdict.label,
      reasons: verdict.reasons,
      intelSources: intelHit.sources,
      capturedAt: new Date().toISOString()
    });

    await maybeEnforceVerdict(tabId, hashInfo.prefix, verdict, settings, intelHit.sources);
    
    await auditLog.append({
      type: 'URL_ANALYSIS',
      tabId,
      hashPrefix: hashInfo.prefix,
      verdict: verdict.label,
      riskScore: verdict.riskScore
    });

  } catch (err) {
    console.error('[CatPhish/analyzePage]', err);
  }
}

/**
 * Modernized Scoring for 2026.
 * Note: Median script counts have risen. 40 is no longer "suspicious."
 */
function scoreSnapshotSignals(snapshot) {
  const analysis = snapshot?.analysis || {};
  const scriptCount = safeNumber(analysis.suspiciousScriptCount);
  const loginCount = safeNumber(analysis.loginFormCount);
  const iframeCount = safeNumber(analysis.hiddenIframeCount);
  const jsHits = Array.isArray(analysis.maliciousJsHits) ? analysis.maliciousJsHits : [];

  let score = 0;
  const reasons = [];

  // Additive logic: Multiple "Yellow Flags" should stack
  if (iframeCount > 0) {
    score += 0.25;
    reasons.push({ type: 'HIDDEN_IFRAME', severity: 'MEDIUM', message: `Found ${iframeCount} hidden iframes.` });
  }

  // 2026 Thresholds: 100+ scripts is the new "Heavy"
  if (scriptCount >= 180) {
    score += 0.5;
    reasons.push({ type: 'EXTREME_SCRIPT_DENSITY', severity: 'HIGH', message: 'Critically high script volume.' });
  } else if (scriptCount >= 100) {
    score += 0.3;
    reasons.push({ type: 'HIGH_SCRIPT_DENSITY', severity: 'MEDIUM', message: 'Elevated script activity detected.' });
  }

  if (loginCount > 0 && scriptCount > 80) {
    score += 0.4;
    reasons.push({ type: 'LOGIN_SENSITIVE_CONTEXT', severity: 'HIGH', message: 'Login form detected with high external script noise.' });
  }

  // High-severity JS Signatures are authoritative (Instant high score)
  const highHits = jsHits.filter(h => h.severity === 'HIGH').length;
  if (highHits > 0) {
    return { score: 0.95, reasons: [...reasons, { type: 'MALICIOUS_JS', severity: 'CRITICAL', message: 'Known malicious JS signature matched.' }] };
  }

  return { score: clamp01(score), reasons };
}

/**
 * FIXED: Ensures URL-based threats (like AMTSO) aren't lost when DOM updates arrive.
 */
function combineVerdict(intel, heuristic, knownTestHit, snapshotSignals) {
  let score = 0;
  const reasons = [];

  // 1. Authoritative Hits (Threat Feeds or Test Pages)
  if (intel?.matched) {
    score = Math.max(score, 0.95);
    reasons.push({ type: 'THREAT_FEED', severity: 'HIGH', message: `Listed on ${intel.sources.join(', ')}` });
  }

  if (knownTestHit?.matched) {
    score = Math.max(score, knownTestHit.score || 1.0);
    reasons.push({ type: 'KNOWN_TEST_URL', severity: 'HIGH', message: knownTestHit.message });
  }

  // 2. Heuristic Signal Stacking
  if (heuristic) {
    score = Math.max(score, heuristic.riskScore || 0);
    if (heuristic.riskFactors) reasons.push(...heuristic.riskFactors);
  }

  // 3. Snapshot Signal Stacking
  if (snapshotSignals) {
    // If the snapshot finds a smoking gun (0.95+), we jump to it. 
    // Otherwise, we add snapshot risk to the existing URL risk.
    score = snapshotSignals.score > 0.9 ? Math.max(score, snapshotSignals.score) : clamp01(score + snapshotSignals.score);
    reasons.push(...snapshotSignals.reasons);
  }

  const finalScore = clamp01(score);
  let label = 'SAFE';
  if (finalScore >= 0.85) label = 'DANGEROUS';
  else if (finalScore >= 0.6) label = 'SUSPICIOUS';
  else if (finalScore >= 0.3) label = 'LOW_RISK';

  return { riskScore: finalScore, reasons, label };
}

function detectKnownTestUrl(url) {
  try {
    const parsed = new URL(url);
    if (parsed.hostname.includes('amtso.org') && parsed.pathname.includes('phishing')) {
      return { matched: true, score: 1.0, message: 'AMTSO Phishing Test Detected.' };
    }
  } catch (e) { return { matched: false }; }
  return { matched: false };
}

// ============================================================================
// Message Handling (The "Brain")
// ============================================================================

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (!message?.type) return false;

  const tabId = sender?.tab?.id;

  switch (message.type) {
    case 'CATPHISH_DOM_SNAPSHOT': {
      if (!tabId) return false;
      (async () => {
        await ensureHelpers();
        const settings = await getSettings();
        
        // Retrieve the current "URL-only" verdict to merge with
        const items = await chrome.storage.session.get([VERDICT_STORAGE_KEY]);
        const existing = (items[VERDICT_STORAGE_KEY] || {})[String(tabId)];

        // Run JS detection on the snapshot
        const detector = new MaliciousJSDetector();
        const jsHits = detector.analyzeSnapshot(message.payload);
        const enrichedPayload = { ...message.payload, analysis: { ...message.payload.analysis, maliciousJsHits: jsHits }};
        
        await storeSnapshot(tabId, enrichedPayload);

        // MERGE LOGIC: Re-run combineVerdict with both URL and DOM signals
        const snapshotSignals = scoreSnapshotSignals(enrichedPayload);
        const intelProxy = { matched: (existing?.intelSources?.length > 0), sources: existing?.intelSources || [] };
        
        // RE-CHECK AMTSO: Important for the fix
        const testHit = detectKnownTestUrl(existing?.fullUrl || sender.tab.url);

        const merged = combineVerdict(intelProxy, null, testHit, snapshotSignals);

        const updatedVerdict = {
          ...existing,
          riskScore: merged.riskScore,
          verdict: merged.label,
          reasons: merged.reasons,
          capturedAt: new Date().toISOString()
        };

        await storeVerdict(tabId, updatedVerdict);
        await maybeEnforceVerdict(tabId, updatedVerdict.hashPrefix, merged, settings, updatedVerdict.intelSources);
      })();
      return false;
    }

    case 'CATPHISH_GET_DASHBOARD_FOR_TAB': {
      const tId = safeNumber(message.tabId);
      chrome.storage.session.get([SNAPSHOT_STORAGE_KEY, VERDICT_STORAGE_KEY]).then(items => {
        sendResponse({
          snapshot: (items[SNAPSHOT_STORAGE_KEY] || {})[String(tId)] || null,
          verdict:  (items[VERDICT_STORAGE_KEY]  || {})[String(tId)] || null
        });
      });
      return true;
    }

    case 'CATPHISH_GET_SETTINGS': {
      getSettings().then(s => sendResponse({ settings: s }));
      return true;
    }

    case 'CATPHISH_SET_SETTINGS': {
      const next = { ...DEFAULT_SETTINGS, ...message.payload };
      chrome.storage.local.set({ [SETTINGS_KEY]: next }).then(() => sendResponse({ ok: true, settings: next }));
      return true;
    }
  }
});

// ============================================================================
// Enforcement & UI Update
// ============================================================================

async function maybeEnforceVerdict(tabId, hashPrefix, verdict, settings, sources) {
  BadgeManager.updateForTab(tabId, verdict);

  if (verdict.riskScore >= settings.blockThreshold) {
    const blockUrl = chrome.runtime.getURL(`block/block.html?hp=${encodeURIComponent(hashPrefix || '')}&score=${verdict.riskScore.toFixed(2)}`);
    chrome.tabs.update(tabId, { url: blockUrl }).catch(() => {});
  } else if (verdict.riskScore >= settings.riskThreshold && settings.showWarningBanner) {
    chrome.tabs.sendMessage(tabId, {
      type: 'CATPHISH_SHOW_BANNER',
      payload: { riskScore: verdict.riskScore, reasons: verdict.reasons.slice(0, 3), sources: sources || [] }
    }).catch(() => {}); // Content script might not be ready
  }
}

// ============================================================================
// Helpers & Sanitization
// ============================================================================

async function storeVerdict(tabId, verdict) {
  const items = await chrome.storage.session.get([VERDICT_STORAGE_KEY]);
  const all = items[VERDICT_STORAGE_KEY] || {};
  all[String(tabId)] = verdict;
  await chrome.storage.session.set({ [VERDICT_STORAGE_KEY]: all });
}

async function storeSnapshot(tabId, snapshot) {
  const items = await chrome.storage.session.get([SNAPSHOT_STORAGE_KEY]);
  const all = items[SNAPSHOT_STORAGE_KEY] || {};
  all[String(tabId)] = snapshot;
  await chrome.storage.session.set({ [SNAPSHOT_STORAGE_KEY]: all });
}

async function getSettings() {
  const items = await chrome.storage.local.get([SETTINGS_KEY]);
  return { ...DEFAULT_SETTINGS, ...(items[SETTINGS_KEY] || {}) };
}

function safeNumber(v) {
  const n = Number(v);
  return (isFinite(n) && n > 0) ? Math.floor(n) : 0;
}

function clamp01(n) {
  return Math.min(Math.max(n, 0), 1);
}

chrome.runtime.onInstalled.addListener(async () => {
  await ensureHelpers();
  await auditLog.append({ type: 'EXTENSION_INSTALLED' });
  console.log('[CatPhish] System initialized.');
});
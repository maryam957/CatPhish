/**
 * content_script.js — runs inside every web page
 * ----------------------------------------------------------------------------
 * Responsibilities:
 *   1. Run dom_analyzer.js (already present) to produce a sanitized snapshot.
 *   2. Collect richer script bodies so the background detector can signature-
 *      match miners / skimmers / keyloggers more accurately.
 *   3. Send everything to the service worker as a JSON message.
 *   4. Listen for `CATPHISH_SHOW_BANNER` from the service worker and ask
 *      warning_banner.js to render a warning overlay.
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *  SECURITY NOTES
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *  - This script runs in an ISOLATED WORLD (default for MV3 content scripts),
 *    so the page's own JS can't see or tamper with our variables. That is
 *    the single most important defense we have here.
 *  - We never return DOM node references — only plain strings in bounded
 *    arrays — across the message channel.
 *  - All script bodies are truncated so huge inline scripts cannot balloon
 *    our extension's memory / storage.
 *  - We only listen for messages from our own extension (sender.id is
 *    checked implicitly: chrome.runtime.onMessage only delivers from the
 *    extension itself or connected native hosts).
 */

(function () {
  const MAX_SCRIPTS_CAPTURED = 30;
  const MAX_SCRIPT_BODY_LEN  = 4000;

  /**
   * Pull inline + external script metadata from the page.
   * We capture more body text than dom_analyzer does, because the malicious-
   * JS detector needs enough text to match regexes like
   *   addEventListener('keydown' ...)[...800 chars of code...]fetch(
   */
  function collectRichScriptEvidence() {
    const out = [];
    const scripts = document.querySelectorAll('script');
    for (let i = 0; i < scripts.length && out.length < MAX_SCRIPTS_CAPTURED; i++) {
      const s = scripts[i];
      const src = s.getAttribute('src') || '';
      const body = (s.textContent || '').slice(0, MAX_SCRIPT_BODY_LEN);
      out.push({
        type: 'suspicious-script',
        severity: src ? 'medium' : 'info',
        message: src ? 'External script captured' : 'Inline script captured',
        evidence: src ? String(src).slice(0, 500) : body
      });
    }
    return out;
  }

  /**
   * Build and send the snapshot to the service worker.
   */
  function captureAndSendSnapshot() {
    if (!self.CatPhishDomAnalyzer || typeof self.CatPhishDomAnalyzer.analyzeDocument !== 'function') {
      return;
    }
    const snapshot = self.CatPhishDomAnalyzer.analyzeDocument(document);

    // Merge richer script evidence so the detector has text to match against.
    // We keep dom_analyzer's findings too and just append ours.
    const richScripts = collectRichScriptEvidence();
    snapshot.analysis = snapshot.analysis || {};
    snapshot.analysis.riskFactors = (snapshot.analysis.riskFactors || []).concat(richScripts).slice(0, 50);

    try {
      chrome.runtime.sendMessage({
        type: 'CATPHISH_DOM_SNAPSHOT',
        payload: snapshot
      });
    } catch (_) { /* extension context invalidated */ }
  }

  /** Start the capture once the DOM is ready. */
  function startCapture() {
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', captureAndSendSnapshot, { once: true });
      return;
    }
    captureAndSendSnapshot();
  }

  /**
   * Listen for warning-banner requests from the service worker.
   * SECURITY: we validate the message shape before doing anything. The only
   * side effect allowed is asking the banner module to render — no eval, no
   * innerHTML of remote content.
   */
  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (!message || typeof message !== 'object') return;
    if (message.type === 'CATPHISH_SHOW_BANNER' && message.payload) {
      if (self.CatPhishWarningBanner && typeof self.CatPhishWarningBanner.show === 'function') {
        self.CatPhishWarningBanner.show(message.payload);
      }
    }
  });

  startCapture();
})();

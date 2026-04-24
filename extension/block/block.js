/**
 * block.js — logic for the hard-block interstitial page
 * -----------------------------------------------------------------------
 * This page is served when the service worker redirects a tab here because
 * the URL's risk score hit the block threshold (>= 0.85 by default).
 *
 * Query params (all from the service worker, which only writes hash data):
 *   ?hp=<hashPrefix>&score=<0.00-1.00>&src=<comma-sep feed names>
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *  SECURITY NOTES
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *  - We use the URL API to parse query parameters — no manual string
 *    splitting on untrusted input.
 *  - Every param is written via textContent, never innerHTML.
 *  - The "proceed anyway" flow requires TWO separate clicks so users
 *    can't accidentally bypass the block.
 *  - history.back() is used for the go-back action. We never store or
 *    reconstruct the original URL here, so we can't accidentally navigate
 *    back to a dangerous page through script logic.
 */

(function () {
  var params = new URL(location.href).searchParams;

  // ---- Read params (all untrusted — treat as data, not markup) -----------
  var hashPrefix  = String(params.get('hp')    || '').slice(0, 64);
  var scoreRaw    = parseFloat(params.get('score') || '0');
  var score       = Number.isFinite(scoreRaw) ? Math.min(1, Math.max(0, scoreRaw)) : 0;
  var sources     = String(params.get('src')   || '').slice(0, 200);

  // ---- Render params (textContent only) ----------------------------------
  function el(id) { return document.getElementById(id); }

  el('riskScore').textContent  = Math.round(score * 100) + '%';
  el('hashPrefix').textContent = hashPrefix || 'n/a';
  el('sources').textContent    = sources ? sources.replace(/,/g, ', ') : 'Local heuristics';

  if (sources.toLowerCase().includes('phish') || sources.toLowerCase().includes('safe')) {
    el('reasonLabel').textContent = 'phishing';
  } else if (sources.toLowerCase().includes('malware')) {
    el('reasonLabel').textContent = 'malware';
  }

  // ---- Buttons -----------------------------------------------------------

  el('goHomeBtn').addEventListener('click', function () {
    // SECURITY: redirect to a known-safe page, not back to the blocked URL
    location.replace('chrome://newtab/');
  });

  el('goBackBtn').addEventListener('click', function () {
    history.back();
  });

  // "Proceed anyway" requires a second confirmation click
  el('proceedBtn').addEventListener('click', function () {
    el('proceedWarning').hidden     = false;
    el('confirmProceedBtn').hidden  = false;
    el('proceedBtn').hidden         = true;
  });

  el('confirmProceedBtn').addEventListener('click', function () {
    // SECURITY: we can only navigate back — we don't hold the original URL
    // here, which means we can't accidentally pass it as a JS string that
    // could be eval'd. Going back is the only way to reach the original page.
    history.back();
  });

})();

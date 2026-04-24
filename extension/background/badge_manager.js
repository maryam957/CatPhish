/**
 * BadgeManager — toolbar icon color + text based on page verdict
 * ----------------------------------------------------------------------------
 * The extension icon in the browser toolbar shows an at-a-glance risk cue:
 *   Green  "" / no badge   =>  SAFE
 *   Amber  "!"              =>  LOW or SUSPICIOUS
 *   Red    "X"              =>  DANGEROUS (also coincides with hard-block page)
 *
 * We don't change the icon's SVG per-tab (chrome.action.setIcon needs image
 * data which is heavy); we just overlay a colored text badge. That's plenty
 * for recognition and keeps the worker lean.
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *  SECURITY NOTES
 *    - setBadgeText never embeds untrusted strings. We only ever write one
 *      of three constants. No UI-injection risk.
 *    - All calls are wrapped in try/catch because chrome.action throws if
 *      the tab no longer exists (races with tab close).
 */

const BadgeManager = {
  updateForTab(tabId, verdict) {
    if (!Number.isInteger(tabId) || tabId < 0) return;
    const score = verdict && typeof verdict.riskScore === 'number' ? verdict.riskScore : 0;

    let text = '';
    let color = '#34d399';    // green
    let title = 'CatPhish — page looks safe';

    if (score >= 0.85) {
      text = 'X';
      color = '#dc2626';       // red
      title = 'CatPhish — DANGEROUS page';
    } else if (score >= 0.6) {
      text = '!';
      color = '#f59e0b';       // amber
      title = 'CatPhish — suspicious page';
    } else if (score >= 0.3) {
      text = '?';
      color = '#eab308';       // yellow
      title = 'CatPhish — low risk signals';
    }

    try {
      chrome.action.setBadgeText({ tabId, text });
      chrome.action.setBadgeBackgroundColor({ tabId, color });
      chrome.action.setTitle({ tabId, title });
    } catch (_) { /* tab gone, ignore */ }
  }
};

if (typeof self !== 'undefined') {
  self.BadgeManager = BadgeManager;
}
if (typeof module !== 'undefined' && module.exports) {
  module.exports = BadgeManager;
}

/**
 * warning_banner.js — injects a top-of-page warning overlay
 * ----------------------------------------------------------------------------
 * When the service worker decides a page is SUSPICIOUS (score >= warn threshold
 * but < block threshold), it asks the content script to display this banner.
 *
 * The banner tells the user WHY we're worried and lets them either:
 *   - Dismiss the warning (stay on page, proceed at own risk)
 *   - Leave the page (navigate to about:blank)
 *   - Report the page as phishing (posts via service-worker -> backend)
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *  SECURITY NOTES (critical — banner lives INSIDE the suspicious page)
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *  - The banner is mounted inside a ShadowRoot in closed mode. That isolates
 *    our CSS AND blocks the page's JS from reading/modifying our overlay
 *    via normal DOM queries.
 *  - Every piece of text we render uses `textContent`, NEVER innerHTML.
 *    Reason text from the service worker is untrusted output from the
 *    heuristic engine; we treat it as data.
 *  - We inline our CSS as a <style> element inside the shadow root so the
 *    page's CSS cannot restyle (hide / spoof) our warning.
 *  - The banner uses position: fixed with a very high z-index so the page
 *    can't cover it by stacking a modal on top. However a truly malicious
 *    page could still try to cover us — that's why for high scores we use
 *    the full block page instead of this banner.
 */

(function () {
  let shadowHost = null;

  function show(payload) {
    try {
      // If a banner is already up, refresh its content rather than stacking.
      if (shadowHost && document.documentElement.contains(shadowHost)) {
        shadowHost.remove();
      }

      shadowHost = document.createElement('div');
      // Give the host a hard-to-guess ID so page scripts cannot findById us.
      shadowHost.id = 'catphish-warning-host-' + Math.random().toString(36).slice(2);
      shadowHost.style.all = 'initial';  // reset cascade
      shadowHost.style.position = 'fixed';
      shadowHost.style.top = '0';
      shadowHost.style.left = '0';
      shadowHost.style.right = '0';
      shadowHost.style.zIndex = '2147483647'; // max 32-bit int
      shadowHost.style.pointerEvents = 'auto';

      // SECURITY: closed shadow root => page scripts can't read our nodes
      // via shadowHost.shadowRoot.
      const root = shadowHost.attachShadow({ mode: 'closed' });

      const style = document.createElement('style');
      style.textContent = BANNER_CSS;
      root.appendChild(style);

      const bar = document.createElement('div');
      bar.className = 'cp-bar';

      const icon = document.createElement('span');
      icon.className = 'cp-icon';
      icon.textContent = '\u26A0';            // warning triangle
      bar.appendChild(icon);

      const text = document.createElement('div');
      text.className = 'cp-text';
      const title = document.createElement('div');
      title.className = 'cp-title';
      title.textContent = 'CatPhish detected suspicious signals on this page';
      text.appendChild(title);

      const subtitle = document.createElement('div');
      subtitle.className = 'cp-sub';
      const reasonLines = (payload.reasons || []).slice(0, 3).map((r) => {
        // SECURITY: hard-cast reason fields to string, clamp length
        const msg = String(r && r.message ? r.message : (r && r.type) || '').slice(0, 180);
        return msg;
      }).filter(Boolean);
      subtitle.textContent = reasonLines.length
        ? 'Why: ' + reasonLines.join('  \u2022  ')
        : 'Risk score ' + (Number(payload.riskScore) || 0).toFixed(2);
      text.appendChild(subtitle);
      bar.appendChild(text);

      const actions = document.createElement('div');
      actions.className = 'cp-actions';

      const leaveBtn = document.createElement('button');
      leaveBtn.className = 'cp-btn cp-btn-leave';
      leaveBtn.textContent = 'Leave page';
      leaveBtn.addEventListener('click', () => {
        // SECURITY: use location.replace so no history entry remains
        try { window.location.replace('about:blank'); } catch (_) {}
      });

      const reportBtn = document.createElement('button');
      reportBtn.className = 'cp-btn cp-btn-report';
      reportBtn.textContent = 'Report phishing';
      reportBtn.addEventListener('click', async () => {
        try {
          // The service worker already has the current hash prefix keyed
          // by this tab — the popup uses it the same way.
          chrome.runtime.sendMessage({
            type: 'CATPHISH_REPORT_SITE',
            payload: {
              hashPrefix: String(payload.hashPrefix || ''),
              category: 'phishing',
              notes: 'reported-from-banner'
            }
          }, () => { /* ignore response; banner stays open */ });
          reportBtn.disabled = true;
          reportBtn.textContent = 'Reported \u2713';
        } catch (_) {}
      });

      const safeBtn = document.createElement('button');
      safeBtn.className = 'cp-btn cp-btn-safe';
      safeBtn.textContent = 'Safe preview';
      safeBtn.addEventListener('click', () => {
        try {
          chrome.runtime.sendMessage({
            type: 'CATPHISH_OPEN_SAFE_PREVIEW',
            url: String(window.location.href || '')
          }, () => {});
        } catch (_) {}
      });

      const dismissBtn = document.createElement('button');
      dismissBtn.className = 'cp-btn cp-btn-dismiss';
      dismissBtn.textContent = 'Dismiss';
      dismissBtn.addEventListener('click', () => {
        if (shadowHost) shadowHost.remove();
        shadowHost = null;
      });

      actions.appendChild(leaveBtn);
      actions.appendChild(safeBtn);
      actions.appendChild(reportBtn);
      actions.appendChild(dismissBtn);
      bar.appendChild(actions);

      root.appendChild(bar);
      document.documentElement.appendChild(shadowHost);
    } catch (err) {
      // SECURITY: never throw into the page context.
      console.error('[CatPhish/banner]', err && err.message);
    }
  }

  const BANNER_CSS = `
    .cp-bar {
      all: initial;
      display: flex;
      align-items: center;
      gap: 14px;
      font-family: -apple-system, 'Segoe UI', Roboto, sans-serif;
      color: #0b1224;
      background: linear-gradient(90deg, #fde68a, #fbbf24);
      border-bottom: 2px solid #b45309;
      padding: 12px 18px;
      box-shadow: 0 8px 24px rgba(0,0,0,0.15);
    }
    .cp-icon {
      font-size: 22px;
      flex: 0 0 auto;
    }
    .cp-text {
      flex: 1 1 auto;
      min-width: 0;
    }
    .cp-title {
      font-weight: 700;
      font-size: 14px;
    }
    .cp-sub {
      font-size: 12px;
      margin-top: 2px;
      opacity: 0.85;
      word-break: break-word;
    }
    .cp-actions {
      display: flex;
      gap: 8px;
      flex: 0 0 auto;
    }
    .cp-btn {
      all: initial;
      cursor: pointer;
      font-family: inherit;
      font-size: 12px;
      font-weight: 600;
      padding: 6px 12px;
      border-radius: 8px;
      border: 1px solid rgba(0,0,0,0.15);
      background: #ffffff;
      color: #0b1224;
    }
    .cp-btn-leave   { background: #dc2626; color: #ffffff; }
    .cp-btn-report  { background: #1e3a8a; color: #ffffff; }
    .cp-btn-safe    { background: #0f766e; color: #ffffff; }
    .cp-btn-dismiss { background: #ffffff; }
    .cp-btn:hover   { opacity: 0.92; }
    .cp-btn:disabled { opacity: 0.6; cursor: default; }
  `;

  self.CatPhishWarningBanner = { show };
})();

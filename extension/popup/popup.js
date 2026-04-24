/**
 * popup.js — drives the CatPhish risk dashboard
 * -----------------------------------------------------------------------
 * Talks to the service worker via chrome.runtime.sendMessage, then renders
 * the verdict + snapshot data into the UI built in popup.html.
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *  SECURITY NOTES
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *  - Every piece of untrusted data from the service worker is written
 *    via textContent, never innerHTML.  Even though the service worker
 *    sanitizes before storing, defence-in-depth says we treat storage
 *    as untrusted here too.
 *  - The SVG risk-meter arc is drawn by computing path geometry in JS
 *    and setting a DOM attribute — no string concatenation into markup.
 *  - Report button is disabled until we confirm the tab has a verdict;
 *    it sends only the stored hashPrefix, never a raw URL.
 */

(function () {

  // ---- helpers -----------------------------------------------------------

  function el(id) { return document.getElementById(id); }

  function setText(id, val) {
    var node = el(id);
    if (node) node.textContent = val == null ? '' : String(val);
  }

  function safeStr(val, max) {
    return (val == null ? '' : String(val)).slice(0, max);
  }

  function clamp01(n) {
    var v = Number(n);
    return Number.isFinite(v) ? Math.max(0, Math.min(1, v)) : 0;
  }

  // ---- SVG risk meter ----------------------------------------------------
  // Half-circle arc, radius 90, centre (100,100).  Arc length ≈ π*90 ≈ 283.

  var ARC_LEN = 283;

  function updateMeter(score) {
    var pct   = clamp01(score);
    var fill  = el('meterFill');
    var value = el('meterValue');
    if (!fill || !value) return;

    var dash = (pct * ARC_LEN).toFixed(1);
    fill.setAttribute('stroke-dasharray', dash + ' ' + ARC_LEN);

    var stroke = '#34d399';
    if (pct >= 0.85)      stroke = '#dc2626';
    else if (pct >= 0.6)  stroke = '#f59e0b';
    else if (pct >= 0.3)  stroke = '#eab308';
    fill.setAttribute('stroke', stroke);

    value.textContent = Math.round(pct * 100) + '%';
  }

  // ---- Verdict label / badge ---------------------------------------------

  function applyVerdict(verdict) {
    var badge = el('riskBadge');
    var h1    = el('verdictLabel');
    if (!badge || !h1) return;

    if (!verdict) {
      h1.textContent = 'No data yet';
      badge.textContent = '\u2014';
      badge.className = 'badge';
      setText('meterSubtext', 'Navigate to a page to scan it.');
      return;
    }

    var label = safeStr(verdict.verdict || '', 20);
    var score = clamp01(verdict.riskScore);
    setText('meterSubtext', 'Score: ' + Math.round(score * 100) + '%  \u2014  ' + label);

    if (label === 'DANGEROUS') {
      h1.textContent = '\u2716 DANGEROUS';
      h1.style.color = '#ffb4b4';
      badge.className = 'badge badge-danger';
      badge.textContent = 'DANGEROUS';
    } else if (label === 'SUSPICIOUS') {
      h1.textContent = '\u26A0 Suspicious';
      h1.style.color = '#fde68a';
      badge.className = 'badge badge-warn';
      badge.textContent = 'SUSPICIOUS';
    } else if (label === 'LOW_RISK') {
      h1.textContent = '\u2753 Low risk';
      h1.style.color = '#fef9c3';
      badge.className = 'badge badge-warn';
      badge.textContent = 'LOW RISK';
    } else {
      h1.textContent = '\u2714 Looks safe';
      h1.style.color = '#6ee7b7';
      badge.className = 'badge badge-ok';
      badge.textContent = 'SAFE';
    }
  }

  // ---- Risk factor list --------------------------------------------------

  function renderRiskFactors(factors) {
    var list = el('riskFactorList');
    if (!list) return;
    list.replaceChildren();
    var arr = Array.isArray(factors) ? factors : [];
    if (arr.length === 0) {
      var empty = document.createElement('li');
      empty.className = 'risk-item empty';
      empty.textContent = 'No risk factors recorded for this page.';
      list.appendChild(empty);
      return;
    }
    arr.slice(0, 15).forEach(function (f) {
      var li    = document.createElement('li');
      li.className = 'risk-item';

      var title = document.createElement('div');
      var sev   = safeStr(f && f.severity ? f.severity : 'info', 20).toUpperCase();
      title.className = 'risk-title sev-' + sev;
      title.textContent = safeStr(f && f.type ? f.type : 'factor', 80) + ' \u00b7 ' + sev;
      li.appendChild(title);

      var msg = document.createElement('p');
      msg.className = 'risk-message';
      msg.textContent = safeStr(f && f.message ? f.message : '', 300);
      li.appendChild(msg);

      if (f && f.evidence) {
        var ev = document.createElement('p');
        ev.className = 'risk-evidence';
        ev.textContent = safeStr(f.evidence, 200);
        li.appendChild(ev);
      }
      list.appendChild(li);
    });
  }

  // ---- Malicious JS hits list --------------------------------------------

  function renderJsHits(hits) {
    var list = el('jsHitList');
    if (!list) return;
    list.replaceChildren();
    var arr = Array.isArray(hits) ? hits : [];
    if (arr.length === 0) {
      var empty = document.createElement('li');
      empty.className = 'risk-item empty';
      empty.textContent = 'No malicious script signatures matched.';
      list.appendChild(empty);
      return;
    }
    arr.slice(0, 10).forEach(function (h) {
      var li = document.createElement('li');
      li.className = 'risk-item';

      var title = document.createElement('div');
      var sev   = safeStr(h && h.severity ? h.severity : 'MEDIUM', 20).toUpperCase();
      title.className = 'risk-title sev-' + sev;
      title.textContent =
        safeStr(h && h.category ? h.category : 'UNKNOWN', 40) + ' \u00b7 ' +
        safeStr(h && h.pattern  ? h.pattern  : '', 80);
      li.appendChild(title);

      if (h && h.evidence) {
        var ev = document.createElement('p');
        ev.className = 'risk-evidence';
        ev.textContent = safeStr(h.evidence, 200);
        li.appendChild(ev);
      }
      list.appendChild(li);
    });
  }

  // ---- Main render -------------------------------------------------------

  function renderAll(snapshot, verdict) {
    updateMeter(verdict ? verdict.riskScore : 0);
    applyVerdict(verdict);

    if (verdict) {
      renderRiskFactors(verdict.reasons || []);
    }

    if (snapshot) {
      var a = snapshot.analysis || {};
      setText('loginFormCount',        a.loginFormCount        || 0);
      setText('hiddenIframeCount',     a.hiddenIframeCount     || 0);
      setText('suspiciousScriptCount', a.suspiciousScriptCount || 0);
      renderJsHits(a.maliciousJsHits || []);
      var page = snapshot.page || {};
      setText('pageMeta', safeStr(page.title || 'Untitled page', 100));
    }

    var reportBtn = el('reportBtn');
    if (reportBtn) {
      reportBtn.disabled = !(verdict && verdict.hashPrefix);
    }
  }

  // ---- Report button wiring ----------------------------------------------

  function wireReportButton(hashPrefix) {
    var btn    = el('reportBtn');
    var status = el('reportStatus');
    if (!btn) return;

    btn.addEventListener('click', function () {
      btn.disabled = true;
      btn.textContent = 'Sending\u2026';
      try {
        chrome.runtime.sendMessage(
          {
            type: 'CATPHISH_REPORT_SITE',
            payload: {
              hashPrefix: safeStr(hashPrefix, 64),
              category: 'phishing',
              notes: 'reported-from-popup'
            }
          },
          function (resp) {
            if (resp && resp.ok) {
              btn.textContent = 'Reported \u2713';
              if (status) {
                status.textContent = (resp.result && resp.result.delivered)
                  ? 'Report sent to community database.'
                  : 'Report saved locally (offline).';
              }
            } else {
              btn.disabled = false;
              btn.textContent = 'Report this site as phishing';
              if (status) status.textContent = 'Report failed \u2014 try again.';
            }
          }
        );
      } catch (err) {
        btn.disabled = false;
        btn.textContent = 'Report this site as phishing';
        if (status) status.textContent = 'Error: ' + safeStr(err && err.message, 80);
      }
    });
  }

  // ---- Settings button ---------------------------------------------------

  function wireSettingsButton() {
    var btn = el('settingsBtn');
    if (!btn) return;
    btn.addEventListener('click', function () {
      if (chrome.runtime.openOptionsPage) {
        chrome.runtime.openOptionsPage();
      }
    });
  }

  // ---- Bootstrap ---------------------------------------------------------

  function boot() {
    wireSettingsButton();
    chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
      var tab   = tabs && tabs[0];
      var tabId = tab && Number.isInteger(tab.id) ? tab.id : null;
      if (tabId === null) { renderAll(null, null); return; }

      chrome.runtime.sendMessage(
        { type: 'CATPHISH_GET_DASHBOARD_FOR_TAB', tabId: tabId },
        function (resp) {
          var snapshot = resp && resp.snapshot ? resp.snapshot : null;
          var verdict  = resp && resp.verdict  ? resp.verdict  : null;
          renderAll(snapshot, verdict);
          if (verdict && verdict.hashPrefix) wireReportButton(verdict.hashPrefix);
        }
      );
    });
  }

  boot();

})();

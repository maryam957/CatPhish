/**
 * options.js — Settings page logic
 * -----------------------------------------------------------------------
 * Reads current settings from the service worker, populates the form,
 * saves changes, handles the wipe-data action, and loads the audit log.
 *
 * SECURITY: every value read from the form is coerced through its expected
 * type before being sent to the service worker (which does a second
 * coercion pass). Belt-and-braces.
 */

(function () {

  function el(id) { return document.getElementById(id); }
  function setText(id, v) { var n = el(id); if (n) n.textContent = v == null ? '' : String(v); }

  // ---- Load settings from service worker ---------------------------------

  function loadSettings() {
    chrome.runtime.sendMessage({ type: 'CATPHISH_GET_SETTINGS' }, function (resp) {
      if (!resp || !resp.settings) return;
      var s = resp.settings;
      setCheck('useGoogleSafeBrowsing', s.useGoogleSafeBrowsing !== false);
      setCheck('usePhishTank',          s.usePhishTank          !== false);
      setCheck('useOpenPhish',          s.useOpenPhish          !== false);
      setCheck('showWarningBanner',     s.showWarningBanner     !== false);
      setCheck('telemetryEnabled',      !!s.telemetryEnabled);
      setRange('riskThreshold',  'riskThresholdVal',  s.riskThreshold  != null ? s.riskThreshold  : 0.6);
      setRange('blockThreshold', 'blockThresholdVal', s.blockThreshold != null ? s.blockThreshold : 0.85);
    });
  }

  function setCheck(id, val) { var n = el(id); if (n) n.checked = !!val; }
  function setRange(id, valId, val) {
    var n = el(id);
    if (n) { n.value = String(val); }
    setText(valId, parseFloat(val).toFixed(2));
  }

  // ---- Live range display ------------------------------------------------

  function wireRange(id, valId) {
    var n = el(id);
    if (!n) return;
    n.addEventListener('input', function () {
      setText(valId, parseFloat(n.value).toFixed(2));
    });
  }
  wireRange('riskThreshold',  'riskThresholdVal');
  wireRange('blockThreshold', 'blockThresholdVal');

  // ---- Save --------------------------------------------------------------

  el('saveBtn').addEventListener('click', function () {
    var payload = {
      useGoogleSafeBrowsing: getCheck('useGoogleSafeBrowsing'),
      usePhishTank:          getCheck('usePhishTank'),
      useOpenPhish:          getCheck('useOpenPhish'),
      showWarningBanner:     getCheck('showWarningBanner'),
      telemetryEnabled:      getCheck('telemetryEnabled'),
      riskThreshold:         getRange('riskThreshold'),
      blockThreshold:        getRange('blockThreshold')
    };
    chrome.runtime.sendMessage({ type: 'CATPHISH_SET_SETTINGS', payload: payload }, function (resp) {
      var msg = resp && resp.ok ? 'Settings saved.' : 'Save failed.';
      setText('saveStatus', msg);
      setTimeout(function () { setText('saveStatus', ''); }, 3000);
    });
  });

  function getCheck(id) { var n = el(id); return n ? n.checked : false; }
  function getRange(id) {
    var n = el(id);
    if (!n) return 0;
    var v = parseFloat(n.value);
    return Number.isFinite(v) ? v : 0;
  }

  // ---- Wipe data ---------------------------------------------------------

  el('wipeBtn').addEventListener('click', function () {
    if (!confirm('This will delete all CatPhish snapshots, verdicts, the audit log, and settings. Cannot be undone. Continue?')) return;
    chrome.runtime.sendMessage({ type: 'CATPHISH_WIPE_DATA' }, function (resp) {
      setText('wipeStatus', resp && resp.ok ? 'All data cleared.' : 'Wipe failed.');
    });
  });

  // ---- Audit log ---------------------------------------------------------

  el('loadLogBtn').addEventListener('click', function () {
    chrome.runtime.sendMessage({ type: 'CATPHISH_GET_AUDIT_LOG' }, function (resp) {
      var container = el('logContainer');
      var chainEl   = el('chainStatus');
      if (!container) return;

      if (resp && typeof resp.chainValid === 'boolean') {
        chainEl.textContent = resp.chainValid ? '\u2714 Chain intact' : '\u2716 CHAIN BROKEN — tampering detected!';
        chainEl.className   = 'chain-badge ' + (resp.chainValid ? 'chain-ok' : 'chain-fail');
      }

      container.replaceChildren();
      var entries = resp && Array.isArray(resp.entries) ? resp.entries : [];
      if (entries.length === 0) {
        var p = document.createElement('p');
        p.className = 'log-empty';
        p.textContent = 'No log entries yet.';
        container.appendChild(p);
        return;
      }
      // Newest-first
      entries.slice().reverse().forEach(function (e) {
        var div = document.createElement('div');
        var evType = (e.event && e.event.type) ? String(e.event.type) : 'UNKNOWN';
        div.className = 'log-entry type-' + evType;
        // SECURITY: textContent only, never innerHTML
        div.textContent =
          '#' + String(e.seq).padStart(4, '0') +
          '  ' + safeStr(e.ts, 24) +
          '  ' + evType +
          (e.event && e.event.verdict ? '  verdict=' + safeStr(e.event.verdict, 20) : '') +
          (e.event && e.event.hashPrefix ? '  hp=' + safeStr(e.event.hashPrefix, 16) : '') +
          '  hmac=' + safeStr(e.hmac, 16) + '\u2026';
        container.appendChild(div);
      });
    });
  });

  function safeStr(v, max) { return (v == null ? '' : String(v)).slice(0, max); }

  // ---- Boot --------------------------------------------------------------
  loadSettings();

})();

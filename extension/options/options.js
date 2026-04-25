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
  var API_BASE_CANDIDATES = [
    'http://127.0.0.1:3031/api',
    'http://127.0.0.1:3030/api',
    'https://api.catphish.local/api'
  ];
  var AUTH_KEY = 'catphishAuthSession';

  function el(id) { return document.getElementById(id); }
  function setText(id, v) { var n = el(id); if (n) n.textContent = v == null ? '' : String(v); }
  function getInput(id) { var n = el(id); return n ? String(n.value || '').trim() : ''; }

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

  // ---- API auth (frontend side) ------------------------------------------

  async function loadAuthSession() {
    var data = await chrome.storage.session.get([AUTH_KEY]);
    return data && data[AUTH_KEY] ? data[AUTH_KEY] : null;
  }

  async function saveAuthSession(session) {
    await chrome.storage.session.set({ catphishAuthSession: session });
  }

  async function clearAuthSession() {
    await chrome.storage.session.remove([AUTH_KEY]);
  }

  function isValidEmail(email) {
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
  }

  function writeAuthStatus(msg) {
    setText('authStatus', safeStr(msg, 180));
  }

  async function apiCall(path, method, body, session) {
    var lastErr = null;
    for (var i = 0; i < API_BASE_CANDIDATES.length; i++) {
      try {
        return await apiCallSingle(API_BASE_CANDIDATES[i], path, method, body, session);
      } catch (err) {
        lastErr = err;
      }
    }
    throw (lastErr || new Error('Failed to fetch backend.'));
  }

  async function apiCallSingle(baseUrl, path, method, body, session) {
    var headers = { 'Content-Type': 'application/json' };
    if (session && session.accessToken) {
      headers.Authorization = 'Bearer ' + session.accessToken;
    }
    if (session && session.csrfToken) {
      headers['X-CSRF-Token'] = session.csrfToken;
    }
    var res = await fetch(baseUrl + path, {
      method: method,
      headers: headers,
      credentials: 'include',
      body: body ? JSON.stringify(body) : undefined
    });
    var data = await res.json().catch(function () { return {}; });
    if (!res.ok) {
      throw new Error(String((data && (data.error || data.message)) || 'Request failed.').slice(0, 120));
    }
    return data;
  }

  async function refreshAuthStatus() {
    try {
      var session = await loadAuthSession();
      if (!session || !session.accessToken) {
        writeAuthStatus('Not logged in.');
        return;
      }
      var me = await apiCall('/auth/me', 'GET', null, session);
      var user = me && me.user ? me.user : {};
      writeAuthStatus('Logged in as ' + safeStr(user.email || 'unknown', 80) + ' (' + safeStr(user.role || 'user', 20) + ').');
    } catch (_) {
      await clearAuthSession();
      writeAuthStatus('Session expired. Please login again.');
    }
  }

  async function register() {
    var email = getInput('registerEmail').toLowerCase();
    var password = getInput('registerPassword');
    if (!isValidEmail(email)) {
      writeAuthStatus('Please enter a valid email for registration.');
      return;
    }
    if (password.length < 8 || password.length > 128) {
      writeAuthStatus('Password must be between 8 and 128 characters.');
      return;
    }
    try {
      var response = await apiCall('/auth/register', 'POST', { email: email, password: password }, null);
      // Demo mode helper: activate immediately if enabled server-side.
      await apiCall('/auth/demo-activate', 'POST', { email: email }, null).catch(function () {});
      writeAuthStatus(response && response.message ? response.message : 'Registration request submitted.');
    } catch (err) {
      writeAuthStatus(err.message || 'Registration failed.');
    }
  }

  async function login() {
    var email = getInput('loginEmail').toLowerCase();
    var password = getInput('loginPassword');
    if (!isValidEmail(email)) {
      writeAuthStatus('Please enter a valid email for login.');
      return;
    }
    if (password.length < 1 || password.length > 128) {
      writeAuthStatus('Invalid password.');
      return;
    }
    try {
      var data = await apiCall('/auth/login', 'POST', { email: email, password: password }, null);
      await saveAuthSession({
        accessToken: String(data.accessToken || ''),
        csrfToken: String(data.csrfToken || ''),
        role: String(data.role || 'user'),
        email: email
      });
      writeAuthStatus('Login successful.');
      await refreshAuthStatus();
    } catch (err) {
      writeAuthStatus(err.message || 'Login failed.');
    }
  }

  async function logout() {
    try {
      var session = await loadAuthSession();
      if (session && session.accessToken) {
        await apiCall('/auth/logout', 'POST', {}, session).catch(function () {});
      }
      await clearAuthSession();
      writeAuthStatus('Logged out.');
    } catch (_) {
      await clearAuthSession();
      writeAuthStatus('Logged out.');
    }
  }

  // ---- Boot --------------------------------------------------------------
  loadSettings();
  if (el('registerBtn')) el('registerBtn').addEventListener('click', function () { register(); });
  if (el('loginBtn')) el('loginBtn').addEventListener('click', function () { login(); });
  if (el('logoutBtn')) el('logoutBtn').addEventListener('click', function () { logout(); });
  refreshAuthStatus();

})();

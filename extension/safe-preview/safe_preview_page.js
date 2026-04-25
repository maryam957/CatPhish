(function () {
  function byId(id) { return document.getElementById(id); }
  function setStatus(text) {
    var node = byId('status');
    if (node) node.textContent = String(text || '');
  }

  function getTargetUrl() {
    try {
      var parsed = new URL(window.location.href);
      var target = parsed.searchParams.get('target') || '';
      if (!/^https?:/i.test(target)) return '';
      return target;
    } catch (_) {
      return '';
    }
  }

  async function boot() {
    var target = getTargetUrl();
    var mount = byId('previewMount');

    var backBtn = byId('goBackBtn');
    if (backBtn) {
      backBtn.addEventListener('click', function () {
        try { history.back(); } catch (_) {}
      });
    }

    if (!target) {
      setStatus('No valid target URL was provided.');
      return;
    }

    if (!mount || !self.CatPhishSafePreview || typeof self.CatPhishSafePreview.loadSafePreview !== 'function') {
      setStatus('Safe preview engine is unavailable.');
      return;
    }

    try {
      setStatus('Loading and sanitizing content...');
      await self.CatPhishSafePreview.loadSafePreview(target, mount);
      setStatus('Safe preview loaded. Scripts and unsafe forms are stripped.');
    } catch (err) {
      setStatus('Safe preview failed: ' + String((err && err.message) || 'Unknown error').slice(0, 140));
    }
  }

  boot();
})();
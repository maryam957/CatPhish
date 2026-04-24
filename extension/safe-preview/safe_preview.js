(function () {
  /** Clears a mount node and injects a sandboxed iframe with sanitized srcdoc content. Security checks: uses a zero-permission sandbox, never writes raw HTML into the host document, and only accepts pre-sanitized HTML. Inputs/outputs: accepts a mount node and sanitized HTML and returns the created iframe. */
  function renderSandboxedPreview(mountNode, sanitizedHtml) {
    if (!mountNode) {
      throw new Error('A preview mount node is required.');
    }

    const iframe = document.createElement('iframe');
    iframe.setAttribute('sandbox', '');
    iframe.setAttribute('referrerpolicy', 'no-referrer');
    iframe.title = 'Sanitized page preview';
    iframe.srcdoc = sanitizedHtml;
    mountNode.replaceChildren(iframe);
    return iframe;
  }

  /** Fetches page HTML without executing page scripts, sanitizes the response, and renders the cleaned preview. Security checks: uses fetch instead of navigation, aborts on network/sanitizer failures, and alerts the user if cleanup cannot be guaranteed. Inputs/outputs: accepts a URL and a mount node, then returns a Promise that resolves to the rendered iframe. */
  async function loadSafePreview(url, mountNode) {
    if (!self.CatPhishSafePreviewSanitizer || typeof self.CatPhishSafePreviewSanitizer.sanitizeHtml !== 'function') {
      throw new Error('Safe preview sanitizer is unavailable.');
    }

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 15000);

    try {
      const response = await fetch(url, {
        credentials: 'omit',
        redirect: 'follow',
        signal: controller.signal
      });

      if (!response.ok) {
        throw new Error(`Unable to fetch preview content: ${response.status}`);
      }

      const rawHtml = await response.text();
      const sanitizedHtml = self.CatPhishSafePreviewSanitizer.sanitizeHtml(rawHtml);

      if (!sanitizedHtml) {
        throw new Error('Sanitization failed.');
      }

      return renderSandboxedPreview(mountNode, sanitizedHtml);
    } catch (error) {
      alert('Safe preview was blocked because the content could not be sanitized securely.');
      throw error;
    } finally {
      clearTimeout(timeoutId);
    }
  }

  self.CatPhishSafePreview = {
    loadSafePreview,
    renderSandboxedPreview
  };
})();
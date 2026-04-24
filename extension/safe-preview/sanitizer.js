(function () {
  const BLOCKED_TAGS = new Set(['script', 'iframe', 'object', 'embed']);
  const EXTERNAL_RESOURCE_TAGS = new Set(['link', 'img', 'source', 'video', 'audio', 'track', 'picture', 'meta']);
  const SAFE_SELF_OR_FRAGMENT = /^(#|\/|\.\/|\.\.\/|data:image\/|data:font\/)/i;

  /** Determines whether a URL-like attribute should be stripped from the preview. Security checks: rejects scriptable protocols and external resources so the sandbox never loads attacker-controlled content. Inputs/outputs: accepts an attribute value and returns a boolean. */
  function shouldStripUrl(value) {
    const text = value == null ? '' : String(value).trim();
    if (!text) {
      return false;
    }

    if (/^(javascript|vbscript|file):/i.test(text)) {
      return true;
    }

    if (/^https?:/i.test(text)) {
      return true;
    }

    return !SAFE_SELF_OR_FRAGMENT.test(text) && !/^data:/i.test(text);
  }

  /** Removes unsafe nodes and attributes from parsed HTML. Security checks: deletes executable tags, strips form and iframe navigation, and removes event-handler attributes before any preview rendering occurs. Inputs/outputs: accepts a parsed document and returns a cleaned HTML string. */
  function sanitizeParsedDocument(documentRef) {
    if (!documentRef || !documentRef.documentElement || !documentRef.body) {
      throw new Error('Unable to parse HTML for safe preview.');
    }

    BLOCKED_TAGS.forEach((tagName) => {
      documentRef.querySelectorAll(tagName).forEach((node) => node.remove());
    });

    EXTERNAL_RESOURCE_TAGS.forEach((tagName) => {
      documentRef.querySelectorAll(tagName).forEach((node) => {
        const lowerTagName = node.tagName.toLowerCase();
        if (lowerTagName === 'link') {
          node.remove();
          return;
        }

        if (lowerTagName === 'meta' && String(node.getAttribute('http-equiv') || '').toLowerCase() === 'refresh') {
          node.remove();
          return;
        }

        ['src', 'href', 'srcset', 'poster', 'data'].forEach((attributeName) => {
          if (node.hasAttribute(attributeName)) {
            node.removeAttribute(attributeName);
          }
        });
      });
    });

    documentRef.querySelectorAll('form').forEach((form) => {
      form.removeAttribute('action');
      form.removeAttribute('formaction');
      form.removeAttribute('target');
    });

    documentRef.querySelectorAll('*').forEach((node) => {
      Array.from(node.attributes).forEach((attribute) => {
        const attributeName = attribute.name.toLowerCase();
        const attributeValue = attribute.value;

        if (attributeName.startsWith('on')) {
          node.removeAttribute(attribute.name);
          return;
        }

        if (['src', 'href', 'srcset', 'action', 'formaction', 'poster', 'data', 'xlink:href'].includes(attributeName) && shouldStripUrl(attributeValue)) {
          node.removeAttribute(attribute.name);
        }

        if (attributeName === 'style' && /url\s*\(/i.test(attributeValue)) {
          node.removeAttribute(attribute.name);
        }
      });
    });

    return '<!doctype html>' + documentRef.documentElement.outerHTML;
  }

  /** Sanitizes a raw HTML string for sandboxed preview rendering. Security checks: parses inertly, cleans the DOM in memory, and returns null on any sanitization failure so the caller can fail closed. Inputs/outputs: accepts raw HTML and returns a cleaned HTML string or null. */
  function sanitizeHtml(rawHtml) {
    try {
      const parser = new DOMParser();
      const parsedDocument = parser.parseFromString(String(rawHtml || ''), 'text/html');
      return sanitizeParsedDocument(parsedDocument);
    } catch (error) {
      return null;
    }
  }

  self.CatPhishSafePreviewSanitizer = {
    sanitizeHtml
  };
})();
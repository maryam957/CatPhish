(function () {
  /** Returns a plain text preview from untrusted DOM text. Security checks: removes extra whitespace and limits output length so popup rendering stays bounded. Inputs/outputs: accepts any DOM text and returns a short string. */
  function cleanText(value, maxLength) {
    const text = value == null ? '' : String(value);
    return text.replace(/\s+/g, ' ').trim().slice(0, maxLength);
  }

  /** Determines whether an iframe is hidden enough to be suspicious. Security checks: uses layout-independent attributes and computed styles but never dereferences iframe content. Inputs/outputs: accepts an iframe element and returns a boolean. */
  function isHiddenIframe(iframe) {
    if (!iframe || iframe.nodeType !== Node.ELEMENT_NODE) {
      return false;
    }

    const hiddenAttribute = iframe.hasAttribute('hidden') || iframe.getAttribute('aria-hidden') === 'true';
    const inlineStyle = cleanText(iframe.getAttribute('style'), 200).toLowerCase();
    const hasZeroSize = iframe.getAttribute('width') === '0' || iframe.getAttribute('height') === '0';
    const styleSuggestsHidden = inlineStyle.includes('display:none') || inlineStyle.includes('visibility:hidden') || inlineStyle.includes('opacity:0');

    return hiddenAttribute || hasZeroSize || styleSuggestsHidden;
  }

  /** Scores a form for login-like behavior. Security checks: only inspects element metadata and input types, never submits or mutates forms. Inputs/outputs: accepts a form element and returns a boolean plus explanation text. */
  function analyzeLoginForm(form) {
    const inputs = Array.from(form.querySelectorAll('input'));
    const passwordInputs = inputs.filter((input) => String(input.getAttribute('type') || '').toLowerCase() === 'password');
    const labelText = cleanText(form.getAttribute('aria-label') || form.getAttribute('name') || form.id || '', 80).toLowerCase();
    const textContent = cleanText(form.textContent || '', 200).toLowerCase();
    const looksAuthRelated = /(login|sign in|signin|password|account|verify|authentication)/i.test(labelText + ' ' + textContent);

    if (passwordInputs.length > 0 || looksAuthRelated) {
      return {
        isLoginForm: true,
        evidence: passwordInputs.length > 0 ? 'password input present' : 'authentication-related form text'
      };
    }

    return {
      isLoginForm: false,
      evidence: ''
    };
  }

  /** Flags script tags that are likely risky. Security checks: reads script metadata only, never executes code, and classifies inline or external scripts using static heuristics. Inputs/outputs: accepts a script element and returns a finding or null. */
  function analyzeScript(script) {
    if (!script || script.nodeType !== Node.ELEMENT_NODE) {
      return null;
    }

    const src = cleanText(script.getAttribute('src'), 500);
    const inlineCode = cleanText(script.textContent || '', 500);
    const scriptType = cleanText(script.getAttribute('type'), 60).toLowerCase();
    const externalScript = src && /^https?:/i.test(src);
    const suspiciousInline = inlineCode && /(eval\(|document\.write\(|Function\(|setTimeout\(\s*['"])/i.test(inlineCode);

    if (scriptType && scriptType !== 'text/javascript' && scriptType !== 'application/javascript' && scriptType !== 'module' && !externalScript && !inlineCode) {
      return null;
    }

    if (externalScript) {
      return {
        type: 'suspicious-script',
        severity: 'medium',
        message: 'External script detected',
        evidence: src
      };
    }

    if (suspiciousInline) {
      return {
        type: 'suspicious-script',
        severity: 'high',
        message: 'Inline script contains risky sink usage',
        evidence: inlineCode.slice(0, 120)
      };
    }

    return null;
  }

  /** Builds a sanitized DOM snapshot for the background worker. Security checks: extracts only plain data, clamps all strings, never includes live nodes or raw HTML, and labels findings for the popup. Inputs/outputs: accepts a document and returns a plain JSON snapshot. */
  function analyzeDocument(documentRef) {
    const title = cleanText(documentRef.title || '', 200);
    const url = cleanText(documentRef.location && documentRef.location.href ? documentRef.location.href : '', 500);
    const origin = cleanText(documentRef.location && documentRef.location.origin ? documentRef.location.origin : '', 200);
    const forms = Array.from(documentRef.querySelectorAll('form'));
    const iframes = Array.from(documentRef.querySelectorAll('iframe'));
    const scripts = Array.from(documentRef.querySelectorAll('script'));
    const riskFactors = [];

    let loginFormCount = 0;
    let hiddenIframeCount = 0;
    let suspiciousScriptCount = 0;

    forms.forEach((form) => {
      const loginCheck = analyzeLoginForm(form);
      if (loginCheck.isLoginForm) {
        loginFormCount += 1;
        riskFactors.push({
          type: 'login-form',
          severity: 'medium',
          message: 'Login-like form detected',
          evidence: loginCheck.evidence
        });
      }
    });

    iframes.forEach((iframe) => {
      if (isHiddenIframe(iframe)) {
        hiddenIframeCount += 1;
        riskFactors.push({
          type: 'hidden-iframe',
          severity: 'high',
          message: 'Hidden iframe detected',
          evidence: cleanText(iframe.getAttribute('src') || '', 300)
        });
      }
    });

    scripts.forEach((script) => {
      const finding = analyzeScript(script);
      if (finding) {
        suspiciousScriptCount += 1;
        riskFactors.push(finding);
      }
    });

    return {
      capturedAt: new Date().toISOString(),
      page: {
        title,
        url,
        origin
      },
      analysis: {
        totalFormCount: forms.length,
        loginFormCount,
        hiddenIframeCount,
        suspiciousScriptCount,
        riskFactors: riskFactors.slice(0, 20)
      }
    };
  }

  self.CatPhishDomAnalyzer = {
    analyzeDocument
  };
})();
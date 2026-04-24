/**
 * MaliciousJSDetector — signature-based scanner for risky in-page JavaScript
 * ----------------------------------------------------------------------------
 * The content script (dom_analyzer.js) already collects script metadata from
 * the page. This module reads those findings and classifies them into:
 *
 *   - KEYLOGGER : listens to keyboard events + sends data off-origin
 *   - SKIMMER   : credit-card field hijacks, form intercepts, fake checkout
 *   - MINER     : CoinHive / CryptoLoot / WebAssembly-based crypto miners
 *   - OBFUSCATION : heavy eval / unescape / atob chains, long string blobs
 *   - SINK      : use of dangerous APIs like eval(), document.write, Function()
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *  SECURITY NOTES
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *  - We NEVER execute page scripts. We only inspect their static text via
 *    the string the content script already copied out.
 *  - We never use `eval`, `new Function`, or `RegExp.prototype.exec` with
 *    attacker-controlled flags. All our regexes are literals compiled at
 *    load time.
 *  - Output strings are length-capped so a huge inline script can't balloon
 *    our storage.
 */

class MaliciousJSDetector {
  constructor() {
    // ---- Signature database (regexes are literals, compiled once) ---------
    // Each rule:  { name, category, severity, pattern, evidenceSlice }
    this.signatures = [
      // -------- Keylogger patterns ---------------------------------------
      {
        name: 'keydown+exfiltration',
        category: 'KEYLOGGER',
        severity: 'HIGH',
        // key event listener AND network send in the same script body
        pattern: /(addEventListener\s*\(\s*['"](keydown|keyup|keypress|input)['"])[\s\S]{0,800}(fetch\s*\(|XMLHttpRequest|sendBeacon|navigator\.sendBeacon)/i
      },
      {
        name: 'onkeypress-assign',
        category: 'KEYLOGGER',
        severity: 'MEDIUM',
        pattern: /(document|window)\.(onkeydown|onkeyup|onkeypress)\s*=/i
      },

      // -------- Credit-card skimmer patterns -----------------------------
      {
        name: 'card-number-selector',
        category: 'SKIMMER',
        severity: 'HIGH',
        // any JS that targets #cc-number / input[name=card] etc. AND exfiltrates
        pattern: /(card[-_]?(number|num|no|pan)|cc[-_]?(number|num|no)|cvv|cvc)[\s\S]{0,600}(fetch\s*\(|sendBeacon|new\s+Image\s*\(|XMLHttpRequest)/i
      },
      {
        name: 'form-submit-hijack',
        category: 'SKIMMER',
        severity: 'HIGH',
        pattern: /addEventListener\s*\(\s*['"]submit['"][\s\S]{0,400}(fetch|XMLHttpRequest|sendBeacon)/i
      },
      {
        name: 'luhn-check',
        category: 'SKIMMER',
        severity: 'MEDIUM',
        // Luhn algorithm fragment (card validation) in client script is
        // suspicious outside of a real payment gateway SDK.
        pattern: /\%\s*10\s*===?\s*0[\s\S]{0,100}(card|cc|pan)/i
      },

      // -------- Crypto-miner patterns ------------------------------------
      {
        name: 'coinhive-style',
        category: 'MINER',
        severity: 'HIGH',
        pattern: /(CoinHive|CryptoLoot|Coinimp|WebMinePool|NerohutMiner|mineproxy|cryptonight)/i
      },
      {
        name: 'stratum-mining',
        category: 'MINER',
        severity: 'HIGH',
        pattern: /stratum\+tcp:\/\//i
      },
      {
        name: 'wasm-miner',
        category: 'MINER',
        severity: 'MEDIUM',
        // WASM + Worker + high tight-loop hashing is a miner pattern
        pattern: /WebAssembly\.instantiate[\s\S]{0,400}(Worker|SharedArrayBuffer)[\s\S]{0,400}(hash|mine|nonce)/i
      },

      // -------- Obfuscation / packing ------------------------------------
      {
        name: 'atob-eval-chain',
        category: 'OBFUSCATION',
        severity: 'HIGH',
        pattern: /eval\s*\(\s*atob\s*\(/i
      },
      {
        name: 'unescape-eval',
        category: 'OBFUSCATION',
        severity: 'HIGH',
        pattern: /eval\s*\(\s*(unescape|decodeURIComponent)\s*\(/i
      },
      {
        name: 'fromCharCode-spray',
        category: 'OBFUSCATION',
        severity: 'MEDIUM',
        // String.fromCharCode with >30 args suggests hex-packed code
        pattern: /String\.fromCharCode\s*\([^)]{150,}\)/
      },
      {
        name: 'hex-packed-array',
        category: 'OBFUSCATION',
        severity: 'MEDIUM',
        pattern: /var\s+_0x[0-9a-f]{4,}\s*=\s*\[/i
      },

      // -------- Dangerous sinks ------------------------------------------
      {
        name: 'eval-call',
        category: 'SINK',
        severity: 'MEDIUM',
        pattern: /\beval\s*\(/
      },
      {
        name: 'document-write',
        category: 'SINK',
        severity: 'MEDIUM',
        pattern: /document\.write\s*\(/
      },
      {
        name: 'function-ctor',
        category: 'SINK',
        severity: 'MEDIUM',
        pattern: /new\s+Function\s*\(/
      },
      {
        name: 'settimeout-string',
        category: 'SINK',
        severity: 'MEDIUM',
        pattern: /setTimeout\s*\(\s*['"]/
      }
    ];
  }

  /**
   * Examine a DOM snapshot from the content script and return findings.
   *
   * @param {object} snapshot  sanitized snapshot object
   * @returns {Array<object>}  list of findings (capped at 30)
   */
  analyzeSnapshot(snapshot) {
    const findings = [];
    try {
      const analysis = snapshot && snapshot.analysis ? snapshot.analysis : {};
      const factors = Array.isArray(analysis.riskFactors) ? analysis.riskFactors : [];

      // The dom_analyzer already sliced inline-script evidence for us.
      // Run every signature over every script-related evidence string.
      for (const factor of factors) {
        if (factor.type !== 'suspicious-script') continue;
        const evidence = String(factor.evidence || '');
        for (const sig of this.signatures) {
          if (sig.pattern.test(evidence)) {
            findings.push({
              category: sig.category,
              pattern:  sig.name,
              severity: sig.severity,
              evidence: evidence.slice(0, 200) // SECURITY: cap length
            });
            if (findings.length >= 30) break;
          }
        }
        if (findings.length >= 30) break;
      }

      // High-entropy script body => likely obfuscated even if signatures miss
      for (const factor of factors) {
        if (factor.type !== 'suspicious-script') continue;
        const body = String(factor.evidence || '');
        if (body.length >= 200 && this._shannonEntropy(body) > 5.0) {
          findings.push({
            category: 'OBFUSCATION',
            pattern: 'high-entropy-blob',
            severity: 'MEDIUM',
            evidence: `entropy=${this._shannonEntropy(body).toFixed(2)} length=${body.length}`
          });
          break;
        }
      }
    } catch (err) {
      // SECURITY: detector errors must not break snapshot storage.
      console.error('[MaliciousJSDetector]', err && err.message);
    }
    return findings;
  }

  /** Shannon entropy of a string — high entropy = likely packed/encrypted. */
  _shannonEntropy(str) {
    const freq = {};
    for (const ch of str) freq[ch] = (freq[ch] || 0) + 1;
    const n = str.length;
    let h = 0;
    for (const c in freq) {
      const p = freq[c] / n;
      h -= p * Math.log2(p);
    }
    return h;
  }
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = MaliciousJSDetector;
}

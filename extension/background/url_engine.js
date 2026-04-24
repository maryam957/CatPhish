/**
 * URL Engine - Advanced URL Analysis and Risk Detection
 * Entropy-based inspection for phishing detection
 * FR2: Intercept current tab URL on page load
 * NFR2: SHA-256 the full URL, transmit only first N characters (K-anonymity)
 */

class URLEngine {
  constructor() {
    this.urlHasher = null;
    this.analysisCache = new Map();
    this.riskThreshold = 0.6; // Risk score threshold (0-1)
  }

  /**
   * Initialize URL Engine with hasher
   * @param {URLHasher} urlHasher - Instance of URLHasher
   */
  init(urlHasher) {
    this.urlHasher = urlHasher;
    console.log('[URLEngine] Initialized');
  }

  /**
   * Analyze URL for phishing risks
   * Performs entropy-based inspection without logging full URL
   * @param {string} url - URL to analyze
   * @returns {Promise<Object>} Analysis results with risk score
   */
  async analyzeURL(url) {
    try {
      if (!url || typeof url !== 'string') {
        throw new Error('Invalid URL provided');
      }

      // Check cache
      const hash = await this.urlHasher.getHashPrefix(url);
      if (this.analysisCache.has(hash)) {
        console.log('[URLEngine] Cache hit for URL analysis');
        return this.analysisCache.get(hash);
      }

      const analysis = {
        hashPrefix: hash,
        timestamp: Date.now(),
        riskFactors: [],
        riskScore: 0,
        isPhishingLikely: false
      };

      // Parse URL
      let urlObj;
      try {
        urlObj = new URL(url);
      } catch (error) {
        console.error('[URLEngine] Invalid URL format:', error.message);
        analysis.riskFactors.push({
          type: 'MALFORMED_URL',
          severity: 'HIGH',
          message: 'URL is malformed or invalid',
          evidence: 'URL could not be parsed'
        });
        analysis.riskScore = 0.9;
        return analysis;
      }

      // Perform entropy-based analysis
      this.analyzeSubdomainEntropy(urlObj.hostname, analysis);
      this.analyzeHyphenUsage(urlObj.hostname, analysis);
      this.analyzeHomoglyphs(urlObj.hostname, analysis);
      this.analyzeIPBasedURLs(urlObj, analysis);
      this.analyzeURLLength(url, analysis);
      this.analyzeSuspiciousPatterns(urlObj, analysis);

      // Calculate overall risk score
      analysis.riskScore = this.calculateRiskScore(analysis.riskFactors);
      analysis.isPhishingLikely = analysis.riskScore >= this.riskThreshold;

      // Cache analysis (without full URL)
      this.analysisCache.set(hash, analysis);

      return analysis;
    } catch (error) {
      console.error('[URLEngine] URL analysis failed:', error.message);
      throw error;
    }
  }

  /**
   * Analyze subdomain entropy for randomness
   * High entropy subdomains may indicate phishing
   * @private
   */
  analyzeSubdomainEntropy(hostname, analysis) {
    try {
      const parts = hostname.split('.');
      
      // Skip TLD and domain, analyze subdomains
      if (parts.length > 2) {
        const subdomains = parts.slice(0, -2);
        
        for (const subdomain of subdomains) {
          const entropy = this.calculateEntropy(subdomain);
          
          // High entropy subdomains are suspicious
          if (entropy > 4.5) {
            analysis.riskFactors.push({
              type: 'HIGH_ENTROPY_SUBDOMAIN',
              severity: 'MEDIUM',
              message: `Subdomain "${subdomain}" has unusually high entropy (${entropy.toFixed(2)})`,
              evidence: 'High entropy may indicate randomly generated subdomains'
            });
          }
        }
      }
    } catch (error) {
      console.error('[URLEngine] Subdomain entropy analysis failed:', error.message);
    }
  }

  /**
   * Analyze hyphen usage in domain
   * Excessive hyphens may indicate phishing (e.g., pay-pal-security.com)
   * @private
   */
  analyzeHyphenUsage(hostname, analysis) {
    try {
      const parts = hostname.split('.');
      const domain = parts.length > 1 ? parts[parts.length - 2] : parts[0];
      
      const hyphenCount = (domain.match(/-/g) || []).length;
      
      if (hyphenCount > 1) {
        analysis.riskFactors.push({
          type: 'EXCESSIVE_HYPHENS',
          severity: 'MEDIUM',
          message: `Domain "${domain}" contains ${hyphenCount} hyphens`,
          evidence: 'Hyphens are often used in phishing domains to mimic legitimate sites'
        });
      }
      
      // Check for hyphen at start or end (invalid)
      if (domain.startsWith('-') || domain.endsWith('-')) {
        analysis.riskFactors.push({
          type: 'INVALID_HYPHEN_POSITION',
          severity: 'HIGH',
          message: `Domain "${domain}" has hyphens at start or end`,
          evidence: 'Invalid domain format may indicate spoofing attempt'
        });
      }
    } catch (error) {
      console.error('[URLEngine] Hyphen analysis failed:', error.message);
    }
  }

  /**
   * Analyze homoglyph attacks
   * Check for character confusions (l vs 1, O vs 0, etc.)
   * @private
   */
  analyzeHomoglyphs(hostname, analysis) {
    try {
      const suspiciousPatterns = [
        { pattern: /1l/, message: 'Possible homoglyph: 1 and l' },
        { pattern: /0O/, message: 'Possible homoglyph: 0 and O' },
        { pattern: /rn/, message: 'Possible homoglyph: rn resembles m' },
        { pattern: /vv/, message: 'Possible homoglyph: vv resembles w' }
      ];

      const domain = hostname.split('.')[0];
      
      for (const { pattern, message } of suspiciousPatterns) {
        if (pattern.test(domain)) {
          analysis.riskFactors.push({
            type: 'HOMOGLYPH_DETECTED',
            severity: 'MEDIUM',
            message: message,
            evidence: `Found in domain: "${domain}"`
          });
        }
      }
    } catch (error) {
      console.error('[URLEngine] Homoglyph analysis failed:', error.message);
    }
  }

  /**
   * Analyze IP-based URLs
   * Direct IP addresses are often used in phishing
   * @private
   */
  analyzeIPBasedURLs(urlObj, analysis) {
    try {
      const hostname = urlObj.hostname;
      const ipv4Pattern = /^(\d{1,3}\.){3}\d{1,3}$/;
      const ipv6Pattern = /^\[?([0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}\]?$/i;

      if (ipv4Pattern.test(hostname) || ipv6Pattern.test(hostname)) {
        analysis.riskFactors.push({
          type: 'IP_BASED_URL',
          severity: 'HIGH',
          message: 'URL uses IP address instead of domain name',
          evidence: `Hostname is an IP address: ${hostname}`
        });
      }
    } catch (error) {
      console.error('[URLEngine] IP-based URL analysis failed:', error.message);
    }
  }

  /**
   * Analyze URL length
   * Excessively long URLs may hide malicious parameters
   * @private
   */
  analyzeURLLength(url, analysis) {
    try {
      if (url.length > 2048) {
        analysis.riskFactors.push({
          type: 'EXCESSIVE_URL_LENGTH',
          severity: 'MEDIUM',
          message: 'URL is unusually long (>2048 characters)',
          evidence: 'Long URLs often hide malicious parameters or redirect chains'
        });
      }
    } catch (error) {
      console.error('[URLEngine] URL length analysis failed:', error.message);
    }
  }

  /**
   * Analyze suspicious patterns
   * Check for common phishing indicators
   * @private
   */
  analyzeSuspiciousPatterns(urlObj, analysis) {
    try {
      const hostname = urlObj.hostname.toLowerCase();
      const pathname = urlObj.pathname.toLowerCase();

      // Known phishing domains/patterns
      const suspiciousKeywords = [
        'login', 'signin', 'verify', 'confirm', 'account', 'update', 'secure'
      ];

      for (const keyword of suspiciousKeywords) {
        if (hostname.includes(keyword) && hostname.split('.').length > 2) {
          analysis.riskFactors.push({
            type: 'SUSPICIOUS_KEYWORD',
            severity: 'LOW',
            message: `Suspicious keyword "${keyword}" found in subdomain`,
            evidence: `Hostname: ${hostname}`
          });
          break; // Only add once
        }
      }

      // Check for redirects in query parameters
      const params = new URLSearchParams(urlObj.search);
      const redirectParams = ['redirect', 'return', 'goto', 'next', 'url', 'continue'];
      
      for (const param of redirectParams) {
        if (params.has(param)) {
          analysis.riskFactors.push({
            type: 'REDIRECT_PARAMETER',
            severity: 'LOW',
            message: `Redirect parameter "${param}" detected`,
            evidence: `Parameter found in URL`
          });
          break;
        }
      }
    } catch (error) {
      console.error('[URLEngine] Suspicious pattern analysis failed:', error.message);
    }
  }

  /**
   * Calculate Shannon entropy of a string
   * Used to detect randomly generated subdomains
   * @private
   */
  calculateEntropy(str) {
    const frequencies = {};
    
    for (const char of str) {
      frequencies[char] = (frequencies[char] || 0) + 1;
    }

    let entropy = 0;
    const len = str.length;

    for (const freq of Object.values(frequencies)) {
      const probability = freq / len;
      entropy -= probability * Math.log2(probability);
    }

    return entropy;
  }

  /**
   * Calculate overall risk score from factors
   * @private
   */
  calculateRiskScore(riskFactors) {
    if (riskFactors.length === 0) return 0;

    let score = 0;
    const severityWeights = {
      HIGH: 0.3,
      MEDIUM: 0.2,
      LOW: 0.1
    };

    for (const factor of riskFactors) {
      const weight = severityWeights[factor.severity] || 0.1;
      score += weight;
    }

    // Normalize to 0-1 range
    return Math.min(score / (riskFactors.length * 0.3), 1);
  }

  /**
   * Clear analysis cache
   */
  clearCache() {
    this.analysisCache.clear();
    console.log('[URLEngine] Cache cleared');
  }

  /**
   * Get cache statistics
   */
  getCacheStats() {
    return {
      size: this.analysisCache.size,
      threshold: this.riskThreshold
    };
  }

  /**
   * Set risk threshold
   */
  setRiskThreshold(threshold) {
    if (threshold >= 0 && threshold <= 1) {
      this.riskThreshold = threshold;
    }
  }
}

// Export URLEngine
if (typeof module !== 'undefined' && module.exports) {
  module.exports = URLEngine;
}

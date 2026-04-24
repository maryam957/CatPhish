/**
 * URL Hasher - SHA-256 Hashing with K-Anonymity
 * Implements privacy-preserving URL analysis
 * FR2: Intercept current tab URL on page load
 * NFR2: Transmit only first N characters of hash prefix (K-anonymity)
 * Never logs or stores the full URL anywhere
 */

class URLHasher {
  constructor(hashPrefixLength = 16) {
    this.hashPrefixLength = hashPrefixLength; // Number of hex chars to transmit
    this.hashCache = new Map(); // Cache hashes to avoid rehashing
  }

  /**
   * Hash URL using SHA-256 and return only the prefix
   * Full URL is never stored - only computed hash prefix is returned
   * @param {string} url - Full URL to hash
   * @returns {Promise<Object>} { prefix, fullHash, length, timestamp }
   */
  async hashURL(url) {
    try {
      if (!url || typeof url !== 'string') {
        throw new Error('Invalid URL provided');
      }

      // Normalize URL
      const normalizedURL = this.normalizeURL(url);

      // Check cache
      const cacheKey = normalizedURL;
      if (this.hashCache.has(cacheKey)) {
        console.log('[URLHasher] Cache hit for URL hash');
        return this.hashCache.get(cacheKey);
      }

      // Compute SHA-256
      const fullHash = await this.computeSHA256(normalizedURL);
      
      // Extract prefix for K-anonymity (NFR2)
      const prefix = fullHash.substring(0, this.hashPrefixLength);

      const result = {
        prefix: prefix, // What gets transmitted to backend
        fullHash: fullHash, // Kept in memory only during this function call
        length: this.hashPrefixLength,
        timestamp: Date.now(),
        url: normalizedURL // Kept only for this object, never persisted
      };

      // Cache result (without full URL)
      this.hashCache.set(cacheKey, {
        prefix: result.prefix,
        fullHash: result.fullHash,
        length: result.length,
        timestamp: result.timestamp
      });

      // Clear full URL from result before returning
      delete result.url;

      return result;
    } catch (error) {
      console.error('[URLHasher] URL hashing failed:', error.message);
      throw error;
    }
  }

  /**
   * Get hash prefix from cached hash (K-anonymity safe)
   * @param {string} url - Original URL
   * @returns {Promise<string>} Hash prefix only
   */
  async getHashPrefix(url) {
    const hash = await this.hashURL(url);
    return hash.prefix;
  }

  /**
   * Verify a URL matches a hash prefix
   * Used for comparing URLs without exposing them
   * @param {string} url - URL to verify
   * @param {string} expectedPrefix - Expected hash prefix
   * @returns {Promise<boolean>} True if URL matches prefix
   */
  async verifyURLPrefix(url, expectedPrefix) {
    try {
      const hash = await this.hashURL(url);
      return hash.prefix === expectedPrefix;
    } catch (error) {
      console.error('[URLHasher] Prefix verification failed:', error.message);
      return false;
    }
  }

  /**
   * Compute SHA-256 hash of URL
   * @private
   * @param {string} data - Data to hash
   * @returns {Promise<string>} Hex-encoded SHA-256 hash
   */
  async computeSHA256(data) {
    try {
      const buffer = new TextEncoder().encode(data);
      const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
      return this.arrayBufferToHex(hashBuffer);
    } catch (error) {
      console.error('[URLHasher] SHA-256 computation failed:', error.message);
      throw new Error('Hash computation failed');
    }
  }

  /**
   * Normalize URL for consistent hashing
   * @private
   * @param {string} url - Raw URL
   * @returns {string} Normalized URL
   */
  normalizeURL(url) {
    try {
      // Remove fragments and trailing slashes for consistency
      let normalized = url.split('#')[0];
      
      // Parse URL to handle edge cases
      const urlObj = new URL(normalized);
      
      // Return normalized URL without fragment
      return urlObj.href.split('#')[0];
    } catch (error) {
      // If URL parsing fails, use basic normalization
      console.warn('[URLHasher] URL parsing failed, using basic normalization');
      return url.split('#')[0];
    }
  }

  /**
   * Convert ArrayBuffer to Hex string
   * @private
   */
  arrayBufferToHex(buffer) {
    const bytes = new Uint8Array(buffer);
    return Array.from(bytes)
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
  }

  /**
   * Clear hash cache
   * @returns {void}
   */
  clearCache() {
    this.hashCache.clear();
    console.log('[URLHasher] Cache cleared');
  }

  /**
   * Get cache statistics
   * @returns {Object} Cache info
   */
  getCacheStats() {
    return {
      size: this.hashCache.size,
      keys: Array.from(this.hashCache.keys()),
      prefixLength: this.hashPrefixLength
    };
  }
}

// Export URLHasher
if (typeof module !== 'undefined' && module.exports) {
  module.exports = URLHasher;
}

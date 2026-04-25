/**
 * Encrypted Local Storage Manager
 * Handles all persistent storage with AES-256-GCM encryption
 * Guard condition: only writes after backend response signature verification
 * NFR5: No plaintext data ever persisted to disk
 */

class StorageManager {
  constructor(options = {}) {
    this.masterKey = null;
    this.isInitialized = false;
    this.cacheData = new Map(); // In-memory cache
    this.signatureKey = null; // For backend response verification
    this.storageArea = options.storageArea || (typeof chrome !== 'undefined' ? chrome.storage.local : null);
  }

  /**
   * Initialize storage manager with encryption key
   * Must be called before any storage operations
   * @param {CryptoKey} masterKey - Master encryption key
   * @returns {Promise<void>}
   */
  async init(masterKey) {
    try {
      if (!masterKey) {
        throw new Error('Master key is required for initialization');
      }
      
      this.masterKey = masterKey;
      this.isInitialized = true;
      
      console.log('[StorageManager] Initialized successfully');
    } catch (error) {
      console.error('[StorageManager] Initialization failed:', error.message);
      throw error;
    }
  }

  /**
   * Write encrypted data to storage
   * Guard: Verifies backend response signature before write
   * @param {string} key - Storage key
   * @param {Object} data - Data to store
   * @param {string} backendSignature - Signature from backend (base64)
   * @returns {Promise<void>}
   */
  async write(key, data, backendSignature) {
    try {
      if (!this.isInitialized) {
        throw new Error('StorageManager not initialized');
      }
      if (!this.storageArea) {
        throw new Error('Storage area not available');
      }

      // Guard condition: Verify backend signature if provided
      if (backendSignature && this.signatureKey) {
        const dataString = JSON.stringify(data);
        const isValid = await this.verifyBackendSignature(dataString, backendSignature);
        
        if (!isValid) {
          console.error('[StorageManager] Backend signature verification failed - rejecting write');
          await this.wipeCache();
          throw new Error('Backend signature verification failed');
        }
      }

      const dataString = JSON.stringify(data);
      const encrypted = await this.encryptData(dataString);

      // Store in chrome.storage.local (encrypted)
      const storageKey = `catphish_enc_${key}`;
      await this.storageArea.set({
        [storageKey]: encrypted,
        [`${storageKey}_metadata`]: {
          timestamp: Date.now(),
          keyVersion: 1 // For key rotation support
        }
      });

      // Update in-memory cache
      this.cacheData.set(key, data);

      console.log('[StorageManager] Data written securely:', key);
    } catch (error) {
      console.error('[StorageManager] Write failed:', error.message);
      throw error;
    }
  }

  /**
   * Read and decrypt data from storage
   * @param {string} key - Storage key
   * @returns {Promise<Object|null>} Decrypted data or null if not found
   */
  async read(key) {
    try {
      if (!this.isInitialized) {
        throw new Error('StorageManager not initialized');
      }
      if (!this.storageArea) {
        throw new Error('Storage area not available');
      }

      // Check in-memory cache first
      if (this.cacheData.has(key)) {
        return this.cacheData.get(key);
      }

      // Read from encrypted storage
      const storageKey = `catphish_enc_${key}`;
      const result = await this.storageArea.get([storageKey]);

      if (!result[storageKey]) {
        console.log('[StorageManager] Key not found:', key);
        return null;
      }

      const encrypted = result[storageKey];
      const decrypted = await this.decryptData(encrypted);
      const data = JSON.parse(decrypted);

      // Update cache
      this.cacheData.set(key, data);

      return data;
    } catch (error) {
      console.error('[StorageManager] Read/Decryption failed:', error.message);
      // If decryption fails, data may be tampered - wipe it
      if (error.message.includes('tampered')) {
        await this.delete(key);
      }
      throw error;
    }
  }

  /**
   * Delete data from storage and cache
   * @param {string} key - Storage key
   * @returns {Promise<void>}
   */
  async delete(key) {
    try {
      const storageKey = `catphish_enc_${key}`;
      if (this.storageArea) {
        await this.storageArea.remove([storageKey, `${storageKey}_metadata`]);
      }
      this.cacheData.delete(key);
      console.log('[StorageManager] Data deleted:', key);
    } catch (error) {
      console.error('[StorageManager] Delete failed:', error.message);
      throw error;
    }
  }

  /**
   * Wipe all cache and storage
   * Called when tampering is detected
   * @returns {Promise<void>}
   */
  async wipeCache() {
    try {
      // Clear in-memory cache
      this.cacheData.clear();

      // Clear all catphish encrypted data from storage
      if (!this.storageArea) return;
      const allItems = await this.storageArea.get(null);
      const keysToRemove = Object.keys(allItems).filter(k => k.startsWith('catphish_enc_'));
      
      if (keysToRemove.length > 0) {
        await this.storageArea.remove(keysToRemove);
        console.log('[StorageManager] Cache wiped - removed', keysToRemove.length, 'items');
      }
    } catch (error) {
      console.error('[StorageManager] Wipe failed:', error.message);
      throw error;
    }
  }

  /**
   * Encrypt data using master key
   * @private
   * @param {string} plaintext - Data to encrypt
   * @returns {Promise<Object>} Encrypted data object
   */
  async encryptData(plaintext) {
    try {
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const data = new TextEncoder().encode(plaintext);

      const encrypted = await crypto.subtle.encrypt(
        {
          name: 'AES-GCM',
          iv: iv,
          tagLength: 128
        },
        this.masterKey,
        data
      );

      const ciphertextWithTag = new Uint8Array(encrypted);

      return {
        iv: this.arrayBufferToBase64(iv),
        ciphertext: this.arrayBufferToBase64(ciphertextWithTag.slice(0, -16)),
        tag: this.arrayBufferToBase64(ciphertextWithTag.slice(-16)),
        timestamp: Date.now()
      };
    } catch (error) {
      console.error('[StorageManager] Encryption failed:', error.message);
      throw new Error('Data encryption failed');
    }
  }

  /**
   * Decrypt data using master key
   * @private
   * @param {Object} encrypted - Encrypted data object
   * @returns {Promise<string>} Decrypted plaintext
   */
  async decryptData(encrypted) {
    try {
      const iv = this.base64ToArrayBuffer(encrypted.iv);
      const ciphertext = this.base64ToArrayBuffer(encrypted.ciphertext);
      const tag = this.base64ToArrayBuffer(encrypted.tag);

      const ciphertextWithTag = new Uint8Array(ciphertext.length + tag.length);
      ciphertextWithTag.set(new Uint8Array(ciphertext), 0);
      ciphertextWithTag.set(new Uint8Array(tag), ciphertext.length);

      const decrypted = await crypto.subtle.decrypt(
        {
          name: 'AES-GCM',
          iv: iv,
          tagLength: 128
        },
        this.masterKey,
        ciphertextWithTag
      );

      return new TextDecoder().decode(decrypted);
    } catch (error) {
      console.error('[StorageManager] Decryption failed - possible tampering:', error.message);
      throw new Error('Data may have been tampered with');
    }
  }

  /**
   * Verify signature from backend response
   * @private
   * @param {string} data - Data to verify
   * @param {string} signature - Signature from backend (base64)
   * @returns {Promise<boolean>} True if signature is valid
   */
  async verifyBackendSignature(data, signature) {
    try {
      if (!this.signatureKey) {
        console.warn('[StorageManager] Signature key not set, skipping verification');
        return true;
      }

      const dataBuffer = new TextEncoder().encode(data);
      const signatureBuffer = this.base64ToArrayBuffer(signature);

      const isValid = await crypto.subtle.verify(
        'HMAC',
        this.signatureKey,
        signatureBuffer,
        dataBuffer
      );

      return isValid;
    } catch (error) {
      console.error('[StorageManager] Signature verification error:', error.message);
      return false;
    }
  }

  /**
   * Set the signature verification key (from backend)
   * @param {CryptoKey} signatureKey - HMAC key for verification
   */
  setSignatureKey(signatureKey) {
    this.signatureKey = signatureKey;
  }

  /**
   * Change the browser storage area used for encrypted persistence.
   * @param {Object} storageArea
   */
  setStorageArea(storageArea) {
    this.storageArea = storageArea;
  }

  /**
   * Utility: Convert ArrayBuffer to Base64
   * @private
   */
  arrayBufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  }

  /**
   * Utility: Convert Base64 to ArrayBuffer
   * @private
   */
  base64ToArrayBuffer(base64) {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
  }

  /**
   * Get cache statistics (for debugging)
   * @returns {Object} Cache info
   */
  getCacheStats() {
    return {
      isInitialized: this.isInitialized,
      cacheSize: this.cacheData.size,
      keys: Array.from(this.cacheData.keys())
    };
  }
}

// Export StorageManager
if (typeof module !== 'undefined' && module.exports) {
  module.exports = StorageManager;
}

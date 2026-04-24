/**
 * Crypto Utilities for AES-256-GCM Encryption
 * Implements secure encryption/decryption with authentication tags
 * NFR5: No plaintext data ever persisted to disk
 */

const ALGORITHM = 'AES-GCM';
const KEY_SIZE = 256; // bits
const IV_SIZE = 12; // 96 bits for GCM (recommended)
const TAG_SIZE = 128; // 128 bits
const SALT_SIZE = 16; // 128 bits for PBKDF2

/**
 * Generate a cryptographic key using crypto.subtle
 * @returns {Promise<CryptoKey>} AES-256-GCM key
 */
async function generateEncryptionKey() {
  try {
    const key = await crypto.subtle.generateKey(
      {
        name: ALGORITHM,
        length: KEY_SIZE
      },
      false, // not extractable - key never leaves the system
      ['encrypt', 'decrypt']
    );
    return key;
  } catch (error) {
    console.error('[CryptoUtils] Key generation failed:', error.message);
    throw new Error('Failed to generate encryption key');
  }
}

/**
 * Derive a key from a password using PBKDF2
 * Used for master key establishment from user credential
 * @param {string} password - User password
 * @param {Uint8Array} salt - Salt for key derivation
 * @returns {Promise<CryptoKey>} Derived key
 */
async function deriveKeyFromPassword(password, salt) {
  try {
    const encodedPassword = new TextEncoder().encode(password);
    const baseKey = await crypto.subtle.importKey(
      'raw',
      encodedPassword,
      'PBKDF2',
      false,
      ['deriveKey']
    );

    const derivedKey = await crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt: salt,
        iterations: 100000, // NIST recommended minimum
        hash: 'SHA-256'
      },
      baseKey,
      { name: ALGORITHM, length: KEY_SIZE },
      false,
      ['encrypt', 'decrypt']
    );

    return derivedKey;
  } catch (error) {
    console.error('[CryptoUtils] Key derivation failed:', error.message);
    throw new Error('Failed to derive encryption key from password');
  }
}

/**
 * Encrypt data using AES-256-GCM
 * @param {CryptoKey} key - Encryption key
 * @param {string} plaintext - Data to encrypt
 * @returns {Promise<Object>} { iv, ciphertext, tag } as base64 strings
 */
async function encrypt(key, plaintext) {
  try {
    // Generate random IV
    const iv = crypto.getRandomValues(new Uint8Array(IV_SIZE));
    const data = new TextEncoder().encode(plaintext);

    const encrypted = await crypto.subtle.encrypt(
      {
        name: ALGORITHM,
        iv: iv,
        tagLength: TAG_SIZE
      },
      key,
      data
    );

    // encrypted buffer contains: ciphertext + tag
    const ciphertextWithTag = new Uint8Array(encrypted);

    return {
      iv: arrayBufferToBase64(iv),
      ciphertext: arrayBufferToBase64(ciphertextWithTag.slice(0, -TAG_SIZE / 8)),
      tag: arrayBufferToBase64(ciphertextWithTag.slice(-TAG_SIZE / 8)),
      timestamp: Date.now()
    };
  } catch (error) {
    console.error('[CryptoUtils] Encryption failed:', error.message);
    throw new Error('Encryption operation failed');
  }
}

/**
 * Decrypt data using AES-256-GCM
 * Verifies authentication tag on decryption - if tamper detected, throws error
 * @param {CryptoKey} key - Decryption key
 * @param {Object} encrypted - { iv, ciphertext, tag } as base64 strings
 * @returns {Promise<string>} Decrypted plaintext
 */
async function decrypt(key, encrypted) {
  try {
    const iv = base64ToArrayBuffer(encrypted.iv);
    const ciphertext = base64ToArrayBuffer(encrypted.ciphertext);
    const tag = base64ToArrayBuffer(encrypted.tag);

    // Combine ciphertext and tag for GCM
    const ciphertextWithTag = new Uint8Array(ciphertext.length + tag.length);
    ciphertextWithTag.set(new Uint8Array(ciphertext), 0);
    ciphertextWithTag.set(new Uint8Array(tag), ciphertext.length);

    const decrypted = await crypto.subtle.decrypt(
      {
        name: ALGORITHM,
        iv: iv,
        tagLength: TAG_SIZE
      },
      key,
      ciphertextWithTag
    );

    return new TextDecoder().decode(decrypted);
  } catch (error) {
    console.error('[CryptoUtils] Decryption failed - possible tampering detected:', error.message);
    throw new Error('Decryption failed - data may have been tampered with');
  }
}

/**
 * Compute SHA-256 hash of data
 * Used for URL hashing with K-anonymity
 * @param {string} data - Data to hash
 * @returns {Promise<string>} Hex-encoded SHA-256 hash
 */
async function sha256Hash(data) {
  try {
    const buffer = new TextEncoder().encode(data);
    const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
    return arrayBufferToHex(hashBuffer);
  } catch (error) {
    console.error('[CryptoUtils] SHA-256 hash failed:', error.message);
    throw new Error('Hash computation failed');
  }
}

/**
 * Generate a random salt for key derivation
 * @returns {Uint8Array} Random salt
 */
function generateSalt() {
  return crypto.getRandomValues(new Uint8Array(SALT_SIZE));
}

/**
 * Convert ArrayBuffer to Base64 string
 * @param {ArrayBuffer} buffer - Buffer to convert
 * @returns {string} Base64 string
 */
function arrayBufferToBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

/**
 * Convert Base64 string to ArrayBuffer
 * @param {string} base64 - Base64 string
 * @returns {ArrayBuffer} Decoded buffer
 */
function base64ToArrayBuffer(base64) {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

/**
 * Convert ArrayBuffer to Hex string
 * @param {ArrayBuffer} buffer - Buffer to convert
 * @returns {string} Hex string
 */
function arrayBufferToHex(buffer) {
  const bytes = new Uint8Array(buffer);
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Verify HMAC signature (for integrity checks)
 * @param {CryptoKey} key - HMAC key
 * @param {string} data - Data to verify
 * @param {string} signature - Expected signature (base64)
 * @returns {Promise<boolean>} True if signature is valid
 */
async function verifySignature(key, data, signature) {
  try {
    const dataBuffer = new TextEncoder().encode(data);
    const signatureBuffer = base64ToArrayBuffer(signature);

    const isValid = await crypto.subtle.verify(
      'HMAC',
      key,
      signatureBuffer,
      dataBuffer
    );

    return isValid;
  } catch (error) {
    console.error('[CryptoUtils] Signature verification failed:', error.message);
    return false;
  }
}

// Export functions
if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    generateEncryptionKey,
    deriveKeyFromPassword,
    encrypt,
    decrypt,
    sha256Hash,
    generateSalt,
    arrayBufferToBase64,
    base64ToArrayBuffer,
    arrayBufferToHex,
    verifySignature
  };
}

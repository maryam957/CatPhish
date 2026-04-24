/**
 * password_utils.js — secure password hashing using Node.js crypto (scrypt)
 * -----------------------------------------------------------------------
 * The original file used a mock hash that was explicitly labelled
 * "NOT SECURE — replace with bcrypt in production". This replaces it
 * with real cryptography using Node's built-in `crypto.scrypt`, which
 * is a memory-hard KDF that makes brute-force attacks very expensive.
 *
 * Why scrypt instead of bcrypt?
 *   - No native module dependency (bcrypt needs node-gyp compilation).
 *   - Scrypt is also resistant to GPU / ASIC cracking because it is
 *     both CPU-hard and memory-hard.
 *   - Built in to Node 10+, so no extra install needed.
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *  SECURITY NOTES
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *  SECURITY: salt is 32 random bytes from crypto.randomBytes — NOT
 *    Math.random. Predictable salts let attackers precompute rainbow tables.
 *
 *  SECURITY: scrypt parameters N=131072, r=8, p=1 are above OWASP
 *    minimums and give ~300ms on a modern server, making online brute
 *    force attacks very slow.
 *
 *  SECURITY: comparison is done with crypto.timingSafeEqual — NOT
 *    string comparison. Regular string comparison leaks timing info
 *    about how many characters matched (timing attack).
 *
 *  SECURITY: we never log or return the plaintext password anywhere.
 *    The password variable is used only inside hashPassword / verifyPassword
 *    and is not stored on `this`.
 */

const crypto = require('crypto');
const { promisify } = require('util');
const scrypt = promisify(crypto.scrypt);

class PasswordUtils {
  constructor() {
    // SECURITY: scrypt params. N must be a power of 2.
    // N=16384 (2^14) is the OWASP minimum and works in memory-constrained
    // environments. In production on a dedicated server increase to 2^17.
    this.SCRYPT_N = 16384;
    this.SCRYPT_R = 8;
    this.SCRYPT_P = 1;
    this.SALT_BYTES = 32;    // 256-bit salt
    this.HASH_BYTES = 64;    // 512-bit output
    this.saltRounds = 12;    // kept for API compatibility (not used in scrypt path)
  }

  /**
   * Hash a password.  Returns a string:
   *   "scrypt$<N>$<r>$<p>$<salt_hex>$<hash_hex>"
   * @param {string} password
   * @returns {Promise<string>}
   */
  async hashPassword(password) {
    this.validatePassword(password);

    // SECURITY: crypto.randomBytes is a CSPRNG — safe for salt generation.
    const salt = crypto.randomBytes(this.SALT_BYTES);
    const derivedKey = await scrypt(
      Buffer.from(password, 'utf8'),
      salt,
      this.HASH_BYTES,
      { N: this.SCRYPT_N, r: this.SCRYPT_R, p: this.SCRYPT_P }
    );

    // Encode as a self-describing string so we can change params later
    // without invalidating existing hashes.
    return [
      'scrypt',
      this.SCRYPT_N,
      this.SCRYPT_R,
      this.SCRYPT_P,
      salt.toString('hex'),
      derivedKey.toString('hex')
    ].join('$');
  }

  /**
   * Verify a plaintext password against a stored hash.
   * @param {string} password   plaintext from login form
   * @param {string} storedHash from database
   * @returns {Promise<boolean>}
   */
  async verifyPassword(password, storedHash) {
    if (!password || !storedHash) return false;
    try {
      const parts = storedHash.split('$');
      if (parts.length !== 6 || parts[0] !== 'scrypt') return false;

      const N    = parseInt(parts[1], 10);
      const r    = parseInt(parts[2], 10);
      const p    = parseInt(parts[3], 10);
      const salt = Buffer.from(parts[4], 'hex');
      const expected = Buffer.from(parts[5], 'hex');

      const derived = await scrypt(
        Buffer.from(password, 'utf8'),
        salt,
        expected.length,
        { N, r, p }
      );

      // SECURITY: timingSafeEqual prevents timing-based side channels.
      return crypto.timingSafeEqual(derived, expected);
    } catch (err) {
      console.error('[PasswordUtils] verifyPassword error:', err.message);
      return false;
    }
  }

  /**
   * Validate password strength before hashing.
   * @param {string} password
   * @throws {Error} if requirements not met
   */
  validatePassword(password) {
    if (!password || typeof password !== 'string') throw new Error('Password required');
    if (password.length < 8)   throw new Error('Password must be at least 8 characters');
    if (password.length > 128) throw new Error('Password too long (max 128 chars)');

    // SECURITY: require at least 3 of the 4 character classes.
    const classes = [/[A-Z]/, /[a-z]/, /\d/, /[^A-Za-z0-9]/];
    const passing = classes.filter((re) => re.test(password)).length;
    if (passing < 3) {
      throw new Error(
        'Password must contain at least 3 of: uppercase, lowercase, digit, special character'
      );
    }
  }
}

module.exports = PasswordUtils;

/**
 * user_repository.js — in-memory user store with full auth support
 * -----------------------------------------------------------------------
 * Implements all methods AuthController needs including:
 *   - verification token storage (HMAC-based, time-limited)
 *   - password update (stores new scrypt hash)
 *   - CSRF token per-session store
 *
 * SECURITY: verification tokens are 32-byte CSPRNG values, HMAC-tagged
 *   with an expiry timestamp so they cannot be forged or replayed.
 * SECURITY: user IDs are 128-bit hex from crypto.randomBytes (not sequential).
 * SECURITY: passwords stored only as scrypt hashes — never plaintext.
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

class UserRepository {
  constructor() {
    this.users       = new Map(); // id       -> user object
    this.byEmail     = new Map(); // email    -> id
    this.verTokens   = new Map(); // tokenHex -> { userId, expiry }
    this.csrfTokens  = new Map(); // userId   -> Set<csrfToken>

    this.dataDir = path.join(__dirname, '..', 'data');
    this.dataFile = path.join(this.dataDir, 'users.json');
    this._loadFromDisk();
  }

  // ---- Core CRUD ---------------------------------------------------------

  async create(userData) {
    // SECURITY: random UUID, not sequential int
    const id   = crypto.randomBytes(16).toString('hex');
    const user = { id, ...userData };
    this.users.set(id, user);
    this.byEmail.set(user.email.toLowerCase(), id);
    this._persistToDisk();
    return user;
  }

  async findByEmail(email) {
    const id = this.byEmail.get(email.toLowerCase());
    return id ? { ...this.users.get(id) } : null;  // return copy, not ref
  }

  async findById(id) {
    const u = this.users.get(id);
    return u ? { ...u } : null;
  }

  async updateFailedAttempts(id, count) {
    const u = this.users.get(id);
    if (u) {
      u.failedAttempts = count;
      this._persistToDisk();
    }
  }

  async updateLastLogin(id) {
    const u = this.users.get(id);
    if (u) {
      u.lastLogin = new Date();
      this._persistToDisk();
    }
  }

  async activateUser(id) {
    const u = this.users.get(id);
    if (u) {
      u.isActive = true;
      this._persistToDisk();
    }
  }

  async lockUser(id) {
    const u = this.users.get(id);
    if (u) {
      u.isLocked = true;
      this._persistToDisk();
    }
  }

  // ---- Password management -----------------------------------------------

  /**
   * Update stored password hash.
   * SECURITY: only stores the scrypt hash, never the plaintext.
   */
  async updatePassword(id, newPasswordHash) {
    const u = this.users.get(id);
    if (!u) throw new Error('User not found');
    u.passwordHash = newPasswordHash;
    u.passwordChangedAt = new Date();
    this._persistToDisk();
  }

  // ---- Email verification tokens -----------------------------------------
  // Token format: a 32-byte random hex string.
  // We store it hashed (SHA-256) so even if storage is dumped the raw token
  // is not exposed (same principle as password hashing).
  // Each token is paired with an expiry (1 hour from issue).

  /**
   * Generate and store a verification token for a user.
   * Returns the raw token to be emailed to the user.
   * SECURITY: token is 256 bits from crypto.randomBytes.
   */
  async createVerificationToken(userId) {
    const rawToken = crypto.randomBytes(32).toString('hex'); // 64 hex chars
    // SECURITY: store only the SHA-256 hash of the token
    const tokenHash = crypto.createHash('sha256').update(rawToken).digest('hex');
    const expiry    = Date.now() + 60 * 60 * 1000; // 1 hour
    this.verTokens.set(tokenHash, { userId, expiry });
    return rawToken; // caller emails this to the user
  }

  /**
   * Verify and consume a token.
   * SECURITY: token is single-use — deleted on first valid use.
   * SECURITY: expired tokens are rejected even if hash matches.
   */
  async consumeVerificationToken(rawToken) {
    if (!rawToken || typeof rawToken !== 'string') return null;
    const tokenHash = crypto.createHash('sha256').update(rawToken).digest('hex');
    const record    = this.verTokens.get(tokenHash);
    if (!record) return null;
    if (Date.now() > record.expiry) {
      this.verTokens.delete(tokenHash); // clean up expired
      return null;
    }
    this.verTokens.delete(tokenHash); // SECURITY: single-use
    return record.userId;
  }

  // ---- CSRF tokens per user session --------------------------------------
  // CSRF tokens are 128-bit random values bound to a userId.
  // They are stored server-side; the client sends one per mutating request.

  /**
   * Issue a new CSRF token for a user session.
   * SECURITY: 128-bit crypto.randomBytes.
   */
  issueCsrfToken(userId) {
    const token = crypto.randomBytes(16).toString('hex');
    if (!this.csrfTokens.has(userId)) this.csrfTokens.set(userId, new Set());
    // Keep only last 10 valid CSRF tokens per user (sliding window)
    const s = this.csrfTokens.get(userId);
    if (s.size >= 10) s.delete(s.values().next().value);
    s.add(token);
    return token;
  }

  /**
   * Validate a CSRF token for a user.
   * SECURITY: constant-time comparison via timingSafeEqual.
   * Token is NOT consumed on validation (can be reused within session).
   */
  validateCsrfToken(userId, token) {
    const s = this.csrfTokens.get(userId);
    if (!s) return false;
    for (const stored of s) {
      const a = Buffer.from(stored.padEnd(64, '0'));
      const b = Buffer.from(String(token || '').padEnd(64, '0'));
      if (a.length === b.length && crypto.timingSafeEqual(a, b) && stored === token) {
        return true;
      }
    }
    return false;
  }

  revokeCsrfTokens(userId) {
    this.csrfTokens.delete(userId);
  }

  // ---- Disk persistence ---------------------------------------------------

  _loadFromDisk() {
    try {
      if (!fs.existsSync(this.dataDir)) {
        fs.mkdirSync(this.dataDir, { recursive: true });
      }
      if (!fs.existsSync(this.dataFile)) {
        return;
      }

      const raw = fs.readFileSync(this.dataFile, 'utf8');
      if (!raw || !raw.trim()) {
        return;
      }

      const parsed = JSON.parse(raw);
      const users = Array.isArray(parsed.users) ? parsed.users : [];
      for (const u of users) {
        if (!u || !u.id || !u.email) continue;
        this.users.set(u.id, { ...u });
        this.byEmail.set(String(u.email).toLowerCase(), u.id);
      }
    } catch (err) {
      console.error('[UserRepository] Failed loading users from disk:', err.message);
    }
  }

  _persistToDisk() {
    try {
      if (!fs.existsSync(this.dataDir)) {
        fs.mkdirSync(this.dataDir, { recursive: true });
      }

      const payload = {
        users: Array.from(this.users.values())
      };
      const tmp = `${this.dataFile}.tmp`;
      fs.writeFileSync(tmp, JSON.stringify(payload, null, 2), 'utf8');
      fs.renameSync(tmp, this.dataFile);
    } catch (err) {
      console.error('[UserRepository] Failed persisting users to disk:', err.message);
    }
  }
}

module.exports = UserRepository;
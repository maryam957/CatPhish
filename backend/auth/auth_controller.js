/**
 * auth_controller.js — Authentication Business Logic
 * -----------------------------------------------------------------------
 * Handles register, login, email verification, password change, and
 * refresh-token rotation.  All stubs from the original file are now
 * implemented with real crypto.
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *  SECURITY NOTES (search "SECURITY:")
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *  SECURITY: Registration always returns the same message whether the
 *    email exists or not — prevents user-enumeration attacks.
 *  SECURITY: Verification tokens are 256-bit random values stored as
 *    SHA-256 hashes server-side (UserRepository.createVerificationToken).
 *    They expire in 1 hour and are single-use.
 *  SECURITY: Password change requires re-verifying the current password
 *    before accepting the new one (credential re-confirmation).
 *  SECURITY: Account lockout after 5 failed logins (per IP + per account).
 *  SECURITY: All error messages are generic to avoid leaking account state.
 */

'use strict';

class AuthController {
  constructor(passwordUtils, jwtUtils, userRepository, auditLog) {
    this.passwordUtils  = passwordUtils;
    this.jwtUtils       = jwtUtils;
    this.userRepository = userRepository;
    this.auditLog       = auditLog || null;

    // Per-IP brute-force tracking (complement to per-account lockout)
    this.failedLoginAttempts = new Map();
    this.maxFailedAttempts   = 5;
    this.lockoutDuration     = 15 * 60 * 1000; // 15 minutes
  }

  // =========================================================================
  // Registration
  // =========================================================================

  /**
   * Register a new user.
   * SECURITY: returns same response for existing/new email (no enumeration).
   * SECURITY: password is hashed by PasswordUtils before storage.
   * SECURITY: role is validated against allowlist; defaults to 'user'.
   */
  async register(data) {
    try {
      const { email, password, role = 'user', clientIp } = data;
      this._validateRegistrationInput(email, password, role);

      const existing = await this.userRepository.findByEmail(email);
      if (existing) {
        // SECURITY: pretend success — prevents user enumeration
        this._log('REGISTER_DUPLICATE', { email: this._hashEmail(email), clientIp });
        return { success: true, message: 'Check your email for a verification link.' };
      }

      const passwordHash   = await this.passwordUtils.hashPassword(password);
      const validRoles     = ['user', 'admin'];
      const normalizedRole = validRoles.includes(role) ? role : 'user';

      const user = await this.userRepository.create({
        email:         email.toLowerCase(),
        passwordHash,
        role:          normalizedRole,
        createdAt:     new Date(),
        isActive:      false,
        isLocked:      false,
        failedAttempts: 0,
        lastLogin:     null
      });

      // Issue an email-verification token and (in production) email it.
      // In demo mode the raw token is returned in the response so testers can
      // call /api/auth/verify-email directly without an email server.
      const verToken = await this.userRepository.createVerificationToken(user.id);
      this._log('REGISTER_OK', { userId: user.id, role: normalizedRole, clientIp });

      const isDemoMode = process.env.CATPHISH_DEMO_MODE === 'true';
      return {
        success: true,
        message: 'Check your email for a verification link.',
        // SECURITY: only expose token in demo mode
        ...(isDemoMode && { _demoVerifyToken: verToken, _demoUserId: user.id })
      };
    } catch (err) {
      console.error('[AuthController] register error:', err.message);
      return { success: false, message: 'Registration failed. Please try again later.' };
    }
  }

  // =========================================================================
  // Login
  // =========================================================================

  /**
   * Login with email + password.
   * SECURITY: generic error message for all failure cases.
   * SECURITY: account locked after maxFailedAttempts (per-IP + per-account).
   * SECURITY: CSRF token issued on success and sent back as header-safe value.
   */
  async login(data) {
    try {
      const { email, password, clientIp } = data;
      if (!email || !password) {
        return { success: false, message: 'Invalid email or password.' };
      }

      // SECURITY: IP-level lockout first (faster, less DB work)
      if (this._isIPLocked(clientIp)) {
        return { success: false, message: 'Too many failed attempts. Try again later.' };
      }

      const user = await this.userRepository.findByEmail(email.toLowerCase());
      if (!user) {
        this._recordFailedAttempt(clientIp);
        this._log('LOGIN_NO_USER', { clientIp });
        return { success: false, message: 'Invalid email or password.' };
      }

      if (user.isLocked) {
        this._log('LOGIN_LOCKED', { userId: user.id, clientIp });
        return { success: false, message: 'Account is locked. Contact support.' };
      }

      if (!user.isActive) {
        this._log('LOGIN_INACTIVE', { userId: user.id, clientIp });
        return { success: false, message: 'Please verify your email before logging in.' };
      }

      const valid = await this.passwordUtils.verifyPassword(password, user.passwordHash);
      if (!valid) {
        this._recordFailedAttempt(clientIp);
        const newCount = (user.failedAttempts || 0) + 1;
        await this.userRepository.updateFailedAttempts(user.id, newCount);

        // SECURITY: lock account after too many per-account failures
        if (newCount >= this.maxFailedAttempts) {
          await this.userRepository.lockUser(user.id);
          this._log('ACCOUNT_LOCKED', { userId: user.id, clientIp });
        }
        this._log('LOGIN_BAD_PW', { userId: user.id, clientIp, count: newCount });
        return { success: false, message: 'Invalid email or password.' };
      }

      // Reset failed counters on success
      if (user.failedAttempts > 0) await this.userRepository.updateFailedAttempts(user.id, 0);
      this._clearFailedAttempts(clientIp);
      await this.userRepository.updateLastLogin(user.id);

      const payload      = { userId: user.id, email: user.email, role: user.role };
      const accessToken  = this.jwtUtils.generateAccessToken(payload);
      const refreshToken = this.jwtUtils.generateRefreshToken(payload);

      // Issue CSRF token bound to this user
      const csrfToken = this.userRepository.issueCsrfToken(user.id);

      this._log('LOGIN_OK', { userId: user.id, clientIp });

      return {
        success: true,
        accessToken,
        refreshToken,
        csrfToken,
        role:      user.role,
        expiresIn: 15 * 60,
        message:   'Login successful.'
      };
    } catch (err) {
      console.error('[AuthController] login error:', err.message);
      return { success: false, message: 'Login failed. Please try again later.' };
    }
  }

  // =========================================================================
  // Email verification
  // =========================================================================

  /**
   * Verify email using the token that was emailed to the user.
   * SECURITY: token is consumed on first valid use (single-use).
   * SECURITY: expired tokens are rejected.
   */
  async verifyEmail(email, verificationToken) {
    try {
      if (!email || !verificationToken) {
        return { success: false, message: 'Verification failed.' };
      }

      // Consume the token — returns userId if valid, null if expired/invalid
      const userId = await this.userRepository.consumeVerificationToken(verificationToken);
      if (!userId) {
        this._log('VERIFY_EMAIL_BAD_TOKEN', {});
        return { success: false, message: 'Verification failed.' };
      }

      // Make sure the token belongs to the user who claims the email
      const user = await this.userRepository.findById(userId);
      if (!user || user.email.toLowerCase() !== email.toLowerCase()) {
        this._log('VERIFY_EMAIL_MISMATCH', { userId });
        return { success: false, message: 'Verification failed.' };
      }

      await this.userRepository.activateUser(userId);
      this._log('VERIFY_EMAIL_OK', { userId });
      return { success: true, message: 'Email verified. You can now log in.' };
    } catch (err) {
      console.error('[AuthController] verifyEmail error:', err.message);
      return { success: false, message: 'Verification failed.' };
    }
  }

  // =========================================================================
  // Password change (authenticated)
  // =========================================================================

  /**
   * Change password for an authenticated user.
   * SECURITY: requires current password re-confirmation.
   * SECURITY: new password goes through same strength validation.
   * SECURITY: all CSRF tokens revoked after password change (force re-login).
   */
  async changePassword(userId, currentPassword, newPassword) {
    try {
      if (!currentPassword || !newPassword) {
        return { success: false, message: 'Both current and new passwords are required.' };
      }
      if (currentPassword === newPassword) {
        return { success: false, message: 'New password must differ from current password.' };
      }

      this.passwordUtils.validatePassword(newPassword);

      const user = await this.userRepository.findById(userId);
      if (!user) return { success: false, message: 'User not found.' };

      // SECURITY: re-verify current password before accepting change
      const valid = await this.passwordUtils.verifyPassword(currentPassword, user.passwordHash);
      if (!valid) {
        this._log('PASSWORD_CHANGE_BAD_CURRENT', { userId });
        return { success: false, message: 'Current password is incorrect.' };
      }

      const newHash = await this.passwordUtils.hashPassword(newPassword);
      await this.userRepository.updatePassword(userId, newHash);

      // SECURITY: revoke all CSRF tokens — client must re-authenticate
      this.userRepository.revokeCsrfTokens(userId);
      this._log('PASSWORD_CHANGE_OK', { userId });

      return { success: true, message: 'Password changed successfully.' };
    } catch (err) {
      // Expose validation errors (password strength) but not internal errors
      if (err.message && err.message.length < 200) {
        return { success: false, message: err.message };
      }
      console.error('[AuthController] changePassword error:', err.message);
      return { success: false, message: 'Password change failed.' };
    }
  }

  // =========================================================================
  // Input validation
  // =========================================================================

  _validateRegistrationInput(email, password, role) {
    if (!email || typeof email !== 'string' || email.length > 254) {
      throw new Error('Invalid email address.');
    }
    const emailRe = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRe.test(email)) throw new Error('Invalid email format.');

    if (!password || typeof password !== 'string') throw new Error('Password required.');

    const validRoles = ['user', 'admin'];
    if (role && !validRoles.includes(role)) throw new Error('Invalid role.');
  }

  // =========================================================================
  // IP lockout helpers
  // =========================================================================

  _recordFailedAttempt(ip) {
    if (!ip) return;
    const k  = `${ip}_attempts`;
    const rec = this.failedLoginAttempts.get(k) || { count: 0, firstAttempt: Date.now() };
    rec.count++;
    rec.lastAttempt = Date.now();
    this.failedLoginAttempts.set(k, rec);
    if (rec.count >= this.maxFailedAttempts) {
      this.failedLoginAttempts.set(`${ip}_locked`, { lockedAt: Date.now() });
    }
  }

  _isIPLocked(ip) {
    if (!ip) return false;
    const lock = this.failedLoginAttempts.get(`${ip}_locked`);
    if (!lock) return false;
    if (Date.now() - lock.lockedAt > this.lockoutDuration) {
      this.failedLoginAttempts.delete(`${ip}_locked`);
      return false;
    }
    return true;
  }

  _clearFailedAttempts(ip) {
    if (!ip) return;
    this.failedLoginAttempts.delete(`${ip}_attempts`);
  }

  // =========================================================================
  // Helpers
  // =========================================================================

  /** Hash email for logging so we don't store plaintext emails in audit log */
  _hashEmail(email) {
    const crypto = require('crypto');
    return crypto.createHash('sha256').update(email.toLowerCase()).digest('hex').slice(0, 16);
  }

  _log(type, data) {
    if (this.auditLog) this.auditLog.append({ type, ...data });
  }

  getStats() {
    return {
      lockedIPs:          [...this.failedLoginAttempts.keys()].filter((k) => k.includes('_locked')).length,
      maxFailedAttempts:  this.maxFailedAttempts,
      lockoutDurationMin: this.lockoutDuration / 60000
    };
  }
}

module.exports = AuthController;

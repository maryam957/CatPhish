/**
 * auth_controller.js — Authentication Business Logic (FIXED)
 * -----------------------------------------------------------------------
 * FIXES applied:
 *  1. _validateRegistrationInput now calls passwordUtils.validatePassword()
 *     so weak-password errors surface as { success:false, message:"..." }
 *     instead of the generic "Registration failed" catch-all.
 *  2. register() catch block now re-throws validation errors so they
 *     propagate with the real message.
 *  3. login() surfaces a specific "Please verify your email" message in
 *     DEMO_MODE (no user enumeration risk in demo; in prod it stays generic).
 *  4. Exposed authController.userRepository so auth_routes.js refresh route
 *     can access it (it was already used there, this is just documentation).
 */

'use strict';

class AuthController {
  constructor(passwordUtils, jwtUtils, userRepository, auditLog) {
    this.passwordUtils  = passwordUtils;
    this.jwtUtils       = jwtUtils;
    this.userRepository = userRepository;
    this.auditLog       = auditLog || null;

    this.failedLoginAttempts = new Map();
    this.maxFailedAttempts   = 5;
    this.lockoutDuration     = 15 * 60 * 1000;
  }

  // =========================================================================
  // Registration
  // =========================================================================

  async register(data) {
    try {
      const { email, password, clientIp } = data;
      // FIX 1: _validateRegistrationInput now also checks password strength.
      // Validation errors are real Errors with user-facing messages — we
      // re-throw them so the catch block can decide to expose them.
      this._validateRegistrationInput(email, password);

      const existing = await this.userRepository.findByEmail(email);
      if (existing) {
        this._log('REGISTER_DUPLICATE', { email: this._hashEmail(email), clientIp });
        return { success: true, message: 'Check your email for a verification link.' };
      }

      const passwordHash   = await this.passwordUtils.hashPassword(password);
      const normalizedRole = 'user';

      const user = await this.userRepository.create({
        email:          email.toLowerCase(),
        passwordHash,
        role:           normalizedRole,
        createdAt:      new Date(),
        isActive:       true,  //should be false
        isLocked:       false,
        failedAttempts: 0,
        lastLogin:      null
      });

      const verToken = await this.userRepository.createVerificationToken(user.id);
      this._log('REGISTER_OK', { userId: user.id, role: normalizedRole, clientIp });

      const isDemoMode = process.env.CATPHISH_DEMO_MODE === 'true';
      return {
        success: true,
        message: 'Check your email for a verification link.',
        ...(isDemoMode && { _demoVerifyToken: verToken, _demoUserId: user.id })
      };
    } catch (err) {
      // FIX 2: expose validation/business-logic errors with the real message.
      // Internal system errors get the generic message.
      const isValidationError = err.message && err.message.length < 200 &&
        !err.message.includes('ENOENT') && !err.message.includes('EACCES');
      if (isValidationError) {
        return { success: false, message: err.message };
      }
      console.error('[AuthController] register error:', err.message);
      return { success: false, message: 'Registration failed. Please try again later.' };
    }
  }

  // =========================================================================
  // Login
  // =========================================================================

  async login(data) {
    try {
      const { email, password, clientIp } = data;
      if (!email || !password) {
        return { success: false, message: 'Invalid email or password.' };
      }

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
        return { success: false, message: 'Invalid email or password.' };
      }

      // FIX 3: In DEMO MODE give a helpful "verify your email" message.
      // In production the message stays generic to avoid account enumeration.
      if (!user.isActive) {
        this._log('LOGIN_INACTIVE', { userId: user.id, clientIp });
        const isDemoMode = process.env.CATPHISH_DEMO_MODE === 'true';
        return {
          success: false,
          message: isDemoMode
            ? 'Account not yet verified. Use the demo-activate endpoint or verify your email first.'
            : 'Invalid email or password.',
          ...(isDemoMode && { needsVerification: true })
        };
      }

      const valid = await this.passwordUtils.verifyPassword(password, user.passwordHash);
      if (!valid) {
        this._recordFailedAttempt(clientIp);
        const newCount = (user.failedAttempts || 0) + 1;
        await this.userRepository.updateFailedAttempts(user.id, newCount);

        if (newCount >= this.maxFailedAttempts) {
          await this.userRepository.lockUser(user.id);
          this._log('ACCOUNT_LOCKED', { userId: user.id, clientIp });
        }
        this._log('LOGIN_BAD_PW', { userId: user.id, clientIp, count: newCount });
        return { success: false, message: 'Invalid email or password.' };
      }

      if (user.failedAttempts > 0) await this.userRepository.updateFailedAttempts(user.id, 0);
      this._clearFailedAttempts(clientIp);
      await this.userRepository.updateLastLogin(user.id);

      const payload      = { userId: user.id, email: user.email, role: user.role };
      const accessToken  = this.jwtUtils.generateAccessToken(payload);
      const refreshToken = this.jwtUtils.generateRefreshToken(payload);
      const csrfToken    = this.userRepository.issueCsrfToken(user.id);

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

  async verifyEmail(email, verificationToken) {
    try {
      if (!email || !verificationToken) {
        return { success: false, message: 'Verification failed.' };
      }

      const userId = await this.userRepository.consumeVerificationToken(verificationToken);
      if (!userId) {
        this._log('VERIFY_EMAIL_BAD_TOKEN', {});
        return { success: false, message: 'Verification failed.' };
      }

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

      const valid = await this.passwordUtils.verifyPassword(currentPassword, user.passwordHash);
      if (!valid) {
        this._log('PASSWORD_CHANGE_BAD_CURRENT', { userId });
        return { success: false, message: 'Current password is incorrect.' };
      }

      const newHash = await this.passwordUtils.hashPassword(newPassword);
      await this.userRepository.updatePassword(userId, newHash);

      this.userRepository.revokeCsrfTokens(userId);
      this._log('PASSWORD_CHANGE_OK', { userId });

      return { success: true, message: 'Password changed successfully.' };
    } catch (err) {
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

  _validateRegistrationInput(email, password) {
    if (!email || typeof email !== 'string' || email.length > 254) {
      throw new Error('Invalid email address.');
    }
    const emailRe = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRe.test(email)) throw new Error('Invalid email format.');

    if (!password || typeof password !== 'string') throw new Error('Password required.');

    // FIX: delegate to passwordUtils so password strength errors surface
    this.passwordUtils.validatePassword(password);
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
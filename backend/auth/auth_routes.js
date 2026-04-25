/**
 * auth_routes.js — Express route definitions for all auth endpoints
 * -----------------------------------------------------------------------
 * Every previously stubbed route is now fully implemented:
 *   POST /api/auth/register
 *   POST /api/auth/login          -> sets httpOnly refresh-token cookie, CSRF header
 *   POST /api/auth/verify-email
 *   POST /api/auth/refresh
 *   POST /api/auth/logout
 *   GET  /api/auth/me
 *   POST /api/auth/change-password
 *   GET  /api/auth/csrf-token     -> issue a CSRF token for the current session
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *  SECURITY NOTES
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *  SECURITY: Refresh token stored in httpOnly + Secure + SameSite=Strict
 *    cookie — inaccessible to JS on the page.
 *  SECURITY: CSRF token returned in response body and expected in
 *    X-CSRF-Token header on mutating requests.
 *  SECURITY: change-password delegates to authController.changePassword
 *    which re-verifies the current password before accepting the new one.
 */

'use strict';

function setupAuthRoutes(app, authController, authMiddleware) {

  const COOKIE_OPTS = {
    httpOnly:  true,
    secure:    process.env.NODE_ENV === 'production',   // HTTPS only in prod
    sameSite:  'Strict',
    maxAge:    7 * 24 * 60 * 60 * 1000                 // 7 days ms
  };

  const allowOnlyFields = (allowed) => (req, res, next) => {
    const body = req.body || {};
    const keys = Object.keys(body);
    if (keys.some((k) => !allowed.includes(k))) {
      return res.status(400).json({ success: false, error: 'Invalid request payload.' });
    }
    return next();
  };

  // ---- Register ----------------------------------------------------------
  app.post('/api/auth/register',
    authMiddleware.rateLimitByIP,
    authMiddleware.validateInput,
    allowOnlyFields(['email', 'password']),
    async (req, res) => {
      try {
        const { email, password } = req.body;
        const clientIp = req.ip || req.connection.remoteAddress;
        const result   = await authController.register({ email, password, clientIp });
        // SECURITY: always 200 (prevents timing-based enumeration)
        res.status(200).json(result);
      } catch (err) {
        console.error('[AuthRoutes] register error:', err.message);
        res.status(500).json({ success: false, error: 'Registration failed. Try again.' });
      }
    }
  );

  // ---- Login -------------------------------------------------------------
  app.post('/api/auth/login',
    authMiddleware.rateLimitByIP,
    authMiddleware.validateInput,
    allowOnlyFields(['email', 'password']),
    async (req, res) => {
      try {
        const { email, password } = req.body;
        const clientIp = req.ip || req.connection.remoteAddress;

        if (!email || !password) {
          return res.status(400).json({ success: false, error: 'Email and password required.' });
        }

        const result = await authController.login({ email, password, clientIp });

        if (!result.success) {
          return res.status(401).json({ success: false, error: 'Authentication failed.' });
        }

        // SECURITY: refresh token in httpOnly cookie (not accessible to JS)
        res.cookie('refreshToken', result.refreshToken, COOKIE_OPTS);

        // SECURITY: CSRF token in response body — client must echo it back
        // in X-CSRF-Token header on subsequent mutating requests.
        res.status(200).json({
          success:     true,
          accessToken: result.accessToken,
          csrfToken:   result.csrfToken,
          role:        result.role,
          expiresIn:   result.expiresIn,
          message:     result.message
        });
      } catch (err) {
        console.error('[AuthRoutes] login error:', err.message);
        res.status(500).json({ success: false, error: 'Login failed. Try again.' });
      }
    }
  );

  // ---- Verify email ------------------------------------------------------
  app.post('/api/auth/verify-email', async (req, res) => {
    try {
      const { email, token } = req.body;
      if (!email || !token) {
        return res.status(400).json({ success: false, error: 'Email and token required.' });
      }
      const result = await authController.verifyEmail(email, token);
      res.status(result.success ? 200 : 400).json(result);
    } catch (err) {
      console.error('[AuthRoutes] verify-email error:', err.message);
      res.status(500).json({ success: false, error: 'Verification failed.' });
    }
  });

  // ---- Refresh access token ----------------------------------------------
  app.post('/api/auth/refresh',
    authMiddleware.verifyRefreshToken,
    async (req, res) => {
      try {
        const refreshToken = req.cookies.refreshToken;
        if (!refreshToken) {
          return res.status(401).json({ success: false, error: 'Refresh token not found.' });
        }

        const { userId, email } = req.user;
        const user = await authController.userRepository.findById(userId);
        if (!user || !user.isActive || user.isLocked) {
          res.clearCookie('refreshToken');
          return res.status(401).json({ success: false, error: 'Session invalid.' });
        }

        const result = authController.jwtUtils.refreshAccessToken(
          refreshToken,
          { userId, email, role: user.role }
        );

        res.cookie('refreshToken', result.refreshToken, COOKIE_OPTS);
        res.status(200).json({
          success:     true,
          accessToken: result.accessToken,
          expiresIn:   result.expiresIn
        });
      } catch (err) {
        console.error('[AuthRoutes] refresh error:', err.message);
        res.clearCookie('refreshToken');
        res.status(401).json({ success: false, error: 'Token refresh failed.' });
      }
    }
  );

  // ---- Logout ------------------------------------------------------------
  app.post('/api/auth/logout',
    authMiddleware.verifyAccessToken,
    (req, res) => {
      try {
        const refreshToken = req.cookies.refreshToken;
        if (refreshToken) authController.jwtUtils.revokeRefreshToken(refreshToken);
        authController.userRepository.revokeCsrfTokens(req.user.userId);
        res.clearCookie('refreshToken', { httpOnly: true, secure: COOKIE_OPTS.secure, sameSite: 'Strict' });
        res.status(200).json({ success: true, message: 'Logged out.' });
      } catch (err) {
        console.error('[AuthRoutes] logout error:', err.message);
        res.status(500).json({ success: false, error: 'Logout failed.' });
      }
    }
  );

  // ---- Get current user --------------------------------------------------
  app.get('/api/auth/me',
    authMiddleware.verifyAccessToken,
    (req, res) => {
      res.status(200).json({
        success: true,
        user: { id: req.user.userId, email: req.user.email, role: req.user.role }
      });
    }
  );

  // ---- CSRF token issue --------------------------------------------------
  // Client calls this after login to get a fresh CSRF token if it lost the
  // one from the login response (e.g. SPA route change).
  app.get('/api/auth/csrf-token',
    authMiddleware.verifyAccessToken,
    (req, res) => {
      const token = authController.userRepository.issueCsrfToken(req.user.userId);
      res.status(200).json({ csrfToken: token });
    }
  );

  // ---- Change password ---------------------------------------------------
  // SECURITY: requires valid access token AND re-verification of current password
  app.post('/api/auth/change-password',
    authMiddleware.verifyAccessToken,
    authMiddleware.validateCSRFToken,
    allowOnlyFields(['currentPassword', 'newPassword']),
    async (req, res) => {
      try {
        const { currentPassword, newPassword } = req.body;
        const result = await authController.changePassword(
          req.user.userId,
          currentPassword,
          newPassword
        );
        res.status(result.success ? 200 : 400).json(result);
      } catch (err) {
        console.error('[AuthRoutes] change-password error:', err.message);
        res.status(500).json({ success: false, error: 'Password change failed.' });
      }
    }
  );

  console.log('[AuthRoutes] Routes configured');
}

module.exports = setupAuthRoutes;

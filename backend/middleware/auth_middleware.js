/**
 * auth_middleware.js — Express middleware for JWT auth, CSRF, rate limiting
 * -----------------------------------------------------------------------
 * All previously stubbed middleware is now fully implemented.
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *  SECURITY NOTES
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *  SECURITY: verifyAccessToken reads only the Authorization header.
 *    It NEVER reads from query strings or request bodies — that would
 *    allow fixation attacks.
 *  SECURITY: validateCSRFToken checks the X-CSRF-Token header against
 *    the server-side per-user token store (UserRepository.validateCsrfToken).
 *    Simple existence-check is NOT sufficient.
 *  SECURITY: rateLimitByIP uses a sliding-window counter per IP with a
 *    hard cap. In production replace with Redis for multi-process safety.
 *  SECURITY: securityHeaders sets HSTS, nosniff, X-Frame-Options, and a
 *    tight CSP. We do NOT set X-XSS-Protection: that header is deprecated
 *    and can actually introduce vulnerabilities in older browsers.
 */

'use strict';

function createAuthMiddleware(jwtUtils, userRepository) {
  // ---- Access token verification ----------------------------------------
  const verifyAccessToken = (req, res, next) => {
    try {
      const authHeader = req.headers.authorization;
      if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ success: false, error: 'Authorization header missing.' });
      }

      // SECURITY: only read from header, never from query string
      const token   = authHeader.slice(7);
      const payload = jwtUtils.verifyToken(token);

      if (payload.type !== 'access') {
        return res.status(401).json({ success: false, error: 'Invalid token type.' });
      }

      req.user = {
        userId:      payload.userId,
        email:       payload.email,
        role:        payload.role,
        tokenIssued: payload.iat
      };
      next();
    } catch (err) {
      const msg = err.message || '';
      if (msg.includes('expired')) {
        return res.status(401).json({ success: false, error: 'Token expired.' });
      }
      return res.status(401).json({ success: false, error: 'Invalid or expired token.' });
    }
  };

  // ---- Refresh token verification ----------------------------------------
  const verifyRefreshToken = (req, res, next) => {
    try {
      const refreshToken = req.cookies && req.cookies.refreshToken;
      if (!refreshToken) {
        return res.status(401).json({ success: false, error: 'Refresh token not found.' });
      }

      const payload = jwtUtils.verifyToken(refreshToken);
      if (payload.type !== 'refresh') {
        return res.status(401).json({ success: false, error: 'Invalid token type.' });
      }

      req.user = { userId: payload.userId, email: payload.email, jti: payload.jti };
      next();
    } catch (err) {
      res.clearCookie('refreshToken');
      return res.status(401).json({ success: false, error: 'Invalid refresh token.' });
    }
  };

  // ---- Role-based authorisation -----------------------------------------
  const authorize = (allowedRoles = []) => (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ success: false, error: 'Not authenticated.' });
    }
    if (allowedRoles.length && !allowedRoles.includes(req.user.role)) {
      console.warn(`[AuthMiddleware] Unauthorized: ${req.user.email} (${req.user.role})`);
      return res.status(403).json({ success: false, error: 'Insufficient permissions.' });
    }
    next();
  };

  // ---- Input validation --------------------------------------------------
  const validateInput = (req, res, next) => {
    try {
      const { email, password } = req.body || {};
      const MAX_EMAIL = 254, MAX_PW = 128;

      if (email !== undefined) {
        if (!email || typeof email !== 'string' || email.length === 0) {
          return res.status(400).json({ success: false, error: 'Invalid email.' });
        }
        if (email.length > MAX_EMAIL) {
          return res.status(400).json({ success: false, error: 'Email too long.' });
        }
      }
      if (password !== undefined) {
        if (!password || typeof password !== 'string' || password.length === 0) {
          return res.status(400).json({ success: false, error: 'Invalid password.' });
        }
        if (password.length > MAX_PW) {
          return res.status(400).json({ success: false, error: 'Password too long.' });
        }
      }
      next();
    } catch (err) {
      return res.status(400).json({ success: false, error: 'Invalid input.' });
    }
  };

  // ---- CSRF validation ---------------------------------------------------
  // SECURITY: real server-side validation — not just existence check.
  // Requires verifyAccessToken to have already run (req.user must exist).
  const validateCSRFToken = (req, res, next) => {
    try {
      const method = req.method || '';
      if (!['POST', 'PUT', 'DELETE', 'PATCH'].includes(method)) {
        return next(); // safe methods don't need CSRF protection
      }

      // SECURITY: read from header only — body-based CSRF tokens can be
      // leaked via XSS on the same origin.
      const csrfToken = req.headers['x-csrf-token'];
      if (!csrfToken) {
        return res.status(403).json({ success: false, error: 'CSRF token missing.' });
      }

      if (!req.user || !req.user.userId) {
        // Can't validate without knowing who the user is
        return res.status(401).json({ success: false, error: 'Not authenticated.' });
      }

      // SECURITY: validate against server-side store with timing-safe compare
      if (!userRepository || !userRepository.validateCsrfToken(req.user.userId, csrfToken)) {
        console.warn('[AuthMiddleware] CSRF validation failed for user:', req.user.userId);
        return res.status(403).json({ success: false, error: 'CSRF validation failed.' });
      }

      next();
    } catch (err) {
      console.error('[AuthMiddleware] CSRF error:', err.message);
      return res.status(403).json({ success: false, error: 'CSRF validation failed.' });
    }
  };

  // ---- Rate limiting -----------------------------------------------------
  // Sliding-window per IP. Replace backing store with Redis in production.
  const rateLimitByIP = (() => {
    const windows  = new Map(); // ip -> { count, windowStart }
    const WINDOW   = 15 * 60 * 1000; // 15 min
    const MAX_REQS = 60;             // 60 requests per window

    return (req, res, next) => {
      const ip  = req.ip || req.connection.remoteAddress || 'unknown';
      const now = Date.now();
      let   rec = windows.get(ip);

      if (!rec || (now - rec.windowStart) > WINDOW) {
        rec = { count: 0, windowStart: now };
        windows.set(ip, rec);
      }
      rec.count++;

      res.set({
        'X-RateLimit-Limit':     String(MAX_REQS),
        'X-RateLimit-Remaining': String(Math.max(0, MAX_REQS - rec.count)),
        'X-RateLimit-Reset':     new Date(rec.windowStart + WINDOW).toISOString()
      });

      if (rec.count > MAX_REQS) {
        console.warn('[AuthMiddleware] Rate limit hit for IP:', ip);
        return res.status(429).json({ success: false, error: 'Too many requests. Try later.' });
      }
      next();
    };
  })();

  // ---- Security response headers ----------------------------------------
  // helmet() in server.js covers most of this, but we add it here too for
  // routes not served through helmet (e.g. in tests).
  const securityHeaders = (req, res, next) => {
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    // SECURITY: CSP for API responses (no HTML served, but belt-and-braces)
    res.setHeader('Content-Security-Policy', "default-src 'none'");
    if (req.secure) {
      res.setHeader('Strict-Transport-Security', 'max-age=63072000; includeSubDomains; preload');
    }
    next();
  };

  // ---- Error handler -----------------------------------------------------
  const errorHandler = (err, req, res, next) => {
    console.error('[AuthMiddleware] Unhandled error:', err.message);
    res.status(err.status || 500).json({ success: false, error: 'Internal server error.' });
  };

  return {
    verifyAccessToken,
    verifyRefreshToken,
    authorize,
    validateInput,
    validateCSRFToken,
    rateLimitByIP,
    securityHeaders,
    errorHandler
  };
}

module.exports = createAuthMiddleware;

/**
 * session_routes.js
 * SECURITY: rate-limited to prevent session-flooding DoS.
 */
'use strict';
function setupSessionRoutes(app, sessionController, authMiddleware) {
  const validateSessionPayload = (req, res, next) => {
    const body = req.body;
    if (!body || typeof body !== 'object' || Array.isArray(body)) {
      return res.status(400).json({ error: 'Invalid request payload.' });
    }
    const allowed = ['sessionId', 'keyJwk'];
    const keys = Object.keys(body);
    if (keys.some((k) => !allowed.includes(k))) {
      return res.status(400).json({ error: 'Invalid request payload.' });
    }
    return next();
  };

  app.post('/api/sessions/register',
    authMiddleware.rateLimitByIP,
    validateSessionPayload,
    (req, res) => sessionController.register(req, res)
  );
}
module.exports = setupSessionRoutes;
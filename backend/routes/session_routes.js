/**
 * session_routes.js
 * SECURITY: rate-limited to prevent session-flooding DoS.
 */
'use strict';
function setupSessionRoutes(app, sessionController, authMiddleware) {
  app.post('/api/sessions/register',
    authMiddleware.rateLimitByIP,
    (req, res) => sessionController.register(req, res)
  );
}
module.exports = setupSessionRoutes;

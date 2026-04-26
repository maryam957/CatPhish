/**
 * reporting_routes.js
 * SECURITY: POST /api/reports is rate-limited via auth middleware.
 * GET  /api/reports/admin requires admin JWT.
 */
function setupReportingRoutes(app, reportingController, authMiddleware) {
  const validateReportPayload = (req, res, next) => {
    const body = req.body;
    if (!body || typeof body !== 'object' || Array.isArray(body)) {
      return res.status(400).json({ error: 'Invalid request payload.' });
    }
    const allowed = ['hashPrefix', 'category', 'notes', 'nonce', 'ts', 'sessionId', 'sig'];
    const keys = Object.keys(body);
    if (keys.some((k) => !allowed.includes(k))) {
      return res.status(400).json({ error: 'Invalid request payload.' });
    }
    return next();
  };

  // Public: submit a report (rate-limited)
  app.post('/api/reports',
    authMiddleware.rateLimitByIP,
    validateReportPayload,
    (req, res) => reportingController.submitReport(req, res)
  );
  // Admin: read all reports
  app.get('/api/reports/admin',
    authMiddleware.verifyAccessToken,
    authMiddleware.authorize(['admin']),
    (req, res) => reportingController.getReports(req, res)
  );
}
module.exports = setupReportingRoutes;
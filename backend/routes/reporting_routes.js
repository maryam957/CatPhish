/**
 * reporting_routes.js
 * SECURITY: POST /api/reports is rate-limited via auth middleware.
 * GET  /api/reports/admin requires admin JWT.
 */
function setupReportingRoutes(app, reportingController, authMiddleware) {
  // Public: submit a report (rate-limited)
  app.post('/api/reports',
    authMiddleware.rateLimitByIP,
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

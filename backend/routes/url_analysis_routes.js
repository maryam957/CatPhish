/**
 * url_analysis_routes.js
 * SECURITY: POST is rate-limited. Stats endpoint requires admin JWT.
 */
'use strict';
function setupUrlAnalysisRoutes(app, urlAnalysisCtrl, authMiddleware) {
  app.post('/api/url-analysis/report',
    authMiddleware.rateLimitByIP,
    (req, res) => urlAnalysisCtrl.report(req, res)
  );
  app.get('/api/url-analysis/stats',
    authMiddleware.verifyAccessToken,
    authMiddleware.authorize(['admin']),
    (req, res) => urlAnalysisCtrl.getStats(req, res)
  );
}
module.exports = setupUrlAnalysisRoutes;

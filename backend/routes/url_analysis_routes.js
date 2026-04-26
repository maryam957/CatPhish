/**
 * url_analysis_routes.js
 * SECURITY: POST is rate-limited. Stats endpoint requires admin JWT.
 */
'use strict';
function setupUrlAnalysisRoutes(app, urlAnalysisCtrl, authMiddleware) {
  const validateUrlAnalysisPayload = (req, res, next) => {
    const body = req.body;
    if (!body || typeof body !== 'object' || Array.isArray(body)) {
      return res.status(400).json({ error: 'Invalid request payload.' });
    }
    const allowed = ['hashPrefix', 'clientRiskScore', 'riskFactors', 'timestamp'];
    const keys = Object.keys(body);
    if (keys.some((k) => !allowed.includes(k))) {
      return res.status(400).json({ error: 'Invalid request payload.' });
    }
    return next();
  };

  app.post('/api/url-analysis/report',
    authMiddleware.rateLimitByIP,
    validateUrlAnalysisPayload,
    (req, res) => urlAnalysisCtrl.report(req, res)
  );
  app.get('/api/url-analysis/stats',
    authMiddleware.verifyAccessToken,
    authMiddleware.authorize(['admin']),
    (req, res) => urlAnalysisCtrl.getStats(req, res)
  );
}
module.exports = setupUrlAnalysisRoutes;
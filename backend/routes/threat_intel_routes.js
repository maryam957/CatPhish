'use strict';
function setupThreatIntelRoutes(app, ctrl, authMiddleware) {
  // Public: extension pulls hash-prefix updates
  app.get('/api/threat-intel/updates',
    authMiddleware.rateLimitByIP,
    (req, res) => ctrl.getUpdates(req, res)
  );
  // Admin: add a new threat hash
  app.post('/api/threat-intel/entries',
    authMiddleware.verifyAccessToken,
    authMiddleware.authorize(['admin']),
    (req, res) => ctrl.addEntry(req, res)
  );
  // Admin: remove a threat hash by prefix
  app.delete('/api/threat-intel/entries/:prefix',
    authMiddleware.verifyAccessToken,
    authMiddleware.authorize(['admin']),
    (req, res) => ctrl.removeEntry(req, res)
  );
  // Admin: verify audit-log chain
  app.get('/api/threat-intel/audit',
    authMiddleware.verifyAccessToken,
    authMiddleware.authorize(['admin']),
    (req, res) => ctrl.getAuditStatus(req, res)
  );
}
module.exports = setupThreatIntelRoutes;

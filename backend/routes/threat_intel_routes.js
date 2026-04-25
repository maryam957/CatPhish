'use strict';
function setupThreatIntelRoutes(app, ctrl, authMiddleware) {
  const validateThreatEntryPayload = (req, res, next) => {
    const body = req.body;
    if (!body || typeof body !== 'object' || Array.isArray(body)) {
      return res.status(400).json({ error: 'Invalid request payload.' });
    }
    const allowed = ['prefix', 'fullHash', 'source'];
    const keys = Object.keys(body);
    if (keys.some((k) => !allowed.includes(k))) {
      return res.status(400).json({ error: 'Invalid request payload.' });
    }
    return next();
  };

  // Public: extension pulls hash-prefix updates
  app.get('/api/threat-intel/updates',
    authMiddleware.rateLimitByIP,
    (req, res) => ctrl.getUpdates(req, res)
  );
  // Admin: add a new threat hash
  app.post('/api/threat-intel/entries',
    authMiddleware.verifyAccessToken,
    authMiddleware.authorize(['admin']),
    validateThreatEntryPayload,
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

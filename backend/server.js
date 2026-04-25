/**
 * server.js — CatPhish backend entry point
 * -----------------------------------------------------------------------
 * Quick-start (demo mode — no email server needed):
 *
 *   1. Generate secrets:
 *        node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
 *        # Run 3 times, use outputs for the 3 required vars below
 *
 *   2. Set env and start:
 *        CATPHISH_JWT_SECRET=<32+chars> \
 *        CATPHISH_AUDIT_KEY=<64hexchars> \
 *        CATPHISH_DEMO_MODE=true \
 *        node backend/server.js
 *
 * Required env vars:
 *   CATPHISH_JWT_SECRET    >= 32 random chars
 *   CATPHISH_AUDIT_KEY     64 hex chars  (for HMAC audit log key)
 *   PORT                   default 3000
 *
 * Optional env vars:
 *   CATPHISH_REPORT_SECRET >= 32 chars  (fallback sig check if no session key)
 *   NODE_ENV               'production' → HTTPS-only cookies + HSTS
 *   CATPHISH_DEMO_MODE     'true'       → enables /api/auth/demo-activate
 *   ALLOWED_ORIGINS        comma-separated extra CORS origins
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *  SECURITY NOTES
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *  SECURITY: JWT secret validated at startup — exits if missing/short.
 *  SECURITY: helmet() sets X-Frame-Options, nosniff, HSTS, CSP.
 *  SECURITY: express.json({ limit:'16kb' }) prevents JSON DoS.
 *  SECURITY: CORS restricted to localhost + chrome-extension:// only.
 *  SECURITY: cookie-parser reads httpOnly refresh token cookie.
 *  SECURITY: userRepo passed to auth middleware for real CSRF validation.
 */

'use strict';

const express      = require('express');
const helmet       = require('helmet');
const cors         = require('cors');
const cookieParser = require('cookie-parser');
const path         = require('path');

// ---- Startup validation --------------------------------------------------
const JWT_SECRET = process.env.CATPHISH_JWT_SECRET;
if (!JWT_SECRET || JWT_SECRET.length < 32) {
  console.error('[CatPhish] CATPHISH_JWT_SECRET must be >= 32 chars. Generate:');
  console.error("  node -e \"console.log(require('crypto').randomBytes(32).toString('hex'))\"");
  process.exit(1);
}
const PORT = parseInt(process.env.PORT, 10) || 3030;

// ---- Dependencies --------------------------------------------------------
const AuthController        = require('./auth/auth_controller');
const JWTUtils              = require('./auth/jwt_utils');
const PasswordUtils         = require('./auth/password_utils');
const setupAuthRoutes       = require('./auth/auth_routes');
const createMiddleware      = require('./middleware/auth_middleware');

const UserRepository        = require('./storage/user_repository');
const ReportRepository      = require('./storage/report_repository');
const SessionRepository     = require('./storage/session_repository');
const ServerAuditLog        = require('./storage/audit_log');

const ReportingController   = require('./controllers/reporting_controller');
const ThreatIntelController = require('./controllers/threat_intel_controller');
const UrlAnalysisController = require('./controllers/url_analysis_controller');
const SessionController     = require('./controllers/session_controller');

const setupReportingRoutes   = require('./routes/reporting_routes');
const setupThreatIntelRoutes = require('./routes/threat_intel_routes');
const setupUrlAnalysisRoutes = require('./routes/url_analysis_routes');
const setupSessionRoutes     = require('./routes/session_routes');

// ---- Build app -----------------------------------------------------------
const app = express();
app.set('trust proxy', 1);

// SECURITY: helmet sets security headers on every response
app.use(helmet({
  contentSecurityPolicy: {
    directives: { defaultSrc: ["'none'"], connectSrc: ["'self'"] }
  }
}));

// SECURITY: CORS — Chrome extensions + localhost only
const allowedOrigins = (process.env.ALLOWED_ORIGINS || '')
  .split(',').map((s) => s.trim()).filter(Boolean)
  .concat(['http://localhost:3030', 'http://127.0.0.1:3030']);

app.use(cors({
  origin: (origin, cb) => {
    if (!origin || allowedOrigins.includes(origin) || /^chrome-extension:\/\//.test(origin)) {
      cb(null, true);
    } else {
      cb(new Error('CORS: origin not allowed'));
    }
  },
  credentials: true
}));

// SECURITY: body size cap prevents JSON DoS attacks
app.use(express.json({ limit: '16kb' }));
// SECURITY: reads httpOnly refresh-token cookie
app.use(cookieParser());

// SECURITY: in production, reject insecure transport for auth endpoints.
app.use((req, res, next) => {
  if (process.env.NODE_ENV !== 'production') return next();
  if (!req.path.startsWith('/api/auth/')) return next();
  if (req.secure || req.headers['x-forwarded-proto'] === 'https') return next();
  return res.status(400).json({ error: 'Secure transport required.' });
});

// ---- Instantiate services ------------------------------------------------
const jwtUtils        = new JWTUtils(JWT_SECRET);
const passwordUtils   = new PasswordUtils();
const userRepo        = new UserRepository();
const reportRepo      = new ReportRepository();
const sessionRepo     = new SessionRepository();
const auditLog        = new ServerAuditLog(path.join(__dirname, 'audit_log.jsonl'));

// SECURITY: userRepo passed to middleware so CSRF uses server-side token store
const authMiddleware  = createMiddleware(jwtUtils, userRepo);
const authController  = new AuthController(passwordUtils, jwtUtils, userRepo, auditLog);

const reportingCtrl   = new ReportingController(reportRepo, sessionRepo, auditLog);
const threatIntelCtrl = new ThreatIntelController(auditLog);
const urlAnalysisCtrl = new UrlAnalysisController(auditLog);
const sessionCtrl     = new SessionController(sessionRepo, auditLog);

// ---- Register routes -----------------------------------------------------
setupAuthRoutes(app, authController, authMiddleware);
setupSessionRoutes(app, sessionCtrl, authMiddleware);
setupReportingRoutes(app, reportingCtrl, authMiddleware);
setupThreatIntelRoutes(app, threatIntelCtrl, authMiddleware);
setupUrlAnalysisRoutes(app, urlAnalysisCtrl, authMiddleware);

// ---- Health check --------------------------------------------------------
app.get('/api/health', (req, res) => {
  res.json({
    ok:         true,
    ts:         new Date().toISOString(),
    version:    '1.1.0',
    threatDb:   threatIntelCtrl.entries.length,
    sessions:   sessionRepo.sessions.size
  });
});

// ---- Root route ----------------------------------------------------------
app.get('/', (req, res) => {
  res.json({ ok: true, message: 'CatPhish API server is running.', docs: '/api/health' });
});

// ---- Compatibility route --------------------------------------------------
// Some local scripts/tests probe /get; map it to health-style output.
app.get('/get', (req, res) => {
  res.json({ ok: true, message: 'Use /api/health for the canonical health endpoint.' });
});

// ---- Global error handler -----------------------------------------------
// SECURITY: never leak stack traces to clients
app.use((err, req, res, _next) => {
  console.error('[CatPhish/server]', err.message);
  res.status(err.status || 500).json({ error: 'Internal server error.' });
});

// ---- DEMO MODE: bypass email verification --------------------------------
if (process.env.CATPHISH_DEMO_MODE === 'true') {
  app.post('/api/auth/demo-activate', async (req, res) => {
    const { email } = req.body || {};
    if (!email) return res.status(200).json({ ok: true });
    const user = await userRepo.findByEmail(email.toLowerCase());
    if (!user) return res.status(200).json({ ok: true });
    await userRepo.activateUser(user.id);
    auditLog.append({ type: 'DEMO_USER_ACTIVATED', email: email.slice(0, 64) });
    console.warn('[CatPhish][DEMO] Activated without email verification:', email);
    res.json({ ok: true });
  });
  console.warn('[CatPhish] DEMO MODE — /api/auth/demo-activate is active');
}

// ---- Start ---------------------------------------------------------------
app.listen(PORT, '0.0.0.0', () => {
  console.log(`[CatPhish] Backend listening on http://0.0.0.0:${PORT}`);
  auditLog.append({ type: 'SERVER_STARTED', port: String(PORT) });
});

module.exports = app;

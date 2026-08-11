'use strict';

require('dotenv').config();

const express = require('express');
const path = require('path');
const rateLimit = require('express-rate-limit');
const routes = require('./routes/index');
const adminRoutes = require('./routes/admin');
const db = require('./services/database');
const statsWorker = require('./services/statsWorker');
const maintenanceWorker = require('./services/maintenanceWorker');
const { setupSwagger } = require('./swagger');
const db = require('./services/database');

const app = express();
const PORT = process.env.PORT || 3000;

// ─── Middleware ───────────────────────────────────────────────────────────────
app.set('trust proxy', 1); // nginx está delante

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ limit: '10mb', extended: true }));

// Rate limiting en endpoints de autenticación
const authLimiter = rateLimit({
  windowMs: 60 * 1000,   // 1 minuto
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Demasiados intentos. Espere un minuto e intente nuevamente.' },
});

// Archivos estáticos
app.use('/static', express.static(path.join(__dirname, '../public')));

// Headers de seguridad básicos
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  next();
});

// ─── Rutas ────────────────────────────────────────────────────────────────────
app.use('/auth/login', authLimiter);
app.use('/auth/register', authLimiter);
app.use('/auth/ldap', authLimiter);
app.use('/auth/hotel', authLimiter);
app.use('/auth/restaurant', authLimiter);
app.use('/auth/free-access', authLimiter);
// ─── Health Check ─────────────────────────────────────────────────────────────
app.get('/health', async (req, res) => {
  const checks = {
    postgres: 'ok',
    freeradius: 'ok',
  };

  try {
    const pool = db.getPool && db.getPool();
    if (pool) {
      await pool.query('SELECT 1');
    }
  } catch (e) {
    checks.postgres = 'fail';
  }

  try {
    const { authenticate } = require('./services/radius');
    // No hacemos ping real a RADIUS en health check para no bloquear
    checks.freeradius = process.env.RADIUS_SECRET ? 'ok' : 'unconfigured';
  } catch (e) {
    checks.freeradius = 'fail';
  }

  const status = checks.postgres === 'ok' ? 'ok' : 'degraded';
  res.status(status === 'ok' ? 200 : 503).json({
    status,
    checks,
    timestamp: new Date().toISOString(),
  });
});

// ─── Swagger / OpenAPI ──────────────────────────────────────────────────────
if (process.env.NODE_ENV !== 'test') {
  setupSwagger(app);
}

app.use('/admin', adminRoutes);
app.use('/', routes);

// ─── Manejo de errores ────────────────────────────────────────────────────────
app.use((err, req, res, next) => { // eslint-disable-line no-unused-vars
  console.error('[ERROR]', err.message, err.stack);
  if (req.path.startsWith('/auth')) {
    return res.status(500).json({ error: 'Error interno del servidor.' });
  }
  res.redirect('/error?msg=' + encodeURIComponent('Error interno. Por favor intente nuevamente.'));
});

// ─── Inicio ───────────────────────────────────────────────────────────────────
async function start() {
  await db.connect();
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`[PORTAL] Servidor iniciado en puerto ${PORT}`);
    console.log(`[PORTAL] Portal: ${process.env.PORTAL_NAME || 'Portal Cautivo'}`);
    
    // Iniciar el recolector de estadísticas de consumo en background
    statsWorker.startStatsWorker();

    // Iniciar el programador de depuración automática en background
    maintenanceWorker.startMaintenanceWorker();
  });
}

start().catch(err => {
  console.error('[FATAL] No se pudo iniciar el servidor:', err.message);
  process.exit(1);
});

module.exports = app;

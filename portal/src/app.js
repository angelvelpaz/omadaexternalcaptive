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
const dhcpSyncWorker = require('./services/dhcpSyncWorker');
const { setupSwagger } = require('./swagger');


const app = express();
const PORT = process.env.PORT || 3000;

function validateProductionEnvironment() {
  if (process.env.NODE_ENV !== 'production') return;
  const required = ['POSTGRES_DB', 'POSTGRES_USER', 'POSTGRES_PASSWORD', 'RADIUS_SECRET', 'ADMIN_SECRET', 'SESSION_SECRET'];
  const missing = required.filter(name => !String(process.env[name] || '').trim());
  if (missing.length > 0) {
    throw new Error(`Faltan variables de entorno obligatorias: ${missing.join(', ')}`);
  }
}

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
  skip: (req) => req.method === 'OPTIONS',
  message: { error: 'Demasiados intentos. Espere un minuto e intente nuevamente.' },
});

const adminLoginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Demasiados intentos de administración. Espere antes de reintentar.' },
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
// Manejar preflights CORS globalmente antes de los limiters de autenticación
app.use((req, res, next) => {
  if (req.method === 'OPTIONS' && req.path.startsWith('/auth/')) {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    return res.sendStatus(204);
  }
  next();
});
app.use('/auth/login', authLimiter);
app.use('/auth/register', authLimiter);
app.use('/auth/ldap', authLimiter);
app.use('/auth/hotel', authLimiter);
app.use('/auth/restaurant', authLimiter);
app.use('/auth/free-access', authLimiter);
app.use('/auth/check', authLimiter);
app.use('/auth/check-mac', authLimiter);
app.use('/auth/self-release', authLimiter);
app.use('/admin/api/login', adminLoginLimiter);

// Headers CORS para todas las rutas de autenticación
app.use('/auth', (req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  next();
});

app.use('/auth', (req, res, next) => {
  if (process.env.COOVACHILLI_ENABLED !== 'true' && req.body && req.body.vendor === 'coovachilli') {
    return res.status(403).json({ error: 'La integración CoovaChilli está desactivada.' });
  }
  next();
});
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
    const { probe } = require('./services/radius');
    checks.freeradius = await probe() ? 'ok' : 'fail';
  } catch (e) {
    checks.freeradius = 'fail';
  }

  const status = checks.postgres === 'ok' && checks.freeradius === 'ok' ? 'ok' : 'degraded';
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
  validateProductionEnvironment();
  await db.connect();
  if (process.env.NODE_ENV !== 'test') {
    app.listen(PORT, '0.0.0.0', () => {
      console.log(`[PORTAL] Servidor iniciado en puerto ${PORT}`);
      console.log(`[PORTAL] Portal: ${process.env.PORTAL_NAME || 'Portal Cautivo'}`);
      
      // Iniciar el recolector de estadísticas de consumo en background
      statsWorker.startStatsWorker();

      // Iniciar el programador de depuración automática en background
      maintenanceWorker.startMaintenanceWorker();

      // Iniciar el sincronizador de DHCP leases MikroTik ↔ MAC Bypass
      dhcpSyncWorker.startDhcpSyncWorker();
    });
  }
}

if (process.env.NODE_ENV !== 'test') {
  start().catch(err => {
    console.error('[FATAL] No se pudo iniciar el servidor:', err.message);
    process.exit(1);
  });
} else {
  // Las suites de prueba inicializan la BD explícitamente en sus hooks.
}

module.exports = app;

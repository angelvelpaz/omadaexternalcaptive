'use strict';

require('dotenv').config();

const express = require('express');
const path = require('path');
const rateLimit = require('express-rate-limit');
const routes = require('./routes/index');
const adminRoutes = require('./routes/admin');
const db = require('./services/database');
const statsWorker = require('./services/statsWorker');

const app = express();
const PORT = process.env.PORT || 3000;

// ─── Middleware ───────────────────────────────────────────────────────────────
app.set('trust proxy', 1); // nginx está delante

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

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
  });
}

start().catch(err => {
  console.error('[FATAL] No se pudo iniciar el servidor:', err.message);
  process.exit(1);
});

module.exports = app;

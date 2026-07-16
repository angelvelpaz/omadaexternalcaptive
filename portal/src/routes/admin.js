'use strict';

const express = require('express');
const { body, param, query, validationResult, matchedData } = require('express-validator');
const router = express.Router();
const path = require('path');
const fs = require('fs');
const db             = require('../services/database');
const controllerTest = require('../services/controllerTest');
const omadaSvc       = require('../services/omada');
const unifiSvc       = require('../services/unifi');

const ADMIN_SECRET = process.env.ADMIN_SECRET || 'admin_secret_cambia_esto';
const PUBLIC = path.join(__dirname, '../../public');

// Desactivar caché en todas las respuestas del router admin (API y HTML)
router.use((req, res, next) => {
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');
  next();
});

// ─── Utilidad para obtener la IP del cliente ──────────────────────────────────
function getClientIp(req) {
  let clientIp = req.headers['x-real-ip'] || req.headers['x-forwarded-for'] || req.ip || req.connection?.remoteAddress || '';
  if (clientIp.startsWith('::ffff:')) {
    clientIp = clientIp.substring(7);
  }
  return clientIp;
}

// ─── Utilidad de comprobación de IP CIDR ──────────────────────────────────────
function ipMatchesCidr(ip, cidr) {
  if (ip.startsWith('::ffff:')) {
    ip = ip.substring(7);
  }
  
  const parts = cidr.trim().split('/');
  const rangeIp = parts[0];
  const mask = parts[1] !== undefined ? parseInt(parts[1], 10) : 32;

  if (rangeIp === '0.0.0.0' && (mask === 0 || parts[1] === undefined)) {
    return true;
  }

  const ipToInt = (ipAddress) => {
    const ipParts = ipAddress.split('.');
    if (ipParts.length !== 4) return null;
    return ((parseInt(ipParts[0], 10) << 24) >>> 0) +
           ((parseInt(ipParts[1], 10) << 16) >>> 0) +
           ((parseInt(ipParts[2], 10) << 8) >>> 0) +
           (parseInt(ipParts[3], 10) >>> 0);
  };

  const ipNum = ipToInt(ip);
  const rangeNum = ipToInt(rangeIp);

  if (ipNum === null || rangeNum === null) return false;

  if (mask === 32) {
    return ipNum === rangeNum;
  }

  const maskBuffer = (0xFFFFFFFF << (32 - mask)) >>> 0;
  return (ipNum & maskBuffer) === (rangeNum & maskBuffer);
}

// ─── Middleware de lista blanca de IPs para administración ────────────────────
router.use(async (req, res, next) => {
  try {
    const config = await db.getControllerConfig('branding') || {};
    const ipWhitelist = config.ipWhitelist || '0.0.0.0';

    const clientIp = getClientIp(req);

    if (clientIp === '127.0.0.1' || clientIp === '::1' || clientIp === '') {
      return next();
    }

    const whitelistEntries = ipWhitelist.split(',').map(s => s.trim()).filter(Boolean);
    const allowed = whitelistEntries.some(cidr => ipMatchesCidr(clientIp, cidr));

    if (!allowed) {
      console.warn(`[SECURITY] Intento de acceso denegado a administración desde IP no autorizada: ${clientIp}`);
      // Branding dinámico para la página de error
      const portalName = config.portalName || 'Portal Wi-Fi';
      const primaryColor = config.primaryColor || '#2563eb';
      const logoUrl = config.logoUrl || '/static/logo.svg';

      return res.status(403).send(`
        <!DOCTYPE html>
        <html>
        <head>
          <meta charset="utf-8">
          <title>Acceso Restringido — ${portalName}</title>
          <meta name="viewport" content="width=device-width, initial-scale=1.0">
          <style>
            body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #f3f4f6; color: #1f2937; display: flex; align-items: center; justify-content: center; min-height: 100vh; margin: 0; padding: 1rem; box-sizing: border-box; }
            .card { background: white; padding: 2.5rem; border-radius: 16px; box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.1); max-width: 480px; width: 100%; text-align: center; border-top: 5px solid ${primaryColor}; box-sizing: border-box; border-left: 1px solid #f3f4f6; border-right: 1px solid #f3f4f6; border-bottom: 1px solid #f3f4f6; }
            .logo { height: 50px; margin-bottom: 1.5rem; object-fit: contain; }
            h1 { color: #1f2937; font-size: 1.5rem; margin-top: 0; font-weight: 800; }
            p { font-size: 0.95rem; line-height: 1.6; color: #4b5563; }
            .ip-box { margin: 1.5rem 0; padding: 1rem; background: #f9fafb; border-radius: 8px; border: 1px solid #e5e7eb; }
            .ip-label { font-size: 0.75rem; font-weight: 700; color: #9ca3af; text-transform: uppercase; letter-spacing: 0.05em; display: block; margin-bottom: 0.25rem; }
            .ip { font-family: monospace; color: #1f2937; font-weight: 700; font-size: 1.1rem; }
            .footer { margin-top: 2rem; font-size: 0.8rem; color: #9ca3af; border-top: 1px solid #f3f4f6; padding-top: 1rem; }
          </style>
        </head>
        <body>
          <div class="card">
            <img class="logo" src="${logoUrl}" alt="Logo" onerror="this.style.display='none'">
            <h1>Acceso Restringido</h1>
            <p>El ingreso a esta consola de administración de <strong>${portalName}</strong> está restringido y su dirección IP de conexión no se encuentra en la lista blanca de seguridad.</p>
            <div class="ip-box">
              <span class="ip-label">SU DIRECCIÓN IP DE CONEXIÓN</span>
              <span class="ip">${clientIp}</span>
            </div>
            <p>Si requiere acceso, solicite al administrador de red de la institución que agregue esta dirección IP en el panel de configuración.</p>
            <div class="footer">
              &copy; ${new Date().getFullYear()} ${portalName}
            </div>
          </div>
        </body>
        </html>
      `);
    }

    next();
  } catch (err) {
    next(err);
  }
});

// ─── Auth middleware ──────────────────────────────────────────────────────────

async function requireAdmin(req, res, next) {
  const auth = req.headers.authorization || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
  if (!token) {
    return res.status(401).json({ error: 'No autorizado. Se requiere token.' });
  }

  try {
    // 1. Verificar si es el token del administrador legacy (compatibilidad)
    if (token === ADMIN_SECRET) {
      req.adminUser = 'admin';
      req.adminRol = 'superadministrador';
      return next();
    }

    // 2. Verificar sesión multiusuario en base de datos
    const session = await db.getAdminBySessionToken(token);
    if (!session) {
      return res.status(401).json({ error: 'Sesión no válida o expirada.' });
    }

    req.adminUser = session.username;
    req.adminRol  = session.rol || 'operador';
    next();
  } catch (err) {
    next(err);
  }
}

/**
 * Middleware factory: exige que el admin tenga al menos el rol indicado.
 * Jerarquía: operador < administrador < superadministrador
 */
function requireRol(...roles) {
  const NIVEL = { operador: 1, administrador: 2, superadministrador: 3 };
  const minNivel = Math.min(...roles.map(r => NIVEL[r] || 1));
  return (req, res, next) => {
    const nivelActual = NIVEL[req.adminRol] || 1;
    if (nivelActual < minNivel) {
      return res.status(403).json({ error: 'No tienes permisos suficientes para esta acción.' });
    }
    next();
  };
}

// ─── Página HTML ──────────────────────────────────────────────────────────────

router.get('/', (req, res) => {
  res.sendFile(path.join(PUBLIC, 'admin.html'));
});

// ─── Estadísticas ─────────────────────────────────────────────────────────────

router.get('/api/stats', requireAdmin, async (req, res, next) => {
  try {
    res.json(await db.getStats());
  } catch (err) { next(err); }
});

// ─── Reportes ─────────────────────────────────────────────────────────────────

router.get('/api/reports', requireAdmin,
  query('type').isIn(['users', 'connections', 'access']),
  query('search').optional().isString().trim().escape(),
  query('startDate').optional().isISO8601().toDate(),
  query('endDate').optional().isISO8601().toDate(),
  query('limit').optional().isInt({ min: 1, max: 10000 }).toInt(),
  query('offset').optional().isInt({ min: 0 }).toInt(),
  async (req, res, next) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({ error: 'Parámetros de consulta inválidos.' });
      }

      const { type, search = '', startDate, endDate, limit = 50, offset = 0 } = req.query;

      let result;
      if (type === 'users') {
        result = await db.getUsersReport({ search, startDate, endDate, limit, offset });
      } else if (type === 'connections') {
        result = await db.getConnectionsReport({ search, startDate, endDate, limit, offset });
      } else if (type === 'access') {
        result = await db.getAccessLogReport({ search, startDate, endDate, limit, offset });
      }

      res.json(result);
    } catch (err) { next(err); }
  }
);

// ─── Dispositivos (CRUD) ───────────────────────────────────────────────────────

router.get('/api/devices', requireAdmin,
  query('search').optional().isString().trim(),
  query('limit').optional().isInt({ min: 1, max: 200 }).toInt(),
  query('offset').optional().isInt({ min: 0 }).toInt(),
  async (req, res, next) => {
    try {
      const matched = matchedData(req, { includeOptionals: true, locations: ['query'] });
      const search = matched.search || '';
      const limit  = matched.limit  ?? 50;
      const offset = matched.offset ?? 0;
      res.json(await db.listAllDevices({ search, limit, offset }));
    } catch (err) { next(err); }
  }
);

router.post('/api/devices', requireAdmin,
  body('cedula').isString().trim().isLength({ min: 10, max: 10 }).isNumeric(),
  body('mac_address').isString().trim().matches(/^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$/),
  async (req, res, next) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({ error: 'Dirección MAC inválida (formato esperado: XX-XX-XX-XX-XX-XX o XX:XX:XX:XX:XX:XX).' });
      }
      const { cedula, mac_address } = req.body;
      
      const userExists = await db.userExists(cedula);
      if (!userExists) {
        return res.status(404).json({ error: 'El usuario con la cédula indicada no existe.' });
      }

      const count = await db.getUserDevicesCount(cedula);
      const user = await db.getUserByCedula(cedula);
      if (count >= (user.max_dispositivos || 1)) {
        return res.status(400).json({ error: `El usuario ya ha alcanzado su límite de dispositivos (${user.max_dispositivos || 1}).` });
      }

      await db.registerUserDevice(cedula, mac_address);
      await db.logAdminAudit(req.adminUser, 'REGISTRAR_DISPOSITIVO', `Dispositivo ${mac_address} registrado para el usuario ${cedula}`);
      res.status(201).json({ success: true, message: 'Dispositivo registrado con éxito.' });
    } catch (err) { next(err); }
  }
);

router.put('/api/devices', requireAdmin,
  body('old_cedula').isString().trim().isLength({ min: 10, max: 10 }).isNumeric(),
  body('old_mac_address').isString().trim().matches(/^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$/),
  body('new_cedula').isString().trim().isLength({ min: 10, max: 10 }).isNumeric(),
  body('new_mac_address').isString().trim().matches(/^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$/),
  async (req, res, next) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({ error: 'Datos de dispositivo inválidos.' });
      }
      const { old_cedula, old_mac_address, new_cedula, new_mac_address } = req.body;

      const newExists = await db.userExists(new_cedula);
      if (!newExists) {
        return res.status(404).json({ error: 'El nuevo usuario no existe.' });
      }

      if (old_cedula !== new_cedula) {
        const count = await db.getUserDevicesCount(new_cedula);
        const user = await db.getUserByCedula(new_cedula);
        if (count >= (user.max_dispositivos || 1)) {
          return res.status(400).json({ error: `El nuevo usuario ya alcanzó su límite de dispositivos (${user.max_dispositivos || 1}).` });
        }
      }

      await db.updateUserDevice(old_cedula, old_mac_address, new_cedula, new_mac_address);
      await db.logAdminAudit(req.adminUser, 'MODIFICAR_DISPOSITIVO', `Dispositivo ${old_mac_address} de ${old_cedula} modificado a ${new_mac_address} de ${new_cedula}`);
      res.json({ success: true, message: 'Dispositivo actualizado con éxito.' });
    } catch (err) { next(err); }
  }
);

router.delete('/api/devices', requireAdmin,
  body('cedula').isString().trim().isLength({ min: 10, max: 10 }).isNumeric(),
  body('mac_address').isString().trim().matches(/^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$/),
  async (req, res, next) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({ error: 'Datos de dispositivo inválidos.' });
      }
      const { cedula, mac_address } = req.body;
      await db.deleteUserDevice(cedula, mac_address);
      await db.logAdminAudit(req.adminUser, 'ELIMINAR_DISPOSITIVO', `Dispositivo ${mac_address} eliminado del usuario ${cedula}`);
      res.json({ success: true, message: 'Dispositivo eliminado con éxito.' });
    } catch (err) { next(err); }
  }
);

// ─── Usuarios ─────────────────────────────────────────────────────────────────

router.get('/api/users', requireAdmin,
  query('search').optional().isString().trim(),
  query('limit').optional().isInt({ min: 1, max: 200 }).toInt(),
  query('offset').optional().isInt({ min: 0 }).toInt(),
  async (req, res, next) => {
    try {
      const matched = matchedData(req, { includeOptionals: true, locations: ['query'] });
      const search = matched.search || '';
      const limit  = matched.limit  ?? 50;
      const offset = matched.offset ?? 0;
      res.json(await db.listUsers({ search, limit, offset }));
    } catch (err) { next(err); }
  }
);

router.get('/api/users/:cedula', requireAdmin,
  param('cedula').isNumeric().isLength({ min: 10, max: 10 }),
  async (req, res, next) => {
    try {
      const user = await db.getUserDetail(req.params.cedula);
      if (!user) return res.status(404).json({ error: 'Usuario no encontrado.' });
      res.json(user);
    } catch (err) { next(err); }
  }
);

router.patch('/api/users/:cedula/type', requireAdmin,
  param('cedula').isNumeric().isLength({ min: 10, max: 10 }),
  body('tipo_usuario').isIn(['institucional', 'externo']),
  async (req, res, next) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) return res.status(400).json({ error: 'Parámetros inválidos.' });

      const cedula = req.params.cedula;
      const tipo_usuario = req.body.tipo_usuario;

      await db.updateUserType(cedula, tipo_usuario);

      // Auditoría
      const clientIp = getClientIp(req);
      await db.logAdminAudit({
        username: req.adminUser,
        ipAddress: clientIp,
        accion: 'CAMBIAR_TIPO_USUARIO',
        detalles: `Modificó tipo de usuario cédula: ${cedula} a ${tipo_usuario}`
      });

      res.json({ success: true });
    } catch (err) { next(err); }
  }
);

router.post('/api/users/bulk-type', requireAdmin,
  body('cedulas').isArray({ min: 1 }),
  body('tipo_usuario').isIn(['institucional', 'externo']),
  async (req, res, next) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) return res.status(400).json({ error: 'Parámetros inválidos.' });

      const { cedulas, tipo_usuario } = req.body;

      await db.bulkUpdateUserType(cedulas, tipo_usuario);

      // Auditoría
      const clientIp = getClientIp(req);
      await db.logAdminAudit({
        username: req.adminUser,
        ipAddress: clientIp,
        accion: 'CAMBIAR_TIPO_USUARIO_LOTE',
        detalles: `Modificó tipo de usuario en lote a ${tipo_usuario} para ${cedulas.length} usuarios`
      });

      res.json({ success: true });
    } catch (err) { next(err); }
  }
);

router.post('/api/users/bulk-active', requireAdmin,
  body('cedulas').isArray({ min: 1 }),
  body('active').isBoolean(),
  async (req, res, next) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) return res.status(400).json({ error: 'Parámetros inválidos.' });

      const { cedulas, active } = req.body;

      await db.bulkUpdateUserActive(cedulas, active);

      // Auditoría
      const clientIp = getClientIp(req);
      await db.logAdminAudit({
        username: req.adminUser,
        ipAddress: clientIp,
        accion: active ? 'ACTIVAR_USUARIO_LOTE' : 'DESACTIVAR_USUARIO_LOTE',
        detalles: `Modificó estado activo a ${active} en lote para ${cedulas.length} usuarios`
      });

      // Aplicar acciones en controladores de red en segundo plano (bloquear/desbloquear MACs)
      for (const ced of cedulas) {
        db.getUserDevices(ced).then(devices => {
          for (const d of devices) {
            const mac = d.mac_address;
            if (active) {
              if (process.env.OMADA_CONTROLLER_URL) {
                omadaSvc.unblockClient({ clientMac: mac }).catch(err => {
                  console.error(`[OMADA] Error al desbloquear MAC ${mac} en activación en lote:`, err.message);
                });
              }
            } else {
              if (process.env.OMADA_CONTROLLER_URL) {
                omadaSvc.blockClient({ clientMac: mac }).catch(err => {
                  console.error(`[OMADA] Error al bloquear MAC ${mac} en desactivación en lote:`, err.message);
                });
              }
            }
          }
        }).catch(err => {
          console.error(`[DB] Error al buscar dispositivos del usuario ${ced} para bloqueo/desbloqueo en lote:`, err.message);
        });
      }

      res.json({ success: true });
    } catch (err) { next(err); }
  }
);

router.patch('/api/users/:cedula/active', requireAdmin,
  param('cedula').isNumeric().isLength({ min: 10, max: 10 }),
  body('active').isBoolean(),
  async (req, res, next) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) return res.status(400).json({ error: errors.array()[0].msg });
      
      const cedula = req.params.cedula;
      const active = req.body.active;

      // 1. Cambiar estado en base de datos (y radcheck)
      await db.setUserActive(cedula, active);

      // Auditoría
      const clientIp = getClientIp(req);
      await db.logAdminAudit({
        username: req.adminUser,
        ipAddress: clientIp,
        accion: active ? 'ACTIVAR_USUARIO' : 'DESACTIVAR_USUARIO',
        detalles: `Modificó estado de usuario cédula: ${cedula}`
      });

      // 2. Aplicar acciones en controladores de red en segundo plano (bloquear/desbloquear)
      db.getUserDevices(cedula).then(devices => {
        for (const d of devices) {
          const mac = d.mac_address;
          
          if (active) {
            // Reactivación -> Desbloquear en Omada
            if (process.env.OMADA_CONTROLLER_URL) {
              omadaSvc.unblockClient({ clientMac: mac }).catch(err => {
                console.error(`[OMADA] Error al desbloquear MAC ${mac} en activación:`, err.message);
              });
            }
          } else {
            // Desactivación -> Bloquear en Omada
            if (process.env.OMADA_CONTROLLER_URL) {
              omadaSvc.blockClient({ clientMac: mac }).catch(err => {
                console.error(`[OMADA] Error al bloquear MAC ${mac} en desactivación:`, err.message);
              });
            }

            if (process.env.UNIFI_CONTROLLER_URL) {
              unifiSvc.unauthorizeGuest(mac).catch(err => {
                console.error(`[UNIFI] Error al desautorizar MAC ${mac} en desactivación:`, err.message);
              });
            }
          }
        }
      }).catch(err => {
        console.error('[DB] Error al obtener dispositivos en cambio de estado:', err.message);
      });

      res.json({ ok: true });
    } catch (err) { next(err); }
  }
);

router.put('/api/users/:cedula/groups', requireAdmin,
  param('cedula').isNumeric().isLength({ min: 10, max: 10 }),
  body('groups').isArray(),
  async (req, res, next) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) return res.status(400).json({ error: errors.array()[0].msg });
      await db.setUserGroups(req.params.cedula, req.body.groups);

      // Auditoría
      const clientIp = getClientIp(req);
      await db.logAdminAudit({
        username: req.adminUser,
        ipAddress: clientIp,
        accion: 'MODIFICAR_GRUPOS_USUARIO',
        detalles: `Usuario cédula: ${req.params.cedula}, grupos asignados: ${req.body.groups.join(', ')}`
      });

      res.json({ ok: true });
    } catch (err) { next(err); }
  }
);

router.delete('/api/users/:cedula', requireAdmin, requireRol('administrador', 'superadministrador'),
  param('cedula').isNumeric().isLength({ min: 10, max: 10 }),
  async (req, res, next) => {
    try {
      const cedula = req.params.cedula;
      // 1. Obtener dispositivos registrados del usuario antes de borrarlo
      const devices = await db.getUserDevices(cedula);

      // 2. Borrar de la base de datos y de FreeRADIUS
      await db.deleteUser(cedula);

      // Auditoría
      const clientIp = getClientIp(req);
      await db.logAdminAudit({
        username: req.adminUser,
        ipAddress: clientIp,
        accion: 'ELIMINAR_USUARIO',
        detalles: `Eliminó usuario cédula: ${cedula}`
      });

      // 3. Desautorizar cada uno de sus dispositivos en segundo plano
      for (const d of devices) {
        const mac = d.mac_address;
        
        // Omada
        if (process.env.OMADA_CONTROLLER_URL) {
          omadaSvc.unauthorizeClient({ clientMac: mac }).catch(err => {
            console.error(`[OMADA] Error al desautorizar MAC ${mac}:`, err.message);
          });
        }

        // UniFi
        if (process.env.UNIFI_CONTROLLER_URL) {
          unifiSvc.unauthorizeGuest(mac).catch(err => {
            console.error(`[UNIFI] Error al desautorizar MAC ${mac}:`, err.message);
          });
        }
      }

      res.json({ ok: true });
    } catch (err) { next(err); }
  }
);

router.patch('/api/users/:cedula/max-devices', requireAdmin,
  param('cedula').isNumeric().isLength({ min: 10, max: 10 }),
  body('maxDevices').isInt({ min: 0 }).toInt(),
  async (req, res, next) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) return res.status(400).json({ error: errors.array()[0].msg });
      await db.setUserMaxDevices(req.params.cedula, req.body.maxDevices);

      // Auditoría
      const clientIp = getClientIp(req);
      await db.logAdminAudit({
        username: req.adminUser,
        ipAddress: clientIp,
        accion: 'MODIFICAR_MAX_DISPOSITIVOS',
        detalles: `Usuario cédula: ${req.params.cedula}, límite: ${req.body.maxDevices}`
      });

      res.json({ ok: true });
    } catch (err) { next(err); }
  }
);

router.delete('/api/users/:cedula/devices/:mac', requireAdmin,
  param('cedula').isNumeric().isLength({ min: 10, max: 10 }),
  param('mac').isString().trim(),
  async (req, res, next) => {
    try {
      const { cedula, mac } = req.params;

      // 1. Eliminar de la base de datos local
      await db.deleteUserDevice(cedula, mac);

      // Auditoría
      const clientIp = getClientIp(req);
      await db.logAdminAudit({
        username: req.adminUser,
        ipAddress: clientIp,
        accion: 'ELIMINAR_DISPOSITIVO',
        detalles: `Eliminó dispositivo MAC ${mac} del usuario cédula: ${cedula}`
      });

      // 2. Intentar desautorizar en Omada si está activo
      if (process.env.OMADA_CONTROLLER_URL) {
        try {
          console.log(`[ADMIN-DEVICE] Intentando desautorizar MAC ${mac} en Omada`);
          await omadaSvc.unauthorizeClient({ clientMac: mac });
        } catch (omadaErr) {
          console.error(`[ADMIN-DEVICE] Error desautorizando MAC ${mac} en Omada:`, omadaErr.message);
        }
      }

      // 3. Intentar desautorizar en UniFi si está activo
      if (process.env.UNIFI_CONTROLLER_URL) {
        try {
          console.log(`[ADMIN-DEVICE] Intentando desautorizar MAC ${mac} en UniFi`);
          await unifiSvc.unauthorizeGuest(mac);
        } catch (unifiErr) {
          console.error(`[ADMIN-DEVICE] Error desautorizando MAC ${mac} en UniFi:`, unifiErr.message);
        }
      }

      res.json({ ok: true });
    } catch (err) { next(err); }
  }
);

// ─── Grupos RADIUS ────────────────────────────────────────────────────────────

router.get('/api/groups', requireAdmin, async (req, res, next) => {
  try {
    res.json(await db.listGroups());
  } catch (err) { next(err); }
});

router.post('/api/groups/attributes', requireAdmin,
  body('groupname').isString().trim().isLength({ min: 1, max: 64 }),
  body('attribute').isString().trim().isLength({ min: 1, max: 64 }),
  body('op').isString().trim().isIn([':=', '=', '+=', '==', '!=', '>=', '<=']),
  body('value').isString().trim().isLength({ min: 1, max: 253 }),
  async (req, res, next) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) return res.status(400).json({ error: errors.array()[0].msg });
      const attr = await db.addGroupAttribute(req.body);

      // Auditoría
      const clientIp = getClientIp(req);
      await db.logAdminAudit({
        username: req.adminUser,
        ipAddress: clientIp,
        accion: 'AGREGAR_ATRIBUTO_GRUPO',
        detalles: `Agregó atributo al grupo ${req.body.groupname}: ${req.body.attribute} ${req.body.op} ${req.body.value}`
      });

      res.status(201).json(attr);
    } catch (err) { next(err); }
  }
);

router.delete('/api/groups/attributes/:id', requireAdmin,
  param('id').isInt({ min: 1 }),
  async (req, res, next) => {
    try {
      await db.deleteGroupAttribute(parseInt(req.params.id));

      // Auditoría
      const clientIp = getClientIp(req);
      await db.logAdminAudit({
        username: req.adminUser,
        ipAddress: clientIp,
        accion: 'ELIMINAR_ATRIBUTO_GRUPO',
        detalles: `Eliminó atributo de grupo con ID: ${req.params.id}`
      });

      res.json({ ok: true });
    } catch (err) { next(err); }
  }
);

router.delete('/api/groups/:groupname', requireAdmin,
  param('groupname').isString().trim().isLength({ min: 1, max: 64 }),
  async (req, res, next) => {
    try {
      if (req.params.groupname === 'captive-portal-users') {
        return res.status(400).json({ error: 'No se puede eliminar el grupo base del sistema.' });
      }
      await db.deleteGroup(req.params.groupname);

      // Auditoría
      const clientIp = getClientIp(req);
      await db.logAdminAudit({
        username: req.adminUser,
        ipAddress: clientIp,
        accion: 'ELIMINAR_GRUPO',
        detalles: `Eliminó grupo RADIUS: ${req.params.groupname}`
      });

      res.json({ ok: true });
    } catch (err) { next(err); }
  }
);

// ─── Controladores de red ─────────────────────────────────────────────────────

/**
 * Construye la respuesta de config para un vendor, uniendo DB + env vars.
 * Los secretos se enmascaran.
 */
function buildControllerResponse(vendor, dbCfg) {
  const cfg = dbCfg || {};
  const fromEnv = !dbCfg; // sin registro en DB → mostrando valores del .env

  if (vendor === 'freeradius') {
    const secret = cfg.secret || process.env.RADIUS_SECRET || '';
    return {
      host:       cfg.host    || process.env.RADIUS_HOST    || 'freeradius',
      port:       cfg.port    || process.env.RADIUS_PORT    || '1812',
      secret:     controllerTest.masked(secret),
      timeout:    cfg.timeout || process.env.RADIUS_TIMEOUT || '5000',
      activo:     cfg.activo !== undefined ? (cfg.activo === true || cfg.activo === 'true') : true,
      configured: !!secret,
      fromEnv,
    };
  }
  if (vendor === 'unifi') {
    const pass = cfg.pass || process.env.UNIFI_PASS || '';
    return {
      url:        cfg.url       || process.env.UNIFI_CONTROLLER_URL || '',
      user:       cfg.user      || process.env.UNIFI_USER           || '',
      pass:       controllerTest.masked(pass),
      site:       cfg.site      || process.env.UNIFI_SITE           || 'default',
      verifySSL:  cfg.verifySSL !== undefined ? cfg.verifySSL : (process.env.UNIFI_VERIFY_SSL || 'false'),
      activo:     cfg.activo !== undefined ? (cfg.activo === true || cfg.activo === 'true') : true,
      configured: !!(cfg.url || process.env.UNIFI_CONTROLLER_URL) &&
                  !!(cfg.user || process.env.UNIFI_USER) &&
                  !!pass,
      fromEnv,
    };
  }
  if (vendor === 'omada') {
    const secret = cfg.secret || process.env.OMADA_CLIENT_SECRET || '';
    return {
      url:        cfg.url      || process.env.OMADA_CONTROLLER_URL || '',
      clientId:   cfg.clientId || process.env.OMADA_CLIENT_ID      || '',
      secret:     controllerTest.masked(secret),
      siteId:     cfg.siteId   || process.env.OMADA_SITE_ID        || '',
      activo:     cfg.activo !== undefined ? (cfg.activo === true || cfg.activo === 'true') : true,
      configured: !!(cfg.url || process.env.OMADA_CONTROLLER_URL) &&
                  !!(cfg.clientId || process.env.OMADA_CLIENT_ID) &&
                  !!secret,
      fromEnv,
    };
  }
  return {};
}

/**
 * Construye el objeto de config real (con secretos) para pasar a las funciones de test.
 * Fusiona DB con fallback a env vars.
 */
function buildControllerConfig(vendor, dbCfg) {
  const cfg = dbCfg || {};

  if (vendor === 'freeradius') {
    return {
      host:    cfg.host    || process.env.RADIUS_HOST    || 'freeradius',
      port:    cfg.port    || process.env.RADIUS_PORT    || '1812',
      secret:  cfg.secret  || process.env.RADIUS_SECRET  || '',
      timeout: cfg.timeout || process.env.RADIUS_TIMEOUT || '4000',
    };
  }
  if (vendor === 'unifi') {
    return {
      url:       cfg.url       || process.env.UNIFI_CONTROLLER_URL || '',
      user:      cfg.user      || process.env.UNIFI_USER           || '',
      pass:      cfg.pass      || process.env.UNIFI_PASS           || '',
      site:      cfg.site      || process.env.UNIFI_SITE           || 'default',
      verifySSL: cfg.verifySSL !== undefined ? cfg.verifySSL : (process.env.UNIFI_VERIFY_SSL || 'false'),
    };
  }
  if (vendor === 'omada') {
    return {
      url:      cfg.url      || process.env.OMADA_CONTROLLER_URL  || '',
      clientId: cfg.clientId || process.env.OMADA_CLIENT_ID       || '',
      secret:   cfg.secret   || process.env.OMADA_CLIENT_SECRET   || '',
      siteId:   cfg.siteId   || process.env.OMADA_SITE_ID         || '',
    };
  }
  return {};
}

// GET — configuración actual (secretos enmascarados)
router.get('/api/controllers', requireAdmin, async (req, res, next) => {
  try {
    const vendors = ['freeradius', 'unifi', 'omada'];
    const result  = {};
    for (const vendor of vendors) {
      const dbCfg = await db.getControllerConfig(vendor);
      result[vendor] = buildControllerResponse(vendor, dbCfg);
    }
    res.json(result);
  } catch (err) { next(err); }
});

// PUT — guarda configuración en DB
router.put('/api/controllers/:vendor', requireAdmin,
  param('vendor').isIn(['freeradius', 'unifi', 'omada']),
  async (req, res, next) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) return res.status(400).json({ error: 'Vendor inválido.' });

      const vendor   = req.params.vendor;
      const existing = await db.getControllerConfig(vendor) || {};
      const input    = req.body;

      // Construir nueva config: si el campo secret/pass llega vacío o enmascarado, conservar el existente
      const isMasked = val => typeof val === 'string' && val.includes('***');
      const getVal = (newVal, oldVal) => {
        if (newVal === undefined) return oldVal || '';
        const trimmed = String(newVal).trim();
        if (!trimmed || isMasked(trimmed)) return oldVal || '';
        return trimmed;
      };

      const activoVal = input.activo !== undefined 
        ? (input.activo === true || input.activo === 'true' || input.activo === '1') 
        : (existing.activo !== undefined ? (existing.activo === true || existing.activo === 'true') : true);

      let newCfg;
      if (vendor === 'freeradius') {
        newCfg = {
          host:    getVal(input.host, existing.host),
          port:    getVal(input.port, existing.port),
          secret:  getVal(input.secret, existing.secret),
          timeout: getVal(input.timeout, existing.timeout),
          activo:  activoVal,
        };
      } else if (vendor === 'unifi') {
        newCfg = {
          url:       getVal(input.url, existing.url),
          user:      getVal(input.user, existing.user),
          pass:      getVal(input.pass, existing.pass),
          site:      getVal(input.site, existing.site),
          verifySSL: input.verifySSL !== undefined ? input.verifySSL : (existing.verifySSL || 'false'),
          activo:  activoVal,
        };
      } else if (vendor === 'omada') {
        newCfg = {
          url:      getVal(input.url, existing.url),
          clientId: getVal(input.clientId, existing.clientId),
          secret:   getVal(input.secret, existing.secret),
          siteId:   getVal(input.siteId, existing.siteId),
          activo:  activoVal,
        };
      }

      await db.saveControllerConfig(vendor, newCfg);

      // Auditoría
      const clientIp = getClientIp(req);
      await db.logAdminAudit({
        username: req.adminUser,
        ipAddress: clientIp,
        accion: 'MODIFICAR_CONTROLADOR',
        detalles: `Modificó configuración del controlador: ${vendor}`
      });

      res.json({ ok: true });
    } catch (err) { next(err); }
  }
);

// POST — prueba conectividad usando la config guardada
router.post('/api/controllers/:vendor/test', requireAdmin,
  param('vendor').isIn(['freeradius', 'unifi', 'omada']),
  async (req, res, next) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) return res.status(400).json({ error: 'Vendor inválido.' });

      const vendor = req.params.vendor;
      const dbCfg  = await db.getControllerConfig(vendor);
      const cfg    = buildControllerConfig(vendor, dbCfg);

      let result;
      switch (vendor) {
        case 'freeradius': result = await controllerTest.testFreeRadius(cfg); break;
        case 'unifi':      result = await controllerTest.testUnifi(cfg);      break;
        case 'omada':      result = await controllerTest.testOmada(cfg);      break;
      }
      res.json({ ...result, testedAt: new Date().toISOString() });
    } catch (err) { next(err); }
  }
);

// GET — configuración de branding
router.get('/api/branding', requireAdmin, async (req, res, next) => {
  try {
    const config = await db.getControllerConfig('branding') || {};
    res.json({
      portalName:      config.portalName || process.env.PORTAL_NAME || 'Portal Wi-Fi',
      logoUrl:         config.logoUrl || process.env.PORTAL_LOGO_URL || '/static/logo.svg',
      primaryColor:    config.primaryColor || '#4f46e5',
      accentColor:     config.accentColor || '#6366f1',
      welcomeText:     config.welcomeText || 'Bienvenido a la red Wi-Fi municipal. Por favor regístrese para continuar.',
      termsText:       config.termsText || '',
      inactiveMessage: config.inactiveMessage || 'Su usuario ha sido desactivado. Por favor, contacte al administrador.',
      ipWhitelist:     config.ipWhitelist || '0.0.0.0',
    });
  } catch (err) { next(err); }
});

// PUT — guarda configuración de branding
router.put('/api/branding', requireAdmin, async (req, res, next) => {
  try {
    const input = req.body;

    let ipWhitelist = (input.ipWhitelist || '').trim() || '0.0.0.0';

    // Validar formato de IP o CIDR (ej: 192.168.1.5 o 192.168.1.0/24)
    const whitelistEntries = ipWhitelist.split(',').map(s => s.trim()).filter(Boolean);
    const ipCidrRegex = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?:\/(?:[0-9]|[1-2][0-9]|3[0-2]))?$/;
    for (const entry of whitelistEntries) {
      if (!ipCidrRegex.test(entry)) {
        return res.status(400).json({ error: `La entrada "${entry}" de la lista blanca de IPs no tiene un formato válido. Use direcciones IP (ej: 192.168.1.5) o rangos con máscara de subred (ej: 192.168.1.0/24).` });
      }
    }

    // Comprobar bloqueo para la IP del administrador actual
    const clientIp = getClientIp(req);
    if (clientIp !== '127.0.0.1' && clientIp !== '::1' && clientIp !== '') {
      const allowed = whitelistEntries.some(cidr => ipMatchesCidr(clientIp, cidr));
      if (!allowed) {
        return res.status(400).json({ error: `No se puede aplicar esta lista blanca de IPs porque bloquearía su conexión actual desde la dirección IP ${clientIp}. Por favor, incluya su dirección IP o subred en la lista.` });
      }
    }

    const config = await db.getControllerConfig('branding') || {};
    const oldTermsText = config.termsText || '';
    const newTermsText = (input.termsText || '').trim();

    let termsUpdatedAt = config.termsUpdatedAt || null;
    if (newTermsText !== oldTermsText) {
      termsUpdatedAt = new Date().toISOString();
    }

    let logoUrl = (input.logoUrl || '').trim() || '/static/logo.svg';

    // Si viene una carga de imagen en Base64, decodificarla y guardarla en el servidor
    if (input.logoBase64 && input.logoBase64.startsWith('data:image/')) {
      const fs = require('fs');
      const path = require('path');

      const matches = input.logoBase64.match(/^data:image\/([a-zA-Z0-9+.-]+);base64,(.+)$/);
      if (matches && matches.length === 3) {
        let ext = matches[1];
        if (ext === 'svg+xml') ext = 'svg';
        const base64Data = matches[2];
        const buffer = Buffer.from(base64Data, 'base64');

        const publicDir = path.join(__dirname, '../../public');
        const filename = `logo_upload.${ext}`;
        const filepath = path.join(publicDir, filename);

        fs.writeFileSync(filepath, buffer);
        logoUrl = `/static/${filename}`;
      }
    }

    const newCfg = {
      portalName:      (input.portalName || '').trim() || 'Portal Wi-Fi',
      logoUrl:         logoUrl,
      primaryColor:    (input.primaryColor || '').trim() || '#4f46e5',
      accentColor:     (input.accentColor || '').trim() || '#6366f1',
      welcomeText:     (input.welcomeText || '').trim() || 'Bienvenido a la red Wi-Fi municipal. Por favor regístrese para continuar.',
      termsText:       newTermsText,
      termsUpdatedAt:  termsUpdatedAt,
      inactiveMessage: (input.inactiveMessage || '').trim() || 'Su usuario ha sido desactivado. Por favor, contacte al administrador.',
      ipWhitelist:     ipWhitelist,
    };
    await db.saveControllerConfig('branding', newCfg);

    // Auditoría
    await db.logAdminAudit({
      username: req.adminUser,
      ipAddress: clientIp,
      accion: 'MODIFICAR_PERSONALIZACION',
      detalles: `Modificó branding del portal (nombre: ${newCfg.portalName}, whitelist IP: ${newCfg.ipWhitelist})`
    });

    res.json({ ok: true });
  } catch (err) { next(err); }
});

function sanitizePem(pemText) {
  if (!pemText) return '';
  return pemText
    .split(/\r?\n/)
    .map(line => line.trim())
    .join('\n')
    .trim() + '\n';
}

router.post('/api/ssl', requireAdmin, async (req, res, next) => {
  try {
    const { cert, key } = req.body;
    console.log('[SSL] Intento de carga de certificados. Tamaño cert:', cert ? cert.length : 0, 'Tamaño key:', key ? key.length : 0);

    if (!cert || !key) {
      return res.status(400).json({ error: 'Se requieren el archivo de certificado y el de llave privada.' });
    }

    // Validar formato del certificado
    if (!cert.includes('-----BEGIN CERTIFICATE-----')) {
      console.warn('[SSL] Carga rechazada: El certificado no contiene "-----BEGIN CERTIFICATE-----"');
      return res.status(400).json({ error: 'El archivo de certificado no es un certificado PEM válido (falta "-----BEGIN CERTIFICATE-----"). Asegúrese de no haber subido la llave en este campo.' });
    }

    // Validar formato de la llave privada
    if (!key.includes('-----BEGIN') || !key.includes('KEY')) {
      console.warn('[SSL] Carga rechazada: La llave privada no contiene "-----BEGIN" ni "KEY"');
      return res.status(400).json({ error: 'El archivo de llave privada no es una llave PEM válida (debe contener "-----BEGIN ... KEY-----"). Asegúrese de no haber subido el certificado en este campo.' });
    }

    const sslDir = process.env.SSL_DIR || '/app/ssl';
    if (!fs.existsSync(sslDir)) {
      fs.mkdirSync(sslDir, { recursive: true });
    }

    const cleanCert = sanitizePem(cert);
    const cleanKey = sanitizePem(key);

    fs.writeFileSync(path.join(sslDir, 'portal.crt'), cleanCert, 'utf8');
    fs.writeFileSync(path.join(sslDir, 'portal.key'), cleanKey, 'utf8');
    fs.writeFileSync(path.join(sslDir, '.reload'), new Date().toISOString(), 'utf8');

    console.log('[SSL] Nuevos certificados cargados con éxito. Solicitando recarga de Nginx...');
    res.json({ ok: true });
  } catch (err) {
    next(err);
  }
});

// ─── Base de Datos Externa (PostgreSQL) ───────────────────────────────────────

const { Client } = require('pg');

// GET — obtener configuración de base de datos externa
router.get('/api/external-db/config', requireAdmin, async (req, res, next) => {
  try {
    const config = await db.getControllerConfig('external_db_config') || {};
    res.json({
      enabled:      config.enabled || false,
      host:         config.host || '',
      port:         config.port || 5432,
      database:     config.database || '',
      user:         config.user || '',
      password:     config.password || '',
      ssl:          config.ssl || false,
      tableName:    config.tableName || '',
      colCedula:    config.colCedula || '',
      colNombres:   config.colNombres || '',
      colApellidos: config.colApellidos || '',
      colEmail:     config.colEmail || '',
    });
  } catch (err) { next(err); }
});

// PUT — guardar configuración de base de datos externa
router.put('/api/external-db/config', requireAdmin, async (req, res, next) => {
  try {
    const input = req.body;
    const newCfg = {
      enabled:      !!input.enabled,
      host:         (input.host || '').trim(),
      port:         parseInt(input.port) || 5432,
      database:     (input.database || '').trim(),
      user:         (input.user || '').trim(),
      password:     input.password || '',
      ssl:          !!input.ssl,
      tableName:    (input.tableName || '').trim(),
      colCedula:    (input.colCedula || '').trim(),
      colNombres:   (input.colNombres || '').trim(),
      colApellidos: (input.colApellidos || '').trim(),
      colEmail:     (input.colEmail || '').trim(),
      colStatus:    (input.colStatus || '').trim(),
      allowManualRegistration: input.allowManualRegistration !== false && input.allowManualRegistration !== 'false',
    };
    await db.saveControllerConfig('external_db_config', newCfg);
    res.json({ ok: true });
  } catch (err) { next(err); }
});

// POST — probar conexión y obtener tablas/columnas
router.post('/api/external-db/test', requireAdmin, async (req, res, next) => {
  const { host, port, database, user, password, ssl } = req.body;

  const client = new Client({
    host,
    port: parseInt(port) || 5432,
    database,
    user,
    password,
    ssl: ssl ? { rejectUnauthorized: false } : false,
    connectionTimeoutMillis: 5000,
  });

  try {
    await client.connect();

    // 1. Obtener lista de tablas públicas
    const tablesQuery = `
      SELECT table_name 
      FROM information_schema.tables 
      WHERE table_schema = 'public' AND table_type = 'BASE TABLE'
      ORDER BY table_name;
    `;
    const tablesRes = await client.query(tablesQuery);
    const tables = tablesRes.rows.map(r => r.table_name);

    // 2. Obtener lista de columnas de todas las tablas públicas
    const columnsQuery = `
      SELECT table_name, column_name 
      FROM information_schema.columns 
      WHERE table_schema = 'public'
      ORDER BY table_name, column_name;
    `;
    const columnsRes = await client.query(columnsQuery);
    
    // Organizar columnas por tabla
    const schema = {};
    tables.forEach(t => schema[t] = []);
    columnsRes.rows.forEach(row => {
      if (schema[row.table_name]) {
        schema[row.table_name].push(row.column_name);
      }
    });

    await client.end();
    res.json({ success: true, schema });
  } catch (err) {
    res.json({ success: false, error: err.message });
  }
});

// ─── Autenticación (Login/Logout) ───

router.post('/api/login',
  body('username').isString().trim().notEmpty(),
  body('password').isString().notEmpty(),
  async (req, res, next) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({ error: 'Usuario y contraseña requeridos.' });
      }
      
      const { username, password } = req.body;
      const clientIp = getClientIp(req);
      
      const admin = await db.verifyAdminLogin(username, password);
      if (!admin) {
        // Auditoría de intento fallido
        await db.logAdminAudit({
          username: username.substring(0, 50),
          ipAddress: clientIp,
          accion: 'LOGIN_FALLIDO',
          detalles: 'Intento de inicio de sesión fallido.'
        });
        return res.status(401).json({ error: 'Credenciales inválidas o cuenta inactiva.' });
      }
      
      const { token, expiresAt } = await db.createAdminSession(admin.username);
      
      await db.logAdminAudit({
        username: admin.username,
        ipAddress: clientIp,
        accion: 'LOGIN',
        detalles: 'Inicio de sesión exitoso.'
      });
      
      res.json({
        success: true,
        token,
        expiresAt,
        adminUser: {
          username: admin.username,
          nombres: admin.nombres,
          rol: admin.rol || 'operador'
        }
      });
    } catch (err) {
      next(err);
    }
  }
);

router.post('/api/logout', requireAdmin, async (req, res, next) => {
  try {
    const auth = req.headers.authorization || '';
    const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
    if (token && token !== ADMIN_SECRET) {
      await db.deleteAdminSession(token);
    }
    
    const clientIp = getClientIp(req);
    await db.logAdminAudit({
      username: req.adminUser,
      ipAddress: clientIp,
      accion: 'LOGOUT',
      detalles: 'Cierre de sesión.'
    });
    
    res.json({ success: true });
  } catch (err) {
    next(err);
  }
});

// ─── Administradores (Múltiples Usuarios) ───

router.get('/api/admins', requireAdmin, requireRol('administrador', 'superadministrador'), async (req, res, next) => {
  try {
    const admins = await db.listAdmins();
    res.json(admins);
  } catch (err) {
    next(err);
  }
});

router.post('/api/users', requireAdmin,
  body('cedula').isString().trim().isLength({ min: 10, max: 10 }).isNumeric(),
  body('nombres').isString().trim().isLength({ min: 2, max: 100 }),
  body('apellidos').isString().trim().isLength({ min: 2, max: 100 }),
  body('email').isEmail().normalizeEmail(),
  body('activo').optional().isBoolean(),
  async (req, res, next) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({ error: errors.array().map(e => e.msg).join(', ') });
      }

      const { cedula, nombres, apellidos, email, activo = true } = req.body;

      const exists = await db.userExists(cedula);
      if (exists) {
        return res.status(400).json({ error: 'La cédula ya se encuentra registrada.' });
      }

      await db.createUser({
        cedula,
        nombres,
        apellidos,
        email,
        activo,
        acepta_terminos: true,
        fecha_acepta_terminos: new Date()
      });

      res.status(201).json({ success: true, message: 'Usuario creado exitosamente.' });
    } catch (err) {
      next(err);
    }
  }
);

router.post('/api/admins', requireAdmin, requireRol('superadministrador'),
  body('username').isString().trim().isLength({ min: 3, max: 50 }).matches(/^[a-zA-Z0-9_.-]+$/),
  body('password').isString().isLength({ min: 6 }),
  body('nombres').isString().trim().isLength({ min: 2, max: 100 }),
  async (req, res, next) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({ error: 'Datos de administrador inválidos (el nombre de usuario debe ser alfanumérico, y la contraseña debe tener al menos 6 caracteres).' });
      }
      
      const { username, password, nombres, rol } = req.body;
      const clientIp = getClientIp(req);
      
      const newAdmin = await db.createAdmin({ username, password, nombres, rol });
      
      await db.logAdminAudit({
        username: req.adminUser,
        ipAddress: clientIp,
        accion: 'CREAR_ADMINISTRADOR',
        detalles: `Creó el administrador: ${newAdmin.username} (${newAdmin.nombres}) con rol: ${newAdmin.rol}`
      });
      
      res.status(201).json(newAdmin);
    } catch (err) {
      if (err.code === '23505') {
        return res.status(409).json({ error: 'El nombre de usuario ya está registrado.' });
      }
      next(err);
    }
  }
);

router.put('/api/admins/:username/status', requireAdmin, requireRol('administrador', 'superadministrador'),
  param('username').isString().trim().notEmpty(),
  body('active').isBoolean(),
  async (req, res, next) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({ error: 'Parámetros inválidos.' });
      }
      
      const username = req.params.username;
      const active = req.body.active;
      const clientIp = getClientIp(req);
      
      await db.updateAdminStatus(username, active);
      
      await db.logAdminAudit({
        username: req.adminUser,
        ipAddress: clientIp,
        accion: active ? 'ACTIVAR_ADMINISTRADOR' : 'DESACTIVAR_ADMINISTRADOR',
        detalles: `Modificó administrador: ${username} (activo = ${active})`
      });
      
      res.json({ ok: true });
    } catch (err) {
      res.status(400).json({ error: err.message });
    }
  }
);

router.put('/api/admins/:username/password', requireAdmin,
  param('username').isString().trim().notEmpty(),
  body('password').isString().isLength({ min: 6 }),
  async (req, res, next) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({ error: 'La nueva contraseña debe tener al menos 6 caracteres.' });
      }
      
      const username = req.params.username;
      const newPassword = req.body.password;
      const clientIp = getClientIp(req);
      
      await db.updateAdminPassword(username, newPassword);
      
      await db.logAdminAudit({
        username: req.adminUser,
        ipAddress: clientIp,
        accion: 'CAMBIAR_CONTRASENA_ADMINISTRADOR',
        detalles: `Cambió contraseña del administrador: ${username}`
      });
      
      res.json({ ok: true });
    } catch (err) {
      res.status(400).json({ error: err.message });
    }
  }
);

router.delete('/api/admins/:username', requireAdmin, requireRol('superadministrador'),
  param('username').isString().trim().notEmpty(),
  async (req, res, next) => {
    try {
      const username = req.params.username;
      const clientIp = getClientIp(req);
      
      await db.deleteAdmin(username);
      
      await db.logAdminAudit({
        username: req.adminUser,
        ipAddress: clientIp,
        accion: 'ELIMINAR_ADMINISTRADOR',
        detalles: `Eliminó el administrador: ${username}`
      });
      
      res.json({ ok: true });
    } catch (err) {
      res.status(400).json({ error: err.message });
    }
  }
);

// ─── Cambiar rol de administrador ───

router.put('/api/admins/:username/rol', requireAdmin, requireRol('superadministrador'),
  param('username').isString().trim().notEmpty(),
  body('rol').isString().isIn(['operador', 'administrador', 'superadministrador']),
  async (req, res, next) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) return res.status(400).json({ error: 'Rol inválido.' });
      const username = req.params.username;
      const { rol } = req.body;
      const clientIp = getClientIp(req);

      await db.updateAdminRol(username, rol);

      await db.logAdminAudit({
        username: req.adminUser,
        ipAddress: clientIp,
        accion: 'CAMBIAR_ROL_ADMINISTRADOR',
        detalles: `Cambió rol de ${username} a: ${rol}`
      });

      res.json({ ok: true });
    } catch (err) {
      res.status(400).json({ error: err.message });
    }
  }
);

// ─── Logs de Auditoría ───

router.get('/api/audit-logs', requireAdmin,
  query('search').optional().isString().trim().escape(),
  query('limit').optional().isInt({ min: 1, max: 200 }).toInt(),
  query('offset').optional().isInt({ min: 0 }).toInt(),
  async (req, res, next) => {
    try {
      const { search = '', limit = 50, offset = 0 } = req.query;
      res.json(await db.getAdminAuditLogs({ search, limit, offset }));
    } catch (err) {
      next(err);
    }
  }
);

// ─── Tareas de Mantenimiento ──────────────────────────────────────────────────

router.get('/api/maintenance/stats', requireAdmin,
  query('cedula').optional().isString().trim(),
  async (req, res, next) => {
    try {
      const cedula = req.query.cedula || '';
      const stats = await db.getRandomMacStats({ cedula });
      res.json(stats);
    } catch (err) { next(err); }
  }
);

router.get('/api/maintenance/preview', requireAdmin,
  query('cedula').optional().isString().trim(),
  async (req, res, next) => {
    try {
      const cedula = req.query.cedula || '';
      const preview = await db.getRandomMacPreview({ cedula });
      res.json(preview);
    } catch (err) { next(err); }
  }
);

router.post('/api/maintenance/purge', requireAdmin,
  body('purgeDevices').isBoolean(),
  body('purgeAcct').isBoolean(),
  body('purgeLogs').isBoolean(),
  body('purgeTempSessions').isBoolean(),
  body('cedula').optional().isString().trim(),
  async (req, res, next) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({ error: 'Parámetros inválidos.' });
      }
      const { purgeDevices, purgeAcct, purgeLogs, purgeTempSessions, cedula = '' } = req.body;
      const result = await db.purgeRandomMacs({ purgeDevices, purgeAcct, purgeLogs, purgeTempSessions, cedula });
      
      const clientIp = getClientIp(req);
      await db.logAdminAudit({
        username: req.adminUser,
        ipAddress: clientIp,
        accion: 'DEPURAR_MAC_ALEATORIAS',
        detalles: `Depuración ejecutada. Filtro Cédula: ${cedula || 'Ninguno'}, Disp: ${result.deletedDevices}, Acct: ${result.deletedAcct}, Logs: ${result.deletedLogs}, TempSessions: ${result.deletedTempSessions}`
      });

      res.json({ success: true, result });
    } catch (err) { next(err); }
  }
);

router.get('/api/maintenance/schedule', requireAdmin, async (req, res, next) => {
  try {
    const config = await db.getControllerConfig('maintenance_schedule');
    const defaultConfig = {
      enabled: false,
      frequency: 'weekly',
      ageDays: 30,
      purgeDevices: true,
      purgeAcct: true,
      purgeLogs: true,
      purgeTempSessions: true,
      lastRun: null
    };
    res.json(config || defaultConfig);
  } catch (err) { next(err); }
});

router.post('/api/maintenance/schedule', requireAdmin,
  body('enabled').isBoolean(),
  body('frequency').isIn(['daily', 'weekly', 'monthly']),
  body('ageDays').isInt({ min: 1, max: 365 }),
  body('purgeDevices').isBoolean(),
  body('purgeAcct').isBoolean(),
  body('purgeLogs').isBoolean(),
  body('purgeTempSessions').isBoolean(),
  async (req, res, next) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) return res.status(400).json({ error: 'Parámetros inválidos.' });

      const config = {
        enabled: req.body.enabled,
        frequency: req.body.frequency,
        ageDays: parseInt(req.body.ageDays),
        purgeDevices: req.body.purgeDevices,
        purgeAcct: req.body.purgeAcct,
        purgeLogs: req.body.purgeLogs,
        purgeTempSessions: req.body.purgeTempSessions,
        lastRun: req.body.lastRun || null
      };

      await db.saveControllerConfig('maintenance_schedule', config);

      const clientIp = getClientIp(req);
      await db.logAdminAudit({
        username: req.adminUser,
        ipAddress: clientIp,
        accion: 'CONFIGURAR_DEPURACION_PROGRAMADA',
        detalles: `Configuró depuración programada: Habilitado=${config.enabled}, Frecuencia=${config.frequency}, Edad=${config.ageDays} días`
      });

      res.json({ success: true });
    } catch (err) { next(err); }
  }
);

// ─── Error handler para admin ─────────────────────────────────────────────────

router.use((err, req, res, next) => { // eslint-disable-line no-unused-vars
  console.error('[ADMIN]', err.message);
  res.status(500).json({ error: 'Error interno.' });
});

module.exports = router;

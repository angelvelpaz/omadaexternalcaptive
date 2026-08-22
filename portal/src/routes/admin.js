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
const ldapSvc        = require('../services/ldap');
const winbindManager = require('../services/winbindManager');
const axios          = require('axios');
const externalApi    = require('../services/externalApi');
const { getClientIp, validateBase64Image } = require('../services/utils');

const ADMIN_SECRET = process.env.ADMIN_SECRET || 'admin_secret_cambia_esto';
const PUBLIC = path.join(__dirname, '../../public');

// Desactivar caché en todas las respuestas del router admin (API y HTML)
router.use((req, res, next) => {
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');
  next();
});

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
  let token = auth.startsWith('Bearer ') ? auth.slice(7) : (req.headers['x-admin-token'] || null);
  if (!token) {
    return res.status(401).json({ error: 'No autorizado. Se requiere token.' });
  }

  try {
    // 1. Verificar si es el token del administrador legacy (compatibilidad)
    if (process.env.NODE_ENV !== 'production' && token === ADMIN_SECRET) {
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

function requireSelfOrRol(...roles) {
  return (req, res, next) => {
    if (req.adminUser === String(req.params.username || '').trim().toLowerCase()) {
      return next();
    }
    return requireRol(...roles)(req, res, next);
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
  query('type').isIn(['users', 'connections', 'access', 'failed_auth']),
  query('search').optional().isString().trim().escape(),
  query('ssid').optional().isString().trim().escape(),
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

      const { type, mode = 'consolidated', search = '', ssid = '', startDate, endDate, limit = 50, offset = 0 } = req.query;

      let result;
      if (type === 'users') {
        result = await db.getUsersReport({ search, startDate, endDate, limit, offset });
      } else if (type === 'connections') {
        if (mode === 'consolidated') {
          result = await db.getConsolidatedConnectionsReport({ search, ssid, startDate, endDate, limit, offset });
        } else {
          result = await db.getConnectionsReport({ search, ssid, startDate, endDate, limit, offset });
        }
      } else if (type === 'access') {
        result = await db.getAccessLogReport({ search, startDate, endDate, limit, offset });
      } else if (type === 'failed_auth') {
        result = await db.getFailedAuthReport({ search, startDate, endDate, limit, offset });
      }

      res.json(result);
    } catch (err) { next(err); }
  }
);

router.get('/api/reports/ssids', requireAdmin, async (req, res, next) => {
  try {
    const ssids = await db.getDistinctSsids();
    res.json({ ssids });
  } catch (err) { next(err); }
});

router.get('/api/devices/:mac/live-status', requireAdmin, async (req, res, next) => {
  try {
    const { mac } = req.params;
    const liveStatus = await omadaSvc.getDeviceLiveStatus(mac);
    res.json(liveStatus);
  } catch (err) { next(err); }
});

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

      // Verificar que la MAC no esté registrada en WPA Enterprise
      const conflict = await db.isMacRegisteredInOtherType(mac_address, 'captive');
      if (conflict) {
        return res.status(409).json({
          error: `La MAC ${mac_address} ya está registrada como dispositivo de WPA Enterprise por el usuario ${conflict.username}.`
        });
      }

      await db.registerUserDevice(cedula, mac_address);
      await db.logAdminAudit({
        username: req.adminUser,
        ipAddress: getClientIp(req),
        accion: 'REGISTRAR_DISPOSITIVO',
        detalles: `Dispositivo ${mac_address} registrado para el usuario ${cedula}`
      });
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
      await db.logAdminAudit({
        username: req.adminUser,
        ipAddress: getClientIp(req),
        accion: 'MODIFICAR_DISPOSITIVO',
        detalles: `Dispositivo ${old_mac_address} de ${old_cedula} modificado a ${new_mac_address} de ${new_cedula}`
      });
      res.json({ success: true, message: 'Dispositivo actualizado con éxito.' });
    } catch (err) { next(err); }
  }
);

router.delete('/api/devices', requireAdmin,
  body('cedula').isString().trim().isLength({ min: 1, max: 150 }),
  body('mac_address').isString().trim().matches(/^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$/),
  async (req, res, next) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({ error: 'Datos de dispositivo inválidos.' });
      }
      const { cedula, mac_address } = req.body;
      
      // 1. Eliminar de la base de datos local
      await db.deleteUserDevice(cedula, mac_address);
      
      // Auditoría
      await db.logAdminAudit({
        username: req.adminUser,
        ipAddress: getClientIp(req),
        accion: 'ELIMINAR_DISPOSITIVO',
        detalles: `Dispositivo ${mac_address} eliminado del usuario ${cedula}`
      });
      
      // 2. Desautorizar y desconectar (kick) en Omada
      try {
        console.log(`[ADMIN-DEVICE] Desautorizando MAC ${mac_address} en Omada`);
        await omadaSvc.unauthorizeClient({ clientMac: mac_address });
      } catch (omadaErr) {
        console.error(`[ADMIN-DEVICE] Error desautorizando MAC ${mac_address} en Omada:`, omadaErr.message);
      }

      // 3. Desautorizar en UniFi
      try {
        console.log(`[ADMIN-DEVICE] Intentando desautorizar MAC ${mac_address} en UniFi`);
        await unifiSvc.unauthorizeGuest(mac_address);
      } catch (unifiErr) {
        console.error(`[ADMIN-DEVICE] Error desautorizando MAC ${mac_address} en UniFi:`, unifiErr.message);
      }

      res.json({ success: true, message: 'Dispositivo eliminado con éxito.' });
    } catch (err) { next(err); }
  }
);

router.get('/api/users/active', requireAdmin, async (req, res, next) => {
  try {
    const list = await db.getActiveUserSessions();
    res.json(list);
  } catch (err) { next(err); }
});

router.get('/api/ldap-portal/active', requireAdmin, async (req, res, next) => {
  try {
    const list = await db.getActiveLdapPortalSessions();
    res.json(list);
  } catch (err) { next(err); }
});

router.get('/api/hotel/active', requireAdmin, async (req, res, next) => {
  try {
    const list = await db.getActiveHotelSessions();
    res.json(list);
  } catch (err) { next(err); }
});

router.get('/api/restaurant/active', requireAdmin, async (req, res, next) => {
  try {
    const list = await db.getActiveRestaurantSessions();
    res.json(list);
  } catch (err) { next(err); }
});

router.get('/api/users', requireAdmin,
  query('search').optional().isString().trim(),
  query('limit').optional().isInt({ min: 1, max: 200 }).toInt(),
  query('offset').optional().isInt({ min: 0 }).toInt(),
  query('orderBy').optional().isString().trim(),
  query('orderDir').optional().isString().trim(),
  query('filterLastConnStart').optional().isString().trim(),
  query('filterLastConnEnd').optional().isString().trim(),
  query('filterConsumption').optional().isString().trim(),
  query('tipo_usuario').optional().isString().trim(),
  async (req, res, next) => {
    try {
      const matched = matchedData(req, { includeOptionals: true, locations: ['query'] });
      const search = matched.search || '';
      const limit  = matched.limit  ?? 50;
      const offset = matched.offset ?? 0;
      const orderBy = matched.orderBy || 'fecha_registro';
      const orderDir = matched.orderDir || 'DESC';
      const filterLastConnStart = matched.filterLastConnStart || '';
      const filterLastConnEnd = matched.filterLastConnEnd || '';
      const filterConsumption = matched.filterConsumption || 'all';
      const tipo_usuario = matched.tipo_usuario || '';
      
      res.json(await db.listUsers({ 
        search, limit, offset, orderBy, orderDir, filterLastConnStart, filterLastConnEnd, filterConsumption, tipo_usuario
      }));
    } catch (err) { next(err); }
  }
);

router.get('/api/users/:cedula', requireAdmin,
  param('cedula').isString().trim().notEmpty().isLength({ max: 32 }),
  async (req, res, next) => {
    try {
      const user = await db.getUserDetail(req.params.cedula);
      if (!user) return res.status(404).json({ error: 'Usuario no encontrado.' });
      res.json(user);
    } catch (err) { next(err); }
  }
);

router.patch('/api/users/:cedula/type', requireAdmin,
  param('cedula').isString().trim().notEmpty().isLength({ max: 32 }),
  body('tipo_usuario').isIn(['autoregistro', 'ldap_portal', 'wpa_enterprise', 'hotel', 'restaurant', 'institucional', 'externo']),
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
  body('tipo_usuario').isIn(['autoregistro', 'ldap_portal', 'wpa_enterprise', 'hotel', 'restaurant', 'institucional', 'externo']),
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
              db.disconnectRadiusClient(mac).catch(err => {
                console.error(`[RADIUS-CoA] Error al desautorizar MAC ${mac} en desactivación en lote:`, err.message);
              });
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

router.post('/api/users/bulk-delete', requireAdmin, requireRol('administrador', 'superadministrador'),
  body('cedulas').isArray({ min: 1 }),
  body('purgeHistory').isBoolean(),
  async (req, res, next) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) return res.status(400).json({ error: 'Parámetros inválidos.' });

      const { cedulas, purgeHistory } = req.body;

      // 1. Obtener dispositivos de todos estos usuarios antes de eliminarlos para desautorizarlos de las controladoras
      const allDevices = [];
      for (const ced of cedulas) {
        try {
          const devs = await db.getUserDevices(ced);
          allDevices.push(...devs);
        } catch (err) {
          console.error(`[DB] Error al buscar dispositivos del usuario ${ced} para desautorizar:`, err.message);
        }
      }

      // 2. Ejecutar eliminación en lote
      await db.bulkDeleteUsers(cedulas, purgeHistory);

      // Auditoría
      const clientIp = getClientIp(req);
      await db.logAdminAudit({
        username: req.adminUser,
        ipAddress: clientIp,
        accion: 'ELIMINAR_USUARIO_LOTE',
        detalles: `Eliminó en lote ${cedulas.length} usuarios. ¿Historial purgado?: ${purgeHistory}`
      });

      // 3. Desautorizar dispositivos en segundo plano
      for (const d of allDevices) {
        const mac = d.mac_address;
        
        // Omada
        if (process.env.OMADA_CONTROLLER_URL) {
          omadaSvc.unauthorizeClient({ clientMac: mac }).catch(err => {
            console.error(`[OMADA] Error al desautorizar MAC ${mac} en borrado en lote:`, err.message);
          });
        }

        // UniFi
        if (process.env.UNIFI_CONTROLLER_URL) {
          unifiSvc.unauthorizeGuest(mac).catch(err => {
            console.error(`[UNIFI] Error al desautorizar MAC ${mac} en borrado en lote:`, err.message);
          });
        }
        // RADIUS CoA
        db.disconnectRadiusClient(mac).catch(err => {
          console.error(`[RADIUS-CoA] Error al desautorizar MAC ${mac} en borrado en lote:`, err.message);
        });
      }

      res.json({ success: true });
    } catch (err) { next(err); }
  }
);

router.patch('/api/users/:cedula/active', requireAdmin,
  param('cedula').isString().trim().notEmpty().isLength({ max: 32 }),
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
            // RADIUS CoA
            db.disconnectRadiusClient(mac).catch(err => {
              console.error(`[RADIUS-CoA] Error al desautorizar MAC ${mac} en desactivación:`, err.message);
            });
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
  param('cedula').isString().trim().notEmpty().isLength({ max: 32 }),
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
  param('cedula').isString().trim().notEmpty().isLength({ max: 32 }),
  async (req, res, next) => {
    try {
      const cedula = req.params.cedula;
      const purgeHistory = req.query.purgeHistory === 'true';
      // 1. Obtener dispositivos registrados del usuario antes de borrarlo
      const devices = await db.getUserDevices(cedula);

      // 2. Borrar de la base de datos y de FreeRADIUS
      await db.deleteUser(cedula, purgeHistory);

      // Auditoría
      const clientIp = getClientIp(req);
      await db.logAdminAudit({
        username: req.adminUser,
        ipAddress: clientIp,
        accion: 'ELIMINAR_USUARIO',
        detalles: `Eliminó usuario cédula: ${cedula}. ¿Historial purgado?: ${purgeHistory}`
      });

      // 3. Desautorizar cada uno de sus dispositivos en Omada y UniFi
      for (const d of devices) {
        const mac = d.mac_address;
        
        // Omada: desautorizar y desconectar (kick) en todos los sitios
        try {
          console.log(`[ADMIN-USER] Desautorizando y desconectando MAC ${mac} en Omada`);
          await omadaSvc.unauthorizeClient({ clientMac: mac });
        } catch (omadaErr) {
          console.error(`[ADMIN-USER] Error al desautorizar MAC ${mac} en Omada:`, omadaErr.message);
        }

        // UniFi
        try {
          await unifiSvc.unauthorizeGuest(mac);
        } catch (unifiErr) {}
        // RADIUS CoA
        try {
          await db.disconnectRadiusClient(mac);
        } catch (radiusErr) {}
      }

      res.json({ ok: true });
    } catch (err) { next(err); }
  }
);

router.patch('/api/users/:cedula/max-devices', requireAdmin,
  param('cedula').isString().trim().notEmpty().isLength({ max: 32 }),
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
  param('cedula').isString().trim().notEmpty().isLength({ max: 32 }),
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

      // 2. Intentar desautorizar en Omada
      try {
        console.log(`[ADMIN-DEVICE] Desautorizando MAC ${mac} en Omada`);
        await omadaSvc.unauthorizeClient({ clientMac: mac });
      } catch (omadaErr) {
        console.error(`[ADMIN-DEVICE] Error desautorizando MAC ${mac} en Omada:`, omadaErr.message);
      }

      // 3. Intentar desautorizar en UniFi
      try {
        console.log(`[ADMIN-DEVICE] Intentando desautorizar MAC ${mac} en UniFi`);
        await unifiSvc.unauthorizeGuest(mac);
      } catch (unifiErr) {
        console.error(`[ADMIN-DEVICE] Error desautorizando MAC ${mac} en UniFi:`, unifiErr.message);
      }

      res.json({ ok: true });
    } catch (err) { next(err); }
  }
);

router.post('/api/users/:cedula/devices', requireAdmin,
  param('cedula').isString().trim().notEmpty().isLength({ max: 32 }),
  body('mac').isString().trim(),
  async (req, res, next) => {
    try {
      const { cedula } = req.params;
      let { mac } = req.body;

      if (!mac) {
        return res.status(400).json({ error: 'La dirección MAC es obligatoria' });
      }

      // Normalizar MAC
      mac = mac.toUpperCase().replace(/[^0-9A-F]/g, '');
      if (mac.length !== 12) {
        return res.status(400).json({ error: 'Formato de dirección MAC inválido. Debe tener 12 caracteres hexadecimales.' });
      }

      // Convertir a formato con guiones: AA-BB-CC-DD-EE-FF
      const formattedMac = mac.match(/.{1,2}/g).join('-');

      // 1. Validar si la MAC ya existe asociada a algún usuario
      const existingUser = await db.getUserByDeviceMac(formattedMac);
      if (existingUser) {
        return res.status(400).json({ error: `Este dispositivo ya está registrado al usuario con cédula ${existingUser.cedula}` });
      }

      // 2. Validar límite de dispositivos del usuario
      const user = await db.getUserByCedula(cedula);
      if (!user) {
        return res.status(404).json({ error: 'Usuario no encontrado' });
      }

      const currentCount = await db.getUserDevicesCount(cedula);
      if (user.max_dispositivos !== null && user.max_dispositivos > 0 && currentCount >= user.max_dispositivos) {
        return res.status(400).json({ error: `El usuario ha alcanzado su límite máximo de ${user.max_dispositivos} dispositivos` });
      }

      // 3. Registrar en BD
      await db.registerUserDevice(cedula, formattedMac);

      // Auditoría
      const clientIp = getClientIp(req);
      await db.logAdminAudit({
        username: req.adminUser,
        ipAddress: clientIp,
        accion: 'REGISTRAR_DISPOSITIVO',
        detalles: `Registró dispositivo MAC ${formattedMac} al usuario cédula: ${cedula}`
      });

      // 4. Autorizar en controladoras
      try {
        console.log(`[ADMIN-DEVICE] Autorizando MAC ${formattedMac} en Omada`);
        await omadaSvc.authorizeClient({ clientMac: formattedMac });
      } catch (omadaErr) {
        console.error(`[ADMIN-DEVICE] Error autorizando MAC ${formattedMac} en Omada:`, omadaErr.message);
      }

      try {
        console.log(`[ADMIN-DEVICE] Intentando autorizar MAC ${formattedMac} en UniFi`);
        await unifiSvc.authorizeGuest(formattedMac);
      } catch (unifiErr) {
        console.error(`[ADMIN-DEVICE] Error autorizando MAC ${formattedMac} en UniFi:`, unifiErr.message);
      }

      res.json({ ok: true, macAddress: formattedMac });
    } catch (err) { next(err); }
  }
);

router.put('/api/users/:cedula/devices/:mac', requireAdmin,
  param('cedula').isString().trim().notEmpty().isLength({ max: 32 }),
  param('mac').isString().trim(),
  body('newMac').isString().trim(),
  async (req, res, next) => {
    try {
      const { cedula, mac } = req.params;
      let { newMac } = req.body;

      if (!newMac) {
        return res.status(400).json({ error: 'La nueva dirección MAC es obligatoria' });
      }

      // Normalizar MAC
      newMac = newMac.toUpperCase().replace(/[^0-9A-F]/g, '');
      if (newMac.length !== 12) {
        return res.status(400).json({ error: 'Formato de dirección MAC inválido. Debe tener 12 caracteres hexadecimales.' });
      }

      const formattedNewMac = newMac.match(/.{1,2}/g).join('-');
      const formattedOldMac = mac.toUpperCase().replace(/:/g, '-');

      if (formattedNewMac === formattedOldMac) {
        return res.json({ ok: true, macAddress: formattedNewMac });
      }

      // 1. Validar si la nueva MAC ya existe asociada a otro usuario
      const existingUser = await db.getUserByDeviceMac(formattedNewMac);
      if (existingUser && existingUser.cedula !== cedula) {
        return res.status(400).json({ error: `La nueva MAC ya está registrada al usuario con cédula ${existingUser.cedula}` });
      }

      // 2. Desautorizar la MAC antigua en controladoras
      try {
        console.log(`[ADMIN-DEVICE] Desautorizando MAC antigua ${formattedOldMac} en Omada`);
        await omadaSvc.unauthorizeClient({ clientMac: formattedOldMac });
      } catch (omadaErr) {
        console.error(`[ADMIN-DEVICE] Error desautorizando MAC antigua ${formattedOldMac} en Omada:`, omadaErr.message);
      }

      try {
        console.log(`[ADMIN-DEVICE] Desautorizando MAC antigua ${formattedOldMac} en UniFi`);
        await unifiSvc.unauthorizeGuest(formattedOldMac);
      } catch (unifiErr) {
        console.error(`[ADMIN-DEVICE] Error desautorizando MAC antigua ${formattedOldMac} en UniFi:`, unifiErr.message);
      }

      // 3. Actualizar en BD
      await db.updateUserDevice(cedula, formattedOldMac, cedula, formattedNewMac);

      // Auditoría
      const clientIp = getClientIp(req);
      await db.logAdminAudit({
        username: req.adminUser,
        ipAddress: clientIp,
        accion: 'EDITAR_DISPOSITIVO',
        detalles: `Editó dispositivo MAC ${formattedOldMac} por ${formattedNewMac} del usuario cédula: ${cedula}`
      });

      // 4. Autorizar la nueva MAC en controladoras
      try {
        console.log(`[ADMIN-DEVICE] Autorizando nueva MAC ${formattedNewMac} en Omada`);
        await omadaSvc.authorizeClient({ clientMac: formattedNewMac });
      } catch (omadaErr) {
        console.error(`[ADMIN-DEVICE] Error autorizando nueva MAC ${formattedNewMac} en Omada:`, omadaErr.message);
      }

      try {
        console.log(`[ADMIN-DEVICE] Autorizando nueva MAC ${formattedNewMac} en UniFi`);
        await unifiSvc.authorizeGuest(formattedNewMac);
      } catch (unifiErr) {
        console.error(`[ADMIN-DEVICE] Error autorizando nueva MAC ${formattedNewMac} en UniFi:`, unifiErr.message);
      }

      res.json({ ok: true, macAddress: formattedNewMac });
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
  if (vendor === 'mikrotik') {
    const pass = cfg.pass || '';
    return {
      url:        cfg.url      || '',
      user:       cfg.user     || '',
      pass:       controllerTest.masked(pass),
      activo:     cfg.activo !== undefined ? (cfg.activo === true || cfg.activo === 'true') : true,
      configured: !!cfg.url && !!cfg.user && !!pass,
      fromEnv:    false,
    };
  }
  if (vendor === 'secap') {
    return {
      activo:        cfg.activo !== undefined ? (cfg.activo === true || cfg.activo === 'true') : false,
      emailOpcional: cfg.emailOpcional !== undefined ? (cfg.emailOpcional === true || cfg.emailOpcional === 'true') : false,
      configured:    true,
      fromEnv:       false,
    };
  }
  if (vendor === 'coovachilli') {
    const secret = cfg.secret || '';
    return {
      secret:     controllerTest.masked(secret),
      activo:     cfg.activo !== undefined ? (cfg.activo === true || cfg.activo === 'true') : true,
      configured: true,
      fromEnv:    false,
    };
  }
  if (vendor === 'ldap') {
    const bindCredentials = cfg.ldapBindCredentials || '';
    return {
      ldapServerUrl:       cfg.ldapServerUrl || '',
      ldapBindDN:          cfg.ldapBindDN || '',
      ldapBindCredentials: controllerTest.masked(bindCredentials),
      ldapSearchBase:      cfg.ldapSearchBase || '',
      ldapAllowedGroup:    cfg.ldapAllowedGroup || '',
      configured:          !!(cfg.ldapServerUrl && cfg.ldapBindDN && cfg.ldapSearchBase),
      activo:              cfg.activo !== false,
      fromEnv:             false,
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
  if (vendor === 'mikrotik') {
    return {
      url:   cfg.url  || '',
      user:  cfg.user || '',
      pass:  cfg.pass || '',
    };
  }
  if (vendor === 'secap') {
    return {
      activo:        cfg.activo !== undefined ? (cfg.activo === true || cfg.activo === 'true') : false,
      emailOpcional: cfg.emailOpcional !== undefined ? (cfg.emailOpcional === true || cfg.emailOpcional === 'true') : false,
    };
  }
  if (vendor === 'coovachilli') {
    return {
      secret:  cfg.secret || '',
    };
  }
  if (vendor === 'ldap') {
    return {
      ldapServerUrl:       cfg.ldapServerUrl || '',
      ldapBindDN:          cfg.ldapBindDN || '',
      ldapBindCredentials: cfg.ldapBindCredentials || '',
      ldapSearchBase:      cfg.ldapSearchBase || '',
      ldapAllowedGroup:    cfg.ldapAllowedGroup || '',
    };
  }
  return {};
}

// GET — configuración actual (secretos enmascarados)
router.get('/api/controllers', requireAdmin, requireRol('superadministrador'), async (req, res, next) => {
  try {
    const vendors = ['freeradius', 'unifi', 'omada', 'mikrotik', 'coovachilli', 'secap', 'ldap'];
    const result  = {};
    for (const vendor of vendors) {
      const dbCfg = await db.getControllerConfig(vendor);
      result[vendor] = buildControllerResponse(vendor, dbCfg);
    }
    res.json(result);
  } catch (err) { next(err); }
});

// PUT — guarda configuración en DB
router.put('/api/controllers/:vendor', requireAdmin, requireRol('superadministrador'),
  param('vendor').isIn(['freeradius', 'unifi', 'omada', 'mikrotik', 'coovachilli', 'secap', 'ldap']),
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
      } else if (vendor === 'mikrotik') {
        newCfg = {
          url:     getVal(input.url, existing.url),
          user:    getVal(input.user, existing.user),
          pass:    getVal(input.pass, existing.pass),
          activo:  activoVal,
        };
      } else if (vendor === 'secap') {
        newCfg = {
          activo:        input.activo !== undefined ? (input.activo === true || input.activo === 'true' || input.activo === '1') : false,
          emailOpcional: input.emailOpcional !== undefined ? (input.emailOpcional === true || input.emailOpcional === 'true' || input.emailOpcional === '1') : false,
        };
      } else if (vendor === 'coovachilli') {
        newCfg = {
          secret:  getVal(input.secret, existing.secret),
          activo:  activoVal,
        };
      } else if (vendor === 'ldap') {
        newCfg = {
          ldapServerUrl:       getVal(input.ldapServerUrl, existing.ldapServerUrl),
          ldapBindDN:          getVal(input.ldapBindDN, existing.ldapBindDN),
          ldapBindCredentials: getVal(input.ldapBindCredentials, existing.ldapBindCredentials),
          ldapSearchBase:      getVal(input.ldapSearchBase, existing.ldapSearchBase),
          ldapAllowedGroup:    input.ldapAllowedGroup !== undefined ? String(input.ldapAllowedGroup).trim() : (existing.ldapAllowedGroup || ''),
          activo:              activoVal,
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

// Test LDAP connection endpoint
router.post('/api/controllers/ldap/test', requireAdmin, requireRol('superadministrador'), async (req, res, next) => {
  try {
    let { serverUrl, bindDN, bindCredentials, searchBase, allowedGroup, testUser, testPassword } = req.body;

    // Si no se enviaron campos en el body, leer de la config guardada en DB
    if (!serverUrl && !bindDN && !searchBase) {
      const dbCfg = await db.getControllerConfig('ldap');
      if (dbCfg) {
        serverUrl     = serverUrl     || dbCfg.ldapServerUrl;
        bindDN        = bindDN        || dbCfg.ldapBindDN;
        bindCredentials = bindCredentials || dbCfg.ldapBindCredentials;
        searchBase    = searchBase    || dbCfg.ldapSearchBase;
        allowedGroup  = allowedGroup  || dbCfg.ldapAllowedGroup;
      }
    }

    if (!serverUrl || !bindDN || !searchBase) {
      return res.status(400).json({ error: 'La configuración LDAP del servidor no está completa. Complete Server URL, Bind DN y Search Base.' });
    }
    if (!testUser || !testPassword) {
      return res.status(400).json({ error: 'Ingrese un usuario y contraseña de prueba para validar la conexión.' });
    }

    const testResult = await ldapSvc.authenticateTest({
      url: serverUrl,
      bindDN,
      bindPassword: bindCredentials,
      searchBase,
      allowedGroup,
      username: testUser,
      password: testPassword
    });

    if (testResult.success) {
      res.json({ success: true, message: '¡Conexión y autenticación LDAP exitosas!', user: testResult });
    } else {
      res.json({ success: false, error: testResult.error });
    }
  } catch (err) {
    res.json({ success: false, error: err.message });
  }
});

router.post('/api/controllers/:vendor/test', requireAdmin,
  param('vendor').isIn(['freeradius', 'unifi', 'omada', 'mikrotik', 'coovachilli', 'secap']),
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
        case 'mikrotik':   result = await controllerTest.testMikrotik(cfg);   break;
        case 'secap':
          result = { ok: true, message: 'Servicio SECAP configurado con éxito.' };
          break;
        case 'coovachilli':
          result = { ok: true, message: 'Controlador CoovaChilli / OpenWrt activo a través de RADIUS.' };
          break;
      }
      res.json({ ...result, testedAt: new Date().toISOString() });
    } catch (err) { next(err); }
  }
);

// ─── Winbind / ntlm_auth (solo superadministrador) ────────────────────────────
const WINBIND_REALM = /^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$/;
const WINBIND_NETBIOS = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,14}$/;
const WINBIND_DC = /^(?:(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?|(?:[0-9]{1,3}\.){3}[0-9]{1,3})$/;
const WINBIND_USER = /^[A-Za-z0-9_.@\\-]{1,128}$/;

const winbindDomainValidators = [
  body('realm').isString().trim().matches(WINBIND_REALM),
  body('netbios_domain').isString().trim().matches(WINBIND_NETBIOS),
  body('dc').optional({ values: 'falsy' }).isString().trim().matches(WINBIND_DC),
];

function winbindError(res, error) {
  const status = Number.isInteger(error.status) && error.status >= 400 && error.status < 600
    ? error.status
    : 503;
  return res.status(status).json({ error: error.message || 'Operación Winbind no disponible.' });
}

router.get('/api/winbind/status', requireAdmin, requireRol('superadministrador'), async (req, res) => {
  try {
    res.json(await winbindManager.getStatus());
  } catch (error) {
    winbindError(res, error);
  }
});

router.post('/api/winbind/test', requireAdmin, requireRol('superadministrador'), [
  body('username').isString().trim().matches(WINBIND_USER),
  body('password').isString().isLength({ min: 1, max: 512 }).custom(value => !/[\0\r\n]/.test(value)),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ error: 'Usuario o contraseña de prueba inválidos.' });
  try {
    const result = await winbindManager.testCredentials({
      username: req.body.username.trim(),
      password: req.body.password,
    });
    res.json({ ok: !!result.ok, authenticated: !!result.authenticated, message: result.message });
  } catch (error) {
    winbindError(res, error);
  }
});

router.post('/api/winbind/configure', requireAdmin, requireRol('superadministrador'), winbindDomainValidators, async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ error: 'Realm, dominio NetBIOS o controlador inválido.' });
  try {
    const result = await winbindManager.configureDomain({
      realm: req.body.realm.trim(),
      netbios_domain: req.body.netbios_domain.trim(),
      dc: (req.body.dc || '').trim(),
    });
    res.json({ ok: !!result.ok, message: result.message });
  } catch (error) {
    winbindError(res, error);
  }
});

router.post('/api/winbind/join', requireAdmin, requireRol('superadministrador'), [
  ...winbindDomainValidators,
  body('username').isString().trim().matches(WINBIND_USER),
  body('password').isString().isLength({ min: 1, max: 512 }).custom(value => !/[\0\r\n]/.test(value)),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ error: 'Complete una configuración de dominio y credenciales válidas.' });
  try {
    const result = await winbindManager.joinDomain({
      realm: req.body.realm.trim(),
      netbios_domain: req.body.netbios_domain.trim(),
      dc: (req.body.dc || '').trim(),
      username: req.body.username.trim(),
      password: req.body.password,
    });
    res.status(result.ok ? 200 : 502).json({ ok: !!result.ok, message: result.message });
  } catch (error) {
    winbindError(res, error);
  }
});

// GET — configuración de branding
router.get('/api/branding', requireAdmin, async (req, res, next) => {
  try {
    const config = await db.getControllerConfig('branding') || {};
    res.json({
      portalName:      config.portalName || process.env.PORTAL_NAME || 'Portal Wi-Fi',
      logoUrl:         config.logoUrl || process.env.PORTAL_LOGO_URL || '/static/logo.svg',
      primaryColor:    config.primaryColor || '#4f46e5',
      accentColor:     config.accentColor || '#6366f1',
      welcomeText:     config.welcomeText || 'Bienvenido a la red Wi-Fi. Por favor regístrese para continuar.',
      termsText:       config.termsText || '',
      inactiveMessage: config.inactiveMessage || 'Su usuario ha sido desactivado. Por favor, contacte al administrador.',
      ipWhitelist:     config.ipWhitelist || '0.0.0.0',
      redirectSeconds: config.redirectSeconds !== undefined ? config.redirectSeconds : 3,
      disableRegistration: config.disableRegistration === true,
      adImageUrl:      config.adImageUrl || '',
      adImageUrlMobile: config.adImageUrlMobile || '',
      adSessionMinutes: config.adSessionMinutes !== undefined ? config.adSessionMinutes : 30,
      adAllowDirectRegister: config.adAllowDirectRegister !== false,
      timezone: config.timezone || 'America/Guayaquil',
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
      const v = validateBase64Image(input.logoBase64);
      if (!v.valid) return res.status(400).json({ error: v.error });
      const fs = require('fs');
      const path = require('path');
      const publicDir = path.join(__dirname, '../../public');
      const filename = `logo_upload.${v.ext}`;
      fs.writeFileSync(path.join(publicDir, filename), v.buffer);
      logoUrl = `/static/${filename}`;
    }

    let adImageUrl = input.adImageUrl || '';
    if (input.adBase64 && input.adBase64.startsWith('data:image/')) {
      const v = validateBase64Image(input.adBase64, { maxBytes: 3 * 1024 * 1024 });
      if (!v.valid) return res.status(400).json({ error: v.error });
      const fs = require('fs');
      const path = require('path');
      const publicDir = path.join(__dirname, '../../public');
      const filename = `ad_upload.${v.ext}`;
      fs.writeFileSync(path.join(publicDir, filename), v.buffer);
      adImageUrl = `/static/${filename}`;
    }

    let adImageUrlMobile = input.adImageUrlMobile || '';
    if (input.adMobileBase64 && input.adMobileBase64.startsWith('data:image/')) {
      const v = validateBase64Image(input.adMobileBase64, { maxBytes: 3 * 1024 * 1024 });
      if (!v.valid) return res.status(400).json({ error: v.error });
      const fs = require('fs');
      const path = require('path');
      const publicDir = path.join(__dirname, '../../public');
      const filename = `ad_upload_mobile.${v.ext}`;
      fs.writeFileSync(path.join(publicDir, filename), v.buffer);
      adImageUrlMobile = `/static/${filename}`;
    }

    const newCfg = {
      portalName:      (input.portalName || '').trim() || 'Portal Wi-Fi',
      logoUrl:         logoUrl,
      primaryColor:    (input.primaryColor || '').trim() || '#4f46e5',
      accentColor:     (input.accentColor || '').trim() || '#6366f1',
      welcomeText:     (input.welcomeText || '').trim() || 'Bienvenido a la red Wi-Fi. Por favor regístrese para continuar.',
      termsText:       newTermsText,
      termsUpdatedAt:  termsUpdatedAt,
      inactiveMessage: (input.inactiveMessage || '').trim() || 'Su usuario ha sido desactivado. Por favor, contacte al administrador.',
      ipWhitelist:     ipWhitelist,
      redirectSeconds: parseInt(input.redirectSeconds !== undefined ? input.redirectSeconds : '3'),
      disableRegistration: !!input.disableRegistration,
      adImageUrl:      adImageUrl,
      adImageUrlMobile: adImageUrlMobile,
      adSessionMinutes: parseInt(input.adSessionMinutes !== undefined ? input.adSessionMinutes : '30'),
      adAllowDirectRegister: input.adAllowDirectRegister !== false,
      timezone: (input.timezone || 'America/Guayaquil').trim(),
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

// GET — configuración de anchos de banda
router.get('/api/bandwidth-profiles', requireAdmin, async (req, res, next) => {
  try {
    const config = await db.getControllerConfig('bandwidth_profiles') || {
      ldap: { down_mb: 15, up_mb: 5 },
      citizen: { down_mb: 5, up_mb: 1 },
      publicity: { down_mb: 3, up_mb: 1 }
    };
    res.json(config);
  } catch (err) { next(err); }
});

// PUT — guarda configuración de anchos de banda
router.put('/api/bandwidth-profiles', requireAdmin, async (req, res, next) => {
  try {
    const input = req.body;
    
    // Validar datos numéricos
    if (!input.ldap || !input.citizen || !input.publicity) {
      return res.status(400).json({ error: 'Configuración de perfiles incompleta.' });
    }

    const validateProfile = (p) => {
      const down = parseFloat(p.down_mb);
      const up = parseFloat(p.up_mb);
      return !isNaN(down) && down > 0 && !isNaN(up) && up > 0;
    };

    if (!validateProfile(input.ldap) || !validateProfile(input.citizen) || !validateProfile(input.publicity)) {
      return res.status(400).json({ error: 'Los valores de velocidad deben ser números válidos mayores a cero.' });
    }

    const newCfg = {
      ldap: {
        down_mb: parseFloat(input.ldap.down_mb),
        up_mb: parseFloat(input.ldap.up_mb)
      },
      citizen: {
        down_mb: parseFloat(input.citizen.down_mb),
        up_mb: parseFloat(input.citizen.up_mb)
      },
      publicity: {
        down_mb: parseFloat(input.publicity.down_mb),
        up_mb: parseFloat(input.publicity.up_mb)
      }
    };

    await db.saveControllerConfig('bandwidth_profiles', newCfg);

    // Auditoría
    const clientIp = getClientIp(req);
    await db.logAdminAudit({
      username: req.adminUser,
      ipAddress: clientIp,
      accion: 'MODIFICAR_ANCHOS_DE_BANDA',
      detalles: `Modificó perfiles de velocidad (LDAP: ${newCfg.ldap.down_mb}/${newCfg.ldap.up_mb}M, Ciudadano: ${newCfg.citizen.down_mb}/${newCfg.citizen.up_mb}M, Publicidad: ${newCfg.publicity.down_mb}/${newCfg.publicity.up_mb}M)`
    });

    res.json({ ok: true });
  } catch (err) { next(err); }
});

// SSID Config endpoints
router.get('/api/ssids', requireAdmin, async (req, res, next) => {
  try {
    const list = await db.listAllSsidConfigs();
    res.json(list);
  } catch (err) { next(err); }
});

router.post('/api/ssids', requireAdmin, async (req, res, next) => {
  try {
    const { ssidName, authType, config } = req.body;
    if (!ssidName || !authType) {
      return res.status(400).json({ error: 'El nombre del SSID y el tipo de autenticación son obligatorios.' });
    }

    const configInput = config || {};

    // Validar que si es LDAP y no hay grupo global, sea obligatorio definir el grupo en el SSID
    if (authType === 'ldap') {
      const ldapConfig = await db.getControllerConfig('ldap');
      const hasGlobalGroup = ldapConfig && ldapConfig.ldapAllowedGroup && ldapConfig.ldapAllowedGroup.trim();
      const hasSsidGroup = configInput.ldapAllowedGroup && configInput.ldapAllowedGroup.trim();
      if (!hasGlobalGroup && !hasSsidGroup) {
        return res.status(400).json({ error: 'Como no se ha configurado un Grupo Autorizado Global de LDAP, es obligatorio especificar un grupo de seguridad de LDAP para este perfil de SSID.' });
      }
    }

    let logoUrl = configInput.logoUrl || '/static/logo.svg';
    if (configInput.logoBase64 && configInput.logoBase64.startsWith('data:image/')) {
      const v = validateBase64Image(configInput.logoBase64);
      if (!v.valid) return res.status(400).json({ error: v.error });
      const filename = `logo_upload_${ssidName.replace(/[^a-zA-Z0-9]/g, '_')}.${v.ext}`;
      fs.writeFileSync(path.join(PUBLIC, filename), v.buffer);
      logoUrl = `/static/${filename}`;
    }

    let adImageUrl = configInput.adImageUrl || '';
    if (configInput.adBase64 && configInput.adBase64.startsWith('data:image/')) {
      const v = validateBase64Image(configInput.adBase64, { maxBytes: 3 * 1024 * 1024 });
      if (!v.valid) return res.status(400).json({ error: v.error });
      const filename = `ad_upload_${ssidName.replace(/[^a-zA-Z0-9]/g, '_')}.${v.ext}`;
      fs.writeFileSync(path.join(PUBLIC, filename), v.buffer);
      adImageUrl = `/static/${filename}`;
    }

    let adImageUrlMobile = configInput.adImageUrlMobile || '';
    if (configInput.adMobileBase64 && configInput.adMobileBase64.startsWith('data:image/')) {
      const v = validateBase64Image(configInput.adMobileBase64, { maxBytes: 3 * 1024 * 1024 });
      if (!v.valid) return res.status(400).json({ error: v.error });
      const filename = `ad_upload_mobile_${ssidName.replace(/[^a-zA-Z0-9]/g, '_')}.${v.ext}`;
      fs.writeFileSync(path.join(PUBLIC, filename), v.buffer);
      adImageUrlMobile = `/static/${filename}`;
    }

    const savedConfig = {
      portalName:      (configInput.portalName || '').trim() || 'Portal Wi-Fi',
      logoUrl:         logoUrl,
      primaryColor:    (configInput.primaryColor || '').trim() || '#4f46e5',
      accentColor:     (configInput.accentColor || '').trim() || '#6366f1',
      welcomeText:     (configInput.welcomeText || '').trim() || 'Bienvenido. Por favor identifíquese para continuar.',
      termsText:       (configInput.termsText || '').trim() || '',
      inactiveMessage: (configInput.inactiveMessage || '').trim() || 'Su usuario ha sido desactivado.',
      redirectSeconds: parseInt(configInput.redirectSeconds !== undefined ? configInput.redirectSeconds : '3'),
      adImageUrl:      adImageUrl,
      adImageUrlMobile: adImageUrlMobile,
      adSessionMinutes: parseInt(configInput.adSessionMinutes !== undefined ? configInput.adSessionMinutes : '30'),
      adAllowDirectRegister: configInput.adAllowDirectRegister !== false,
      // LDAP
      ldapServerUrl:   (configInput.ldapServerUrl || '').trim(),
      ldapBindDN:      (configInput.ldapBindDN || '').trim(),
      ldapBindCredentials: (configInput.ldapBindCredentials || '').trim(),
      ldapSearchBase:  (configInput.ldapSearchBase || '').trim(),
      ldapAllowedGroup: (configInput.ldapAllowedGroup || '').trim(),
      // SECAP
      secapEnabled:    configInput.secapEnabled === true || configInput.secapEnabled === 'true',
      emailOpcional:   configInput.emailOpcional === true || configInput.emailOpcional === 'true'
    };

    await db.saveSsidConfig(ssidName.trim(), authType.trim(), savedConfig);

    await db.logAdminAudit({
      username: req.adminUser,
      ipAddress: getClientIp(req),
      accion: 'MODIFICAR_SSID_CONFIG',
      detalles: `Configuró perfil de SSID: ${ssidName} (tipo: ${authType})`
    });

    res.json({ ok: true });
  } catch (err) { next(err); }
});

router.delete('/api/ssids/:ssidName', requireAdmin, async (req, res, next) => {
  try {
    const { ssidName } = req.params;
    if (!ssidName) {
      return res.status(400).json({ error: 'El nombre del SSID es obligatorio.' });
    }

    await db.deleteSsidConfig(ssidName);

    await db.logAdminAudit({
      username: req.adminUser,
      ipAddress: getClientIp(req),
      accion: 'ELIMINAR_SSID_CONFIG',
      detalles: `Eliminó perfil de SSID: ${ssidName}`
    });

    res.json({ ok: true });
  } catch (err) { next(err); }
});

// ─── RUTAS PARA LISTA BLANCA DE DISPOSITIVOS (MAC BYPASS) ─────────────────────

router.get('/api/mac-bypass', requireAdmin, requireRol('operador'), async (req, res, next) => {
  try {
    const list = await db.listMacBypass();
    res.json(list);
  } catch (err) { next(err); }
});

// GET - Listar todas las conexiones activas de mac-bypass
router.get('/api/mac-bypass/active', requireAdmin, requireRol('operador'), async (req, res, next) => {
  try {
    const sessions = await db.getActiveMacBypassSessions();
    res.json(sessions);
  } catch (err) { next(err); }
});

// POST - Importar dispositivos en bypass en lote desde CSV
router.post('/api/mac-bypass/bulk-import', requireAdmin, requireRol('operador'), async (req, res, next) => {
  try {
    const { csvText } = req.body;
    if (!csvText) {
      return res.status(400).json({ error: 'No se envió texto CSV.' });
    }

    const lines = csvText.split(/\r?\n/);
    if (lines.length <= 1) {
      return res.status(400).json({ error: 'El archivo CSV está vacío o le falta la cabecera.' });
    }

    // Límite de lote para evitar timeouts
    if (lines.length > 501) {
      return res.status(400).json({ error: 'El archivo excede el límite máximo de 500 dispositivos por importación.' });
    }

    // Procesar cabecera y filas
    const headers = lines[0].split(',').map(h => h.trim().toLowerCase().replace(/"/g, ''));
    const devices = [];

    for (let i = 1; i < lines.length; i++) {
      const line = lines[i].trim();
      if (!line) continue;

      const values = [];
      let current = '';
      let inQuotes = false;
      for (let j = 0; j < line.length; j++) {
        const char = line[j];
        if (char === '"') {
          inQuotes = !inQuotes;
        } else if (char === ',' && !inQuotes) {
          values.push(current.trim());
          current = '';
        } else {
          current += char;
        }
      }
      values.push(current.trim());

      const row = {};
      headers.forEach((h, index) => {
        let val = values[index] !== undefined ? values[index] : '';
        if (val.startsWith('"') && val.endsWith('"')) {
          val = val.substring(1, val.length - 1);
        }
        row[h] = val;
      });

      row._lineNum = i + 1;
      devices.push(row);
    }

    const result = await db.bulkImportMacBypass(devices);

    // Auditoría de importación masiva
    await db.logAdminAudit({
      username: req.adminUser,
      ipAddress: getClientIp(req),
      accion: 'IMPORTACION_MASIVA_BYPASS',
      detalles: `Importó CSV: ${result.success.length} agregados, ${result.skipped.length} omitidos, ${result.errors.length} errores.`
    });

    res.json(result);
  } catch (err) { next(err); }
});

// POST - Registrar nueva MAC en bypass
router.post('/api/mac-bypass', requireAdmin, requireRol('operador'), async (req, res, next) => {
  try {
    const { macAddress, propietario, alias, ppsk, vlanId, cedula } = req.body;
    if (!macAddress || !propietario) {
      return res.status(400).json({ error: 'La dirección MAC y el propietario son obligatorios.' });
    }

    // Limpiar MAC
    const cleanMac = macAddress.trim().toUpperCase().replace(/:/g, '-');
    if (!/^([0-9A-F]{2}-){5}[0-9A-F]{2}$/.test(cleanMac)) {
      return res.status(400).json({ error: 'Formato de dirección MAC inválido (debe ser xx:xx:xx:xx:xx:xx o xx-xx-xx-xx-xx-xx).' });
    }

    // Verificar si ya existe en la lista de bypass o en dispositivos de usuario
    const exists = await db.getMacBypassByMac(cleanMac);
    if (exists) {
      return res.status(400).json({ error: 'Esta dirección MAC ya está registrada en la lista de exclusiones (MAC Bypass).' });
    }

    const newDevice = await db.createMacBypass(cleanMac, propietario, alias, ppsk, vlanId, cedula);

    await db.logAdminAudit({
      username: req.adminUser,
      ipAddress: getClientIp(req),
      accion: 'REGISTRAR_MAC_BYPASS',
      detalles: `Registró dispositivo en bypass: MAC ${cleanMac}, Propietario: ${propietario}`
    });

    res.json(newDevice);
  } catch (err) { next(err); }
});

// PUT - Actualizar un bypass (Editar propietario, alias, ppsk, vlan_id, mac_address)
router.put('/api/mac-bypass/:id', requireAdmin, requireRol('operador'), async (req, res, next) => {
  try {
    const { id } = req.params;
    const { macAddress, propietario, alias, ppsk, vlanId, cedula } = req.body;
    
    if (!macAddress || !propietario) {
      return res.status(400).json({ error: 'La dirección MAC y el propietario son obligatorios.' });
    }

    const cleanMac = macAddress.trim().toUpperCase().replace(/:/g, '-');
    if (!/^([0-9A-F]{2}-){5}[0-9A-F]{2}$/.test(cleanMac)) {
      return res.status(400).json({ error: 'Formato de dirección MAC inválido (debe ser xx:xx:xx:xx:xx:xx o xx-xx-xx-xx-xx-xx).' });
    }

    // Verificar si la MAC ya existe en otro registro (distinto al actual)
    const existing = await db.getMacBypassByMac(cleanMac);
    if (existing && String(existing.id) !== String(id)) {
      return res.status(400).json({ error: 'Esta dirección MAC ya está registrada en otra exclusión (MAC Bypass).' });
    }

    const updated = await db.updateMacBypass(id, cleanMac, propietario, alias, ppsk, vlanId, cedula);
    if (!updated) {
      return res.status(404).json({ error: 'Registro no encontrado.' });
    }

    // Hotspot dynamic disconnect client (CoA) if MAC changed or configuration updated
    try {
      await db.disconnectRadiusClient(cleanMac);
    } catch (coaErr) {
      console.warn(`[CoA] Error de desconexión al actualizar MAC bypass ${cleanMac}:`, coaErr.message);
    }

    await db.logAdminAudit({
      username: req.adminUser,
      ipAddress: getClientIp(req),
      accion: 'ACTUALIZAR_MAC_BYPASS',
      detalles: `Actualizó dispositivo en bypass ID ${id}: MAC ${cleanMac}, Propietario: ${propietario}`
    });

    res.json({ ok: true, device: updated });
  } catch (err) { next(err); }
});

// PUT - Cambiar estado activo
router.put('/api/mac-bypass/:id/active', requireAdmin, requireRol('operador'), async (req, res, next) => {
  try {
    const { id } = req.params;
    const { activo } = req.body;

    const device = await db.getMacBypassById(id);
    if (!device) {
      return res.status(404).json({ error: 'Dispositivo no encontrado.' });
    }

    const updated = await db.updateMacBypassStatus(id, activo);

    await db.logAdminAudit({
      username: req.adminUser,
      ipAddress: getClientIp(req),
      accion: 'MODIFICAR_ESTADO_MAC_BYPASS',
      detalles: `Cambió estado de MAC ${device.mac_address} a activo=${activo}`
    });

    // Si se desactiva, enviar desconexión inmediata al router (CoA)
    if (!activo) {
      try {
        await db.disconnectRadiusClient(device.mac_address);
      } catch (coaErr) {
        console.warn(`[CoA] Error de desconexión al desactivar MAC bypass ${device.mac_address}:`, coaErr.message);
      }
    }

    res.json(updated);
  } catch (err) { next(err); }
});

// DELETE - Eliminar de la lista de bypass
router.delete('/api/mac-bypass/:id', requireAdmin, requireRol('operador'), async (req, res, next) => {
  try {
    const { id } = req.params;

    const device = await db.getMacBypassById(id);
    if (!device) {
      return res.status(404).json({ error: 'Dispositivo no encontrado.' });
    }

    await db.deleteMacBypass(id);

    await db.logAdminAudit({
      username: req.adminUser,
      ipAddress: getClientIp(req),
      accion: 'ELIMINAR_MAC_BYPASS',
      detalles: `Eliminó dispositivo de bypass: MAC ${device.mac_address}`
    });

    // Enviar desconexión inmediata al router (CoA)
    try {
      await db.disconnectRadiusClient(device.mac_address);
    } catch (coaErr) {
      console.warn(`[CoA] Error de desconexión al eliminar MAC bypass ${device.mac_address}:`, coaErr.message);
    }

    res.json({ ok: true });
  } catch (err) { next(err); }
});

// POST - Actualizar clave PPSK en lote
router.post('/api/mac-bypass/bulk-ppsk', requireAdmin, requireRol('operador'), async (req, res, next) => {
  try {
    const { ids, ppsk } = req.body;
    if (!ids || !Array.isArray(ids) || ids.length === 0) {
      return res.status(400).json({ error: 'Debe seleccionar al menos un dispositivo.' });
    }
    
    const cleanPpsk = ppsk ? String(ppsk).trim() : null;

    // Ejecutar actualización
    await db.bulkUpdateMacBypassPpsk(ids, cleanPpsk);

    // Intentar desconexión de red (CoA) en segundo plano para cada uno
    for (const id of ids) {
      db.getMacBypassById(id).then(dev => {
        if (dev) {
          db.disconnectRadiusClient(dev.mac_address).catch(coaErr => {
            console.warn(`[CoA] Error al desconectar ID ${id} en bulk PPSK:`, coaErr.message);
          });
        }
      }).catch(err => {
        console.error(`[DB] Error al buscar dispositivo ID ${id} para CoA:`, err.message);
      });
    }

    // Registrar auditoría
    await db.logAdminAudit({
      username: req.adminUser,
      ipAddress: getClientIp(req),
      accion: 'ACTUALIZAR_PPSK_BYPASS_LOTE',
      detalles: `Actualizó clave PPSK en lote para ${ids.length} dispositivos.`
    });

    res.json({ ok: true });
  } catch (err) { next(err); }
});

// POST - Actualizar VLAN en lote
router.post('/api/mac-bypass/bulk-vlan', requireAdmin, requireRol('operador'), async (req, res, next) => {
  try {
    const { ids, vlanId } = req.body;
    if (!ids || !Array.isArray(ids) || ids.length === 0) {
      return res.status(400).json({ error: 'Debe seleccionar al menos un dispositivo.' });
    }
    
    const parsedVlan = vlanId ? parseInt(vlanId) : null;
    const dbVlan = isNaN(parsedVlan) ? null : parsedVlan;

    // Ejecutar actualización
    await db.bulkUpdateMacBypassVlan(ids, dbVlan);

    // Intentar desconexión de red (CoA) en segundo plano para cada uno
    for (const id of ids) {
      db.getMacBypassById(id).then(dev => {
        if (dev) {
          db.disconnectRadiusClient(dev.mac_address).catch(coaErr => {
            console.warn(`[CoA] Error al desconectar ID ${id} en bulk VLAN:`, coaErr.message);
          });
        }
      }).catch(err => {
        console.error(`[DB] Error al buscar dispositivo ID ${id} para CoA:`, err.message);
      });
    }

    // Registrar auditoría
    await db.logAdminAudit({
      username: req.adminUser,
      ipAddress: getClientIp(req),
      accion: 'ACTUALIZAR_VLAN_BYPASS_LOTE',
      detalles: `Actualizó VLAN ID a ${dbVlan || 'ninguno'} en lote para ${ids.length} dispositivos.`
    });

    res.json({ ok: true });
  } catch (err) { next(err); }
});

// ── Hoteles: Gestión de Huéspedes ──────────────────────────────────────────

router.get('/api/hotel/guests', requireAdmin, async (req, res, next) => {
  try {
    const guests = await db.listHotelGuests();
    res.json(guests);
  } catch (err) { next(err); }
});

router.post('/api/hotel/guests', requireAdmin, async (req, res, next) => {
  try {
    const { habitacion, apellido, nombre, fecha_checkin, fecha_checkout, perfil_velocidad } = req.body;
    if (!habitacion || !apellido || !fecha_checkout) {
      return res.status(400).json({ error: 'Se requieren habitación, apellido y fecha de checkout.' });
    }
    const guest = await db.createHotelGuest({
      habitacion,
      apellido,
      nombre,
      fecha_checkin,
      fecha_checkout,
      perfil_velocidad
    });

    await db.logAdminAudit({
      username: req.adminUser,
      ipAddress: getClientIp(req),
      accion: 'CREAR_HUESPED',
      detalles: `Registró huésped de habitación ${habitacion} (Apellido: ${apellido}).`
    });

    res.json(guest);
  } catch (err) { next(err); }
});

router.delete('/api/hotel/guests/:id', requireAdmin, async (req, res, next) => {
  try {
    const guest = await db.deleteHotelGuest(req.params.id);
    if (!guest) {
      return res.status(404).json({ error: 'Huésped no encontrado.' });
    }

    await db.logAdminAudit({
      username: req.adminUser,
      ipAddress: getClientIp(req),
      accion: 'ELIMINAR_HUESPED',
      detalles: `Eliminó huésped de habitación ${guest.habitacion} (Apellido: ${guest.apellido}).`
    });

    res.json({ ok: true });
  } catch (err) { next(err); }
});

// ── Restaurante: Gestión de PINs ──────────────────────────────────────────

router.get('/api/restaurant/pins', requireAdmin, async (req, res, next) => {
  try {
    const pins = await db.listRestaurantPins();
    res.json(pins);
  } catch (err) { next(err); }
});

router.post('/api/restaurant/pins', requireAdmin, async (req, res, next) => {
  try {
    const { pin, duracion_minutos, limite_dispositivos, expira_el } = req.body;
    if (!pin) {
      return res.status(400).json({ error: 'El PIN es requerido.' });
    }
    const pinObj = await db.createRestaurantPin({
      pin,
      duracion_minutos,
      limite_dispositivos,
      expira_el
    });

    await db.logAdminAudit({
      username: req.adminUser,
      ipAddress: getClientIp(req),
      accion: 'CREAR_PIN_RESTAURANTE',
      detalles: `Creó PIN de ticket: ${pin} (Duración: ${duracion_minutos} min).`
    });

    res.json(pinObj);
  } catch (err) { next(err); }
});

router.delete('/api/restaurant/pins/:id', requireAdmin, async (req, res, next) => {
  try {
    const pinObj = await db.deleteRestaurantPin(req.params.id);
    if (!pinObj) {
      return res.status(404).json({ error: 'PIN no encontrado.' });
    }

    await db.logAdminAudit({
      username: req.adminUser,
      ipAddress: getClientIp(req),
      accion: 'ELIMINAR_PIN_RESTAURANTE',
      detalles: `Eliminó PIN de ticket: ${pinObj.pin}.`
    });

    res.json({ ok: true });
  } catch (err) { next(err); }
});

// GET - Obtener sesiones activas en tiempo real
router.get('/api/active-sessions', requireAdmin, async (req, res, next) => {
  try {
    const sessions = await db.getActiveSessions();
    res.json(sessions);
  } catch (err) { next(err); }
});

router.get('/api/wpa-enterprise/active', requireAdmin, async (req, res, next) => {
  try {
    // 1. Obtener sesiones activas con firma RADIUS (802.1X)
    const sessions = await db.getActiveWpaSessions();

    // 2. Resolver configuración LDAP
    let ldapServerUrl = process.env.LDAP_SERVER_URL;
    let ldapBindDN = process.env.LDAP_BIND_DN;
    let ldapBindPassword = process.env.LDAP_BIND_PASSWORD;
    let ldapSearchBase = process.env.LDAP_SEARCH_BASE;
    let ldapAllowedGroup = process.env.LDAP_ALLOWED_GROUP;

    try {
      const ldapConfig = await db.getControllerConfig('ldap');
      if (ldapConfig) {
        if (ldapConfig.ldapServerUrl) ldapServerUrl = ldapConfig.ldapServerUrl;
        if (ldapConfig.ldapBindDN) ldapBindDN = ldapConfig.ldapBindDN;
        if (ldapConfig.ldapBindCredentials) ldapBindPassword = ldapConfig.ldapBindCredentials;
        if (ldapConfig.ldapSearchBase) ldapSearchBase = ldapConfig.ldapSearchBase;
        if (ldapConfig.ldapAllowedGroup !== undefined) ldapAllowedGroup = ldapConfig.ldapAllowedGroup;
      }
    } catch (dbErr) {
      console.warn('[WPA-Active] No se pudo leer la configuración global de LDAP:', dbErr.message);
    }

    // Identificar grupos LDAP autorizados para WPA Enterprise (Global y específicos de VLAN)
    let targetGroups = [];
    if (ldapAllowedGroup && ldapAllowedGroup.trim()) {
      targetGroups.push(ldapAllowedGroup.trim().toLowerCase());
    }
    try {
      const vlanGroups = await db.listLdapGroupVlans();
      vlanGroups.forEach(g => {
        targetGroups.push(g.group_dn.trim().toLowerCase());
      });
    } catch (err) {
      console.warn('[WPA-Active] No se pudo leer ldap_group_vlans:', err.message);
    }

    // Eliminar duplicados de grupos
    const uniqueGroups = Array.from(new Set(targetGroups));

    // Si no hay grupos LDAP autorizados configurados o falta configuración de red, no podemos filtrar
    if (uniqueGroups.length === 0 || !ldapServerUrl || !ldapBindDN || !ldapSearchBase) {
      return res.json([]);
    }

    // 3. Consultar los nombres de usuario en vivo pertenecientes a esos grupos en Active Directory
    const allowedUsernames = new Set();
    const ldapSvc = require('../services/ldap');
    await Promise.all(uniqueGroups.map(async (groupDn) => {
      try {
        const list = await ldapSvc.getGroupMembers({
          url: ldapServerUrl,
          bindDN: ldapBindDN,
          bindPassword: ldapBindPassword,
          searchBase: ldapSearchBase,
          allowedGroup: groupDn
        });
        list.forEach(m => {
          if (m.username) {
            allowedUsernames.add(String(m.username).toLowerCase().trim());
          }
        });
      } catch (err) {
        console.warn(`[WPA-Active] Error al consultar miembros del grupo ${groupDn}:`, err.message);
      }
    }));

    // 4. Filtrar las sesiones activas para retornar únicamente las de los miembros de los grupos autorizados
    const result = sessions.filter(s => {
      const username = String(s.username).toLowerCase().trim();
      return allowedUsernames.has(username);
    });

    res.json(result);
  } catch (err) { next(err); }
});

// POST - Expulsar / Desconectar un usuario activo (Kick / CoA)
router.post('/api/active-sessions/kick', requireAdmin, async (req, res, next) => {
  try {
    const { mac } = req.body;
    if (!mac) {
      return res.status(400).json({ error: 'La dirección MAC es obligatoria.' });
    }

    const normalizedMac = mac.toUpperCase().replace(/:/g, '-');

    // 1. Desconectar vía CoA RADIUS
    const coaSuccess = await db.disconnectRadiusClient(normalizedMac);

    // 2. Desautorizar en Omada (desconectar del WiFi)
    let omadaSuccess = false;
    try {
      await omadaSvc.unauthorizeClient({ clientMac: normalizedMac });
      omadaSuccess = true;
      console.log(`[KICK] Omada unauthorize enviado para MAC ${normalizedMac}`);
    } catch (omadaErr) {
      console.error(`[KICK] Error Omada para ${normalizedMac}:`, omadaErr.message);
    }

    await db.logAdminAudit({
      username: req.adminUser,
      ipAddress: getClientIp(req),
      accion: 'EXPULSAR_SESION_ACTIVA',
      detalles: `Expulsó dispositivo MAC: ${normalizedMac} (CoA: ${coaSuccess}, Omada: ${omadaSuccess})`
    });

    res.json({ ok: true, coa: coaSuccess, omada: omadaSuccess });
  } catch (err) { next(err); }
});

function getCNFromDN(dn) {
  if (!dn) return '';
  const match = dn.match(/CN=([^,]+)/i);
  return match ? match[1] : dn;
}

// GET - Obtener miembros del grupo de Active Directory (LDAP) configurado
router.get('/api/ldap/group-members', requireAdmin, async (req, res, next) => {
  try {
    let ldapServerUrl = process.env.LDAP_SERVER_URL;
    let ldapBindDN = process.env.LDAP_BIND_DN;
    let ldapBindPassword = process.env.LDAP_BIND_PASSWORD;
    let ldapSearchBase = process.env.LDAP_SEARCH_BASE;
    let ldapAllowedGroup = process.env.LDAP_ALLOWED_GROUP;

    // Cargar config global del controlador ldap
    try {
      const ldapConfig = await db.getControllerConfig('ldap');
      if (ldapConfig) {
        if (ldapConfig.ldapServerUrl) ldapServerUrl = ldapConfig.ldapServerUrl;
        if (ldapConfig.ldapBindDN) ldapBindDN = ldapConfig.ldapBindDN;
        if (ldapConfig.ldapBindCredentials) ldapBindPassword = ldapConfig.ldapBindCredentials;
        if (ldapConfig.ldapSearchBase) ldapSearchBase = ldapConfig.ldapSearchBase;
        if (ldapConfig.ldapAllowedGroup !== undefined) ldapAllowedGroup = ldapConfig.ldapAllowedGroup;
      }
    } catch (dbErr) {
      console.warn('[LDAP-Members] No se pudo leer la configuración global de LDAP:', dbErr.message);
    }

    if (!ldapServerUrl || !ldapBindDN || !ldapSearchBase) {
      return res.json({ error: 'La conexión LDAP no está configurada.' });
    }

    // 1. Identificar grupos de WPA-Enterprise (Global y Tabla de VLANs)
    let targetGroups = [];
    if (ldapAllowedGroup && ldapAllowedGroup.trim()) {
      targetGroups.push({ group_dn: ldapAllowedGroup.trim(), source: 'Global' });
    }

    // Obtener grupos desde la tabla de VLANs
    try {
      const vlanGroups = await db.listLdapGroupVlans();
      vlanGroups.forEach(g => {
        targetGroups.push({ group_dn: g.group_dn, source: `VLAN ${g.vlan_id}` });
      });
    } catch (err) {
      console.warn('[LDAP-Members] No se pudo leer ldap_group_vlans:', err.message);
    }

    // Filtrar duplicados
    const uniqueGroups = [];
    const seen = new Set();
    targetGroups.forEach(g => {
      const lowerDn = g.group_dn.toLowerCase();
      if (!seen.has(lowerDn)) {
        seen.add(lowerDn);
        uniqueGroups.push(g);
      }
    });

    if (uniqueGroups.length === 0) {
      return res.json({ error: 'No hay grupos de seguridad de LDAP configurados para WPA-Enterprise.' });
    }

    // 2. Consultar mapeos de VLAN por grupo para cruce rápido
    let vlanMappings = [];
    try {
      vlanMappings = await db.listLdapGroupVlans();
    } catch (dbErr) {
      console.warn('[LDAP-Members] No se pudo leer la lista de mapeos de VLAN:', dbErr.message);
    }
    const vlanMap = new Map();
    vlanMappings.forEach(m => {
      vlanMap.set(m.group_dn.toLowerCase(), m.vlan_id);
    });

    // 3. Buscar miembros de cada grupo en paralelo y consolidar
    const allMembersMap = new Map();
    await Promise.all(uniqueGroups.map(async (g) => {
      try {
        const list = await ldapSvc.getGroupMembers({
          url: ldapServerUrl,
          bindDN: ldapBindDN,
          bindPassword: ldapBindPassword,
          searchBase: ldapSearchBase,
          allowedGroup: g.group_dn
        });
        
        list.forEach(m => {
          const lowerUser = String(m.username).toLowerCase();
          const mappedVlan = vlanMap.get(g.group_dn.toLowerCase());
          
          if (!allMembersMap.has(lowerUser)) {
            allMembersMap.set(lowerUser, {
              ...m,
              grupoDn: g.group_dn,
              grupoCn: getCNFromDN(g.group_dn),
              vlanId: mappedVlan || null,
              ssidName: null
            });
          }
        });
      } catch (err) {
        console.warn(`[LDAP-Members] Error al buscar miembros del grupo ${g.group_dn}:`, err.message);
      }
    }));

    const members = Array.from(allMembersMap.values());

    // Obtener sesiones activas para cruzar conexión (solo la más reciente por usuario)
    // La query ordena por acctstarttime DESC, así que la primera es la más reciente
    const activeSessions = await db.getActiveSessions();
    const activeSessionsMap = new Map();
    activeSessions.forEach(s => {
      const key = String(s.username).toLowerCase();
      if (!activeSessionsMap.has(key)) {
        activeSessionsMap.set(key, {
          macAddress: s.mac_address,
          ipAddress: s.ip_address,
          startTime: s.start_time
        });
      }
    });

    // Consultar estado local de estos usuarios
    const usernames = members.map(m => String(m.username).toLowerCase());
    let localUsers = [];
    if (usernames.length > 0) {
      try {
        localUsers = await db.getUsersLocalStatus(usernames);
      } catch (dbErr) {
        console.error('[LDAP-Members] Error al consultar estados locales en la base de datos:', dbErr.message);
      }
    }
    const localActiveMap = new Map();
    localUsers.forEach(u => {
      localActiveMap.set(String(u.cedula).toLowerCase(), u.activo === true);
    });

    // Batch: obtener VLAN individual, dispositivos y límite para todos los usuarios
    const userVlanMap = new Map();
    const userDevicesMap = new Map();
    const userMaxMap = new Map();
    if (usernames.length > 0) {
      try {
        const vlanResult = await db.getPool().query(
          `SELECT username, value AS vlan_id FROM radreply
           WHERE attribute = 'Tunnel-Private-Group-ID'
             AND username = ANY($1)`,
          [usernames]
        );
        vlanResult.rows.forEach(r => {
          userVlanMap.set(String(r.username).toLowerCase(), parseInt(r.vlan_id, 10));
        });

        const devicesResult = await db.getPool().query(
          `SELECT username, COUNT(*)::int AS device_count
           FROM wpa_enterprise_devices
           WHERE username = ANY($1)
           GROUP BY username`,
          [usernames]
        );
        devicesResult.rows.forEach(r => {
          userDevicesMap.set(String(r.username).toLowerCase(), r.device_count);
        });

        // Contar sesiones activas de WPA Enterprise (radacct) por usuario
        const sessionsResult = await db.getPool().query(
          `SELECT username, COUNT(*)::int AS active_count
           FROM radacct
           WHERE acctstoptime IS NULL
             AND acctauthentic = 'RADIUS'
             AND username = ANY($1)
           GROUP BY username`,
          [usernames]
        );
        sessionsResult.rows.forEach(r => {
          const key = String(r.username).toLowerCase();
          const registered = userDevicesMap.get(key) || 0;
          userDevicesMap.set(key, registered + r.active_count);
        });

        const maxResult = await db.getPool().query(
          `SELECT cedula, max_dispositivos_wpa
           FROM usuarios_portal
           WHERE cedula = ANY($1)`,
          [usernames]
        );
        maxResult.rows.forEach(r => {
          userMaxMap.set(String(r.cedula).toLowerCase(), r.max_dispositivos_wpa);
        });
      } catch (dbErr) {
        console.error('[LDAP-Members] Error en queries batch:', dbErr.message);
      }
    }

    const result = members.map(m => {
      const lowerUser = String(m.username).toLowerCase();
      const session = activeSessionsMap.get(lowerUser);
      return {
        ...m,
        activo: localActiveMap.has(lowerUser) ? localActiveMap.get(lowerUser) : true,
        isConnected: !!session,
        session: session || null,
        userVlan: userVlanMap.get(lowerUser) || null,
        deviceCount: userDevicesMap.get(lowerUser) || 0,
        maxDispositivos: userMaxMap.get(lowerUser) || 0
      };
    });

    res.json(result);
  } catch (err) {
    res.status(500).json({ error: 'Error al consultar miembros de AD: ' + err.message });
  }
});

// GET - Obtener miembros de los grupos de LDAP autorizados para los portales cautivos (SSID)
router.get('/api/ldap/portal-members', requireAdmin, async (req, res, next) => {
  try {
    let ldapServerUrl = process.env.LDAP_SERVER_URL;
    let ldapBindDN = process.env.LDAP_BIND_DN;
    let ldapBindPassword = process.env.LDAP_BIND_PASSWORD;
    let ldapSearchBase = process.env.LDAP_SEARCH_BASE;
    let ldapAllowedGroup = process.env.LDAP_ALLOWED_GROUP;

    try {
      const ldapConfig = await db.getControllerConfig('ldap');
      if (ldapConfig) {
        if (ldapConfig.ldapServerUrl) ldapServerUrl = ldapConfig.ldapServerUrl;
        if (ldapConfig.ldapBindDN) ldapBindDN = ldapConfig.ldapBindDN;
        if (ldapConfig.ldapBindCredentials) ldapBindPassword = ldapConfig.ldapBindCredentials;
        if (ldapConfig.ldapSearchBase) ldapSearchBase = ldapConfig.ldapSearchBase;
        if (ldapConfig.ldapAllowedGroup !== undefined) ldapAllowedGroup = ldapConfig.ldapAllowedGroup;
      }
    } catch (dbErr) {
      console.warn('[LDAP-Portal-Members] No se pudo leer la configuración global de LDAP:', dbErr.message);
    }

    if (!ldapServerUrl || !ldapBindDN || !ldapSearchBase) {
      return res.json({ error: 'La conexión LDAP no está configurada.' });
    }

    // 1. Identificar grupos LDAP configurados en los SSIDs
    let targetGroups = [];
    
    // Obtener grupos desde ssid_config
    try {
      const ssids = await db.listAllSsidConfigs();
      ssids.forEach(s => {
        const sc = s.config || {};
        if (s.auth_type === 'ldap') {
          const group = sc.ldapAllowedGroup && sc.ldapAllowedGroup.trim() ? sc.ldapAllowedGroup.trim() : (ldapAllowedGroup && ldapAllowedGroup.trim() ? ldapAllowedGroup.trim() : '');
          if (group) {
            targetGroups.push({ group_dn: group, ssidName: s.ssid_name });
          }
        }
      });
    } catch (err) {
      console.warn('[LDAP-Portal-Members] No se pudo leer ssid_config:', err.message);
    }

    // Filtrar duplicados
    const groupSsidMap = new Map();
    targetGroups.forEach(g => {
      const key = g.group_dn.toLowerCase();
      if (!groupSsidMap.has(key)) {
        groupSsidMap.set(key, { group_dn: g.group_dn, ssids: new Set() });
      }
      groupSsidMap.get(key).ssids.add(g.ssidName);
    });

    const uniqueGroups = Array.from(groupSsidMap.values());

    if (uniqueGroups.length === 0) {
      return res.json([]);
    }

    // 2. Buscar miembros de cada grupo en AD
    const allMembersMap = new Map();
    await Promise.all(uniqueGroups.map(async (g) => {
      try {
        const list = await ldapSvc.getGroupMembers({
          url: ldapServerUrl,
          bindDN: ldapBindDN,
          bindPassword: ldapBindPassword,
          searchBase: ldapSearchBase,
          allowedGroup: g.group_dn
        });
        
        list.forEach(m => {
          const lowerUser = String(m.username).toLowerCase();
          const ssidList = Array.from(g.ssids).join(', ');
          
          if (!allMembersMap.has(lowerUser)) {
            allMembersMap.set(lowerUser, {
              ...m,
              grupoDn: g.group_dn,
              grupoCn: getCNFromDN(g.group_dn),
              ssidName: ssidList,
              vlanId: null
            });
          } else {
            const existing = allMembersMap.get(lowerUser);
            const set = new Set(existing.ssidName.split(', '));
            g.ssids.forEach(s => set.add(s));
            existing.ssidName = Array.from(set).join(', ');
          }
        });
      } catch (err) {
        console.warn(`[LDAP-Portal-Members] Error al buscar miembros del grupo ${g.group_dn}:`, err.message);
      }
    }));

    const members = Array.from(allMembersMap.values());

    // Obtener sesiones activas para cruzar conexión (solo la más reciente por usuario)
    // La query ordena por acctstarttime DESC, así que la primera es la más reciente
    const activeSessions = await db.getActiveSessions();
    const activeSessionsMap = new Map();
    activeSessions.forEach(s => {
      const key = String(s.username).toLowerCase();
      if (!activeSessionsMap.has(key)) {
        activeSessionsMap.set(key, {
          macAddress: s.mac_address,
          ipAddress: s.ip_address,
          startTime: s.start_time
        });
      }
    });

    // Consultar estado local de estos usuarios
    const usernames = members.map(m => String(m.username).toLowerCase());
    let localUsers = [];
    if (usernames.length > 0) {
      try {
        localUsers = await db.getUsersLocalStatus(usernames);
      } catch (dbErr) {
        console.error('[LDAP-Portal-Members] Error al consultar estados locales:', dbErr.message);
      }
    }
    const localActiveMap = new Map();
    localUsers.forEach(u => {
      localActiveMap.set(String(u.cedula).toLowerCase(), u.activo === true);
    });

    // Batch: obtener VLAN individual, dispositivos y límite
    const userVlanMap = new Map();
    const userDevicesMap = new Map();
    const userMaxMap = new Map();
    if (usernames.length > 0) {
      try {
        const vlanResult = await db.getPool().query(
          `SELECT username, value AS vlan_id FROM radreply WHERE attribute = 'Tunnel-Private-Group-ID' AND username = ANY($1)`,
          [usernames]
        );
        vlanResult.rows.forEach(r => userVlanMap.set(String(r.username).toLowerCase(), parseInt(r.vlan_id, 10)));

        const devicesResult = await db.getPool().query(
          `SELECT username, COUNT(*)::int AS device_count FROM wpa_enterprise_devices WHERE username = ANY($1) GROUP BY username`,
          [usernames]
        );
        devicesResult.rows.forEach(r => userDevicesMap.set(String(r.username).toLowerCase(), r.device_count));

        const maxResult = await db.getPool().query(
          `SELECT cedula, max_dispositivos_wpa FROM usuarios_portal WHERE cedula = ANY($1)`,
          [usernames]
        );
        maxResult.rows.forEach(r => userMaxMap.set(String(r.cedula).toLowerCase(), r.max_dispositivos_wpa));
      } catch (dbErr) {
        console.error('[Portal-Members] Error en queries batch:', dbErr.message);
      }
    }

    const result = members.map(m => {
      const lowerUser = String(m.username).toLowerCase();
      const session = activeSessionsMap.get(lowerUser);
      return {
        ...m,
        activo: localActiveMap.has(lowerUser) ? localActiveMap.get(lowerUser) : true,
        isConnected: !!session,
        session: session || null,
        userVlan: userVlanMap.get(lowerUser) || null,
        deviceCount: userDevicesMap.get(lowerUser) || 0,
        maxDispositivos: userMaxMap.get(lowerUser) || 0
      };
    });

    res.json(result);
  } catch (err) {
    res.status(500).json({ error: 'Error al consultar miembros de portal: ' + err.message });
  }
});

async function ensureLdapUserExists(username, defaultType = 'wpa_enterprise') {
  const normalized = username.trim().toLowerCase();
  let user = await db.getUserByCedula(normalized);
  if (!user) {
    let userDetails = { nombres: username, apellidos: '', email: `${username}@ldap.local` };
    try {
      const ldapConfig = await db.getControllerConfig('ldap');
      if (ldapConfig) {
        const adUser = await ldapSvc.searchUser({
          url: ldapConfig.ldapServerUrl,
          bindDN: ldapConfig.ldapBindDN,
          bindPassword: ldapConfig.ldapBindCredentials,
          searchBase: ldapConfig.ldapSearchBase,
          username: normalized
        });
        if (adUser) {
          userDetails = adUser;
        }
      }
    } catch (ldapErr) {
      console.warn('[LDAP-Ensure] No se pudo resolver datos en AD:', ldapErr.message);
    }

    user = await db.createUser({
      cedula: normalized,
      nombres: userDetails.nombres,
      apellidos: userDetails.apellidos,
      email: userDetails.email,
      terminosAceptados: 'Creado automáticamente por Admin',
      tipo_usuario: defaultType
    });
  }
  return user;
}

// PUT - Activar/Desactivar localmente un usuario de LDAP/AD
router.put('/api/ldap/users/:username/status', requireAdmin,
  body('active').isBoolean(),
  async (req, res, next) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) return res.status(400).json({ error: 'El parámetro active debe ser un booleano.' });

      const { username } = req.params;
      const { active, tipo_usuario } = req.body;
      const normalized = username.trim().toLowerCase();

      // Asegurar existencia local del usuario de AD
      await ensureLdapUserExists(normalized, tipo_usuario || 'wpa_enterprise');

      // 2. Modificar estado
      await db.bulkUpdateUserActive([normalized], active);

      // Auditoría
      const clientIp = getClientIp(req);
      await db.logAdminAudit({
        username: req.adminUser,
        ipAddress: clientIp,
        accion: active ? 'ACTIVAR_USUARIO_LDAP' : 'DESACTIVAR_USUARIO_LDAP',
        detalles: `Modificó estado de usuario LDAP ${normalized} a activo=${active}`
      });

      // Si se desactiva, expulsar sus sesiones activas de red
      if (!active) {
        // 1. Dispositivos de portal cautivo (dispositivos_usuario)
        const userDevices = await db.getUserDevices(normalized);
        for (const d of userDevices) {
          await db.disconnectRadiusClient(d.mac_address).catch(() => {});
        }
        // 2. Sesiones activas WPA Enterprise (radacct) — CoA + Omada
        const activeSessions = await db.getActiveSessions();
        const userSessions = activeSessions
          .filter(s => String(s.username).toLowerCase() === normalized);
        for (const s of userSessions) {
          // CoA disconnect
          db.disconnectRadiusClient(s.mac_address).catch(() => {});
          // Omada unauthorize
          omadaSvc.unauthorizeClient({ clientMac: s.mac_address }).catch(() => {});
        }
      }

      res.json({ success: true });
    } catch (err) { next(err); }
  }
);

// GET - Obtener todos los mapeos de grupos LDAP a VLANs
router.get('/api/ldap/group-vlans', requireAdmin, async (req, res, next) => {
  try {
    const list = await db.listLdapGroupVlans();
    res.json(list);
  } catch (err) { next(err); }
});

// POST - Crear o actualizar un mapeo de grupo LDAP a VLAN
router.post('/api/ldap/group-vlans', requireAdmin,
  body('group_dn').isString().trim().notEmpty().withMessage('El DN del grupo es obligatorio.'),
  body('vlan_id').isInt({ min: 1, max: 4094 }).withMessage('El ID de VLAN debe ser un número entre 1 y 4094.'),
  async (req, res, next) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({ error: errors.array().map(e => e.msg).join(', ') });
      }

      const { group_dn, vlan_id } = req.body;
      const mapping = await db.createLdapGroupVlan(group_dn, vlan_id);

      // Auditoría
      await db.logAdminAudit({
        username: req.adminUser,
        ipAddress: getClientIp(req),
        accion: 'CREAR_MAPEO_VLAN_LDAP',
        detalles: `Creó/Actualizó mapeo de VLAN ${vlan_id} para el grupo LDAP: ${group_dn}`
      });

      res.status(201).json(mapping);
    } catch (err) { next(err); }
  }
);

// DELETE - Eliminar un mapeo de grupo LDAP a VLAN
router.delete('/api/ldap/group-vlans/:id', requireAdmin, async (req, res, next) => {
  try {
    const id = parseInt(req.params.id);
    if (isNaN(id)) return res.status(400).json({ error: 'ID de mapeo inválido.' });

    const deleted = await db.deleteLdapGroupVlan(id);
    if (!deleted) return res.status(404).json({ error: 'Mapeo no encontrado.' });

    // Auditoría
    await db.logAdminAudit({
      username: req.adminUser,
      ipAddress: getClientIp(req),
      accion: 'ELIMINAR_MAPEO_VLAN_LDAP',
      detalles: `Eliminó mapeo de VLAN ${deleted.vlan_id} para el grupo LDAP: ${deleted.group_dn}`
    });

    res.json({ success: true });
  } catch (err) { next(err); }
});

// ─── WPA Enterprise: VLAN Individual, Dispositivos y Límites ─────────────────

// PUT - Asignar VLAN individual a usuario WPA Enterprise
router.put('/api/ldap/users/:username/vlan', requireAdmin,
  param('username').isString().trim().notEmpty(),
  body('vlan_id').isInt({ min: 1, max: 4094 }),
  async (req, res, next) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({ error: 'Datos inválidos. VLAN debe ser 1-4094.' });
      }
      const { username } = req.params;
      const { vlan_id } = req.body;
      const normalized = username.trim().toLowerCase();

      await ensureLdapUserExists(normalized, 'wpa_enterprise');
      await db.setUserVlan(normalized, vlan_id);

      await db.logAdminAudit({
        username: req.adminUser,
        ipAddress: getClientIp(req),
        accion: 'ASIGNAR_VLAN_WPA',
        detalles: `Asignó VLAN ${vlan_id} al usuario WPA: ${normalized}`
      });

      res.json({ success: true, vlan_id });
    } catch (err) { next(err); }
  }
);

// DELETE - Quitar VLAN individual (revertir a grupo AD)
router.delete('/api/ldap/users/:username/vlan', requireAdmin,
  param('username').isString().trim().notEmpty(),
  async (req, res, next) => {
    try {
      const { username } = req.params;
      const normalized = username.trim().toLowerCase();

      await ensureLdapUserExists(normalized, 'wpa_enterprise');
      await db.clearUserVlan(normalized);

      await db.logAdminAudit({
        username: req.adminUser,
        ipAddress: getClientIp(req),
        accion: 'LIMPIAR_VLAN_WPA',
        detalles: `Eliminó VLAN individual del usuario WPA: ${normalized}`
      });

      res.json({ success: true });
    } catch (err) { next(err); }
  }
);

// GET - Obtener VLAN individual de usuario WPA Enterprise
router.get('/api/ldap/users/:username/vlan', requireAdmin,
  param('username').isString().trim().notEmpty(),
  async (req, res, next) => {
    try {
      const { username } = req.params;
      const vlanId = await db.getUserVlan(username);
      res.json({ vlan_id: vlanId });
    } catch (err) { next(err); }
  }
);

// GET - Listar dispositivos WPA Enterprise de un usuario
// Incluye dispositivos registrados (wpa_enterprise_devices) + sesiones activas (radacct)
router.get('/api/ldap/users/:username/devices', requireAdmin,
  param('username').isString().trim().notEmpty(),
  async (req, res, next) => {
    try {
      const { username } = req.params;
      const registeredDevices = await db.getWpaDevices(username);
      const max = await db.getWpaUserMaxDevices(username);

      // Obtener sesiones activas de radacct para este usuario
      const activeSessions = await db.getActiveSessions();
      const userActiveSessions = activeSessions
        .filter(s => String(s.username).toLowerCase() === username.toLowerCase())
        .map(s => ({
          mac_address: s.mac_address,
          ip_address: s.ip_address,
          start_time: s.start_time,
          source: 'session'
        }));

      // Combinar: dispositivos registrados + sesiones activas (evitar duplicados por MAC)
      const registeredMacs = new Set(registeredDevices.map(d => d.mac_address));
      const combined = [...registeredDevices];
      userActiveSessions.forEach(s => {
        if (!registeredMacs.has(s.mac_address)) {
          combined.push({
            id: null,
            username,
            mac_address: s.mac_address,
            ip_address: s.ip_address,
            created_at: s.start_time,
            source: 'session'
          });
        }
      });

      res.json({ devices: combined, max_dispositivos: max, deviceCount: combined.length });
    } catch (err) { next(err); }
  }
);

// POST - Registrar dispositivo WPA Enterprise (+ CoA eviction si excede límite)
router.post('/api/ldap/users/:username/devices', requireAdmin,
  param('username').isString().trim().notEmpty(),
  body('mac_address').isString().trim().matches(/^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$/),
  async (req, res, next) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({ error: 'MAC address inválida.' });
      }
      const { username } = req.params;
      const mac = req.body.mac_address.toUpperCase().replace(/:/g, '-');
      const normalized = username.trim().toLowerCase();

      await ensureLdapUserExists(normalized, 'wpa_enterprise');

      // Verificar que la MAC no esté registrada en otro tipo de autenticación
      const conflict = await db.isMacRegisteredInOtherType(mac, 'wpa');
      if (conflict) {
        return res.status(409).json({
          error: `La MAC ${mac} ya está registrada como dispositivo de ${conflict.type === 'captive' ? 'portal cautivo' : 'WPA Enterprise'} por el usuario ${conflict.username}.`
        });
      }

      // Registrar el dispositivo
      const device = await db.registerWpaDevice(normalized, mac);

      // Verificar límite y desconectar el más antiguo si excede
      const max = await db.getWpaUserMaxDevices(normalized);
      if (max > 0) {
        const count = await db.getWpaDeviceCount(normalized);
        if (count > max) {
          const oldest = await db.getOldestWpaDevice(normalized);
          if (oldest && oldest.mac_address !== mac) {
            console.log(`[WPA-LIMIT] Límite excedido para ${normalized} (${count}/${max}). Desconectando MAC más antigua: ${oldest.mac_address}`);
            try {
              await db.disconnectRadiusClient(oldest.mac_address);
            } catch (coaErr) {
              console.error(`[WPA-LIMIT] Error CoA para ${oldest.mac_address}:`, coaErr.message);
            }
            await db.deleteWpaDevice(normalized, oldest.mac_address);
          }
        }
      }

      await db.logAdminAudit({
        username: req.adminUser,
        ipAddress: getClientIp(req),
        accion: 'REGISTRAR_DISPOSITIVO_WPA',
        detalles: `Registró dispositivo ${mac} para usuario WPA: ${normalized}`
      });

      res.json({ success: true, device });
    } catch (err) { next(err); }
  }
);

// DELETE - Eliminar dispositivo WPA Enterprise + CoA disconnect
router.delete('/api/ldap/users/:username/devices/:mac', requireAdmin,
  param('username').isString().trim().notEmpty(),
  param('mac').isString().trim(),
  async (req, res, next) => {
    try {
      const { username, mac } = req.params;
      const normalized = username.trim().toLowerCase();
      const normalizedMac = mac.toUpperCase().replace(/:/g, '-');

      await ensureLdapUserExists(normalized, 'wpa_enterprise');

      // Eliminar de la base de datos
      await db.deleteWpaDevice(normalized, normalizedMac);

      // Intentar desconectar vía CoA si hay sesión activa
      try {
        await db.disconnectRadiusClient(normalizedMac);
        console.log(`[WPA-DELETE] CoA disconnect enviado para MAC ${normalizedMac}`);
      } catch (coaErr) {
        console.error(`[WPA-DELETE] Error CoA para ${normalizedMac}:`, coaErr.message);
      }

      await db.logAdminAudit({
        username: req.adminUser,
        ipAddress: getClientIp(req),
        accion: 'ELIMINAR_DISPOSITIVO_WPA',
        detalles: `Eliminó dispositivo ${normalizedMac} del usuario WPA: ${normalized}`
      });

      res.json({ success: true });
    } catch (err) { next(err); }
  }
);

// PUT - Establecer límite de dispositivos WPA Enterprise
router.put('/api/ldap/users/:username/max-devices', requireAdmin,
  param('username').isString().trim().notEmpty(),
  body('max').isInt({ min: 0, max: 100 }),
  async (req, res, next) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({ error: 'Valor de límite inválido (0-100).' });
      }
      const { username } = req.params;
      const { max } = req.body;
      const normalized = username.trim().toLowerCase();

      await ensureLdapUserExists(normalized, 'wpa_enterprise');
      await db.setWpaUserMaxDevices(normalized, max);

      await db.logAdminAudit({
        username: req.adminUser,
        ipAddress: getClientIp(req),
        accion: 'SET_WPA_MAX_DEVICES',
        detalles: `Límite de dispositivos WPA para ${normalized}: ${max === 0 ? 'sin límite' : max}`
      });

      res.json({ success: true, max_dispositivos: max });
    } catch (err) { next(err); }
  }
);

// GET - Obtener límite de dispositivos WPA Enterprise
router.get('/api/ldap/users/:username/max-devices', requireAdmin,
  param('username').isString().trim().notEmpty(),
  async (req, res, next) => {
    try {
      const { username } = req.params;
      const max = await db.getWpaUserMaxDevices(username);
      res.json({ max_dispositivos: max });
    } catch (err) { next(err); }
  }
);

// DELETE - Remover usuario del grupo AD de WPA Enterprise
router.delete('/api/ldap/users/:username/remove-from-group', requireAdmin,
  param('username').isString().trim().notEmpty(),
  async (req, res, next) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) return res.status(400).json({ error: 'Nombre de usuario inválido.' });

      const { username } = req.params;
      const normalized = username.trim().toLowerCase();

      // Resolver config LDAP
      let ldapServerUrl = process.env.LDAP_SERVER_URL;
      let ldapBindDN = process.env.LDAP_BIND_DN;
      let ldapBindPassword = process.env.LDAP_BIND_PASSWORD;
      let ldapSearchBase = process.env.LDAP_SEARCH_BASE;
      let ldapAllowedGroup = process.env.LDAP_ALLOWED_GROUP;

      try {
        const ldapConfig = await db.getControllerConfig('ldap');
        if (ldapConfig) {
          if (ldapConfig.ldapServerUrl) ldapServerUrl = ldapConfig.ldapServerUrl;
          if (ldapConfig.ldapBindDN) ldapBindDN = ldapConfig.ldapBindDN;
          if (ldapConfig.ldapBindCredentials) ldapBindPassword = ldapConfig.ldapBindCredentials;
          if (ldapConfig.ldapSearchBase) ldapSearchBase = ldapConfig.ldapSearchBase;
          if (ldapConfig.ldapAllowedGroup !== undefined) ldapAllowedGroup = ldapConfig.ldapAllowedGroup;
        }
      } catch (dbErr) {
        console.warn('[LDAP-RemoveGroup] No se pudo leer config LDAP:', dbErr.message);
      }

      if (!ldapServerUrl || !ldapBindDN || !ldapSearchBase || !ldapAllowedGroup) {
        return res.status(400).json({ error: 'La configuración LDAP no está completa.' });
      }

      const result = await ldapSvc.removeFromGroup({
        url: ldapServerUrl,
        bindDN: ldapBindDN,
        bindPassword: ldapBindPassword,
        searchBase: ldapSearchBase,
        groupDN: ldapAllowedGroup.trim(),
        username: normalized
      });

      if (!result.success) {
        return res.status(404).json({ error: result.error });
      }

      await db.logAdminAudit({
        username: req.adminUser,
        ipAddress: getClientIp(req),
        accion: 'REMOVER_USUARIO_GRUPO_AD',
        detalles: `Removió usuario ${normalized} del grupo AD: ${ldapAllowedGroup.trim()}`
      });

      res.json({ success: true, message: `Usuario ${normalized} removido del grupo de Active Directory.` });
    } catch (err) { next(err); }
  }
);

// GET - Listar todos los dispositivos WPA Enterprise (global)
router.get('/api/wpa-devices', requireAdmin,
  query('limit').optional().isInt({ min: 1, max: 200 }).toInt(),
  query('offset').optional().isInt({ min: 0 }).toInt(),
  async (req, res, next) => {
    try {
      const limit = req.query.limit || 50;
      const offset = req.query.offset || 0;
      const result = await db.getAllWpaDevices(offset, limit);
      res.json(result);
    } catch (err) { next(err); }
  }
);

// GET - Resolver nombre de propietario desde servidores externos (SECAP o LDAP)
router.get('/api/mac-bypass/resolve-owner', requireAdmin, async (req, res, next) => {
  try {
    const identifier = String(req.query.identifier || '').trim();
    if (!identifier) {
      return res.status(400).json({ error: 'El identificador (cédula o usuario) es obligatorio.' });
    }

    // 1. Si son 10 dígitos, consultar SECAP (Registro Civil)
    if (/^\d{10}$/.test(identifier)) {
      const result = await externalApi.querySecapCivilRegistry(identifier);
      if (result.success) {
        return res.json({
          source: 'secap',
          nombres: result.nombres,
          apellidos: result.apellidos,
          nombreCompleto: `${result.nombres} ${result.apellidos}`.trim()
        });
      } else {
        return res.status(400).json({ error: result.error || 'Cédula no encontrada en el Registro Civil.' });
      }
    }

    // 2. Si es texto, consultar LDAP / Active Directory
    let ldapServerUrl = process.env.LDAP_SERVER_URL;
    let ldapBindDN = process.env.LDAP_BIND_DN;
    let ldapBindPassword = process.env.LDAP_BIND_PASSWORD;
    let ldapSearchBase = process.env.LDAP_SEARCH_BASE;

    // Cargar config global del controlador ldap
    try {
      const ldapConfig = await db.getControllerConfig('ldap');
      if (ldapConfig) {
        if (ldapConfig.ldapServerUrl) ldapServerUrl = ldapConfig.ldapServerUrl;
        if (ldapConfig.ldapBindDN) ldapBindDN = ldapConfig.ldapBindDN;
        if (ldapConfig.ldapBindCredentials) ldapBindPassword = ldapConfig.ldapBindCredentials;
        if (ldapConfig.ldapSearchBase) ldapSearchBase = ldapConfig.ldapSearchBase;
      }
    } catch (dbErr) {
      console.warn('[Resolve-Owner] No se pudo leer la configuración global de LDAP:', dbErr.message);
    }

    if (!ldapServerUrl || !ldapBindDN || !ldapSearchBase) {
      return res.status(400).json({ error: 'El servidor LDAP no está configurado en el sistema.' });
    }

    try {
      const result = await ldapSvc.searchUser({
        url: ldapServerUrl,
        bindDN: ldapBindDN,
        bindPassword: ldapBindPassword,
        searchBase: ldapSearchBase,
        username: identifier
      });

      if (result) {
        return res.json({
          source: 'ldap',
          nombres: result.nombres,
          apellidos: result.apellidos,
          nombreCompleto: `${result.nombres} ${result.apellidos}`.trim()
        });
      } else {
        return res.status(404).json({ error: 'Usuario no encontrado en el servidor LDAP.' });
      }
    } catch (ldapErr) {
      return res.status(500).json({ error: 'Error al conectar con el servidor LDAP: ' + ldapErr.message });
    }
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

router.post('/api/ssl', requireAdmin, requireRol('superadministrador'), async (req, res, next) => {
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
    fs.chmodSync(path.join(sslDir, 'portal.crt'), 0o640);
    fs.chmodSync(path.join(sslDir, 'portal.key'), 0o640);
    fs.writeFileSync(path.join(sslDir, '.reload'), new Date().toISOString(), 'utf8');

    console.log('[SSL] Nuevos certificados cargados con éxito. Solicitando recarga de Nginx...');
    res.json({ ok: true });
  } catch (err) {
    next(err);
  }
});

router.post('/api/wpa-certs', requireAdmin, requireRol('superadministrador'), async (req, res, next) => {
  try {
    const { ca, cert, key, pem } = req.body;
    console.log('[WPA-Certs] Intento de carga de certificados. ca:', ca ? ca.length : 0, 'cert:', cert ? cert.length : 0, 'key:', key ? key.length : 0, 'pem:', pem ? pem.length : 0);

    if (!ca || !cert || !key || !pem) {
      return res.status(400).json({ error: 'Se requieren los cuatro archivos: CA (ca.pem), Servidor (server.crt), Clave Privada (server.key) y Combined PEM (server.pem).' });
    }

    // Validar formato PEM
    if (!ca.includes('-----BEGIN CERTIFICATE-----')) {
      return res.status(400).json({ error: 'El archivo de la CA no es un certificado PEM válido.' });
    }
    if (!cert.includes('-----BEGIN CERTIFICATE-----')) {
      return res.status(400).json({ error: 'El certificado del servidor no es un certificado PEM válido.' });
    }
    if (!key.includes('-----BEGIN') || !key.includes('KEY')) {
      return res.status(400).json({ error: 'La clave privada del servidor no es una clave PEM válida.' });
    }
    if (!pem.includes('-----BEGIN')) {
      return res.status(400).json({ error: 'El archivo Combined PEM no es un archivo PEM válido.' });
    }

    const certsDir = '/app/freeradius-certs';
    if (!fs.existsSync(certsDir)) {
      fs.mkdirSync(certsDir, { recursive: true });
    }

    const cleanCa = sanitizePem(ca);
    const cleanCert = sanitizePem(cert);
    const cleanKey = sanitizePem(key);
    const cleanPem = sanitizePem(pem);

    // Guardar archivos
    fs.writeFileSync(path.join(certsDir, 'ca.pem'), cleanCa, 'utf8');
    fs.writeFileSync(path.join(certsDir, 'server.crt'), cleanCert, 'utf8');
    fs.writeFileSync(path.join(certsDir, 'server.key'), cleanKey, 'utf8');
    fs.writeFileSync(path.join(certsDir, 'server.pem'), cleanPem, 'utf8');

    // Cambiar permisos
    try {
      fs.chmodSync(path.join(certsDir, 'server.key'), 0o640);
      fs.chmodSync(path.join(certsDir, 'server.crt'), 0o644);
      fs.chmodSync(path.join(certsDir, 'ca.pem'), 0o644);
      fs.chmodSync(path.join(certsDir, 'server.pem'), 0o644);
    } catch (chmodErr) {
      console.warn('[WPA-Certs] No se pudo ajustar los permisos de los certificados:', chmodErr.message);
    }

    // Notificar al contenedor freeradius escribiendo el archivo reload
    fs.writeFileSync(path.join(certsDir, '.reload'), new Date().toISOString(), 'utf8');

    console.log('[WPA-Certs] Nuevos certificados WPA-Enterprise cargados con éxito.');
    res.json({ ok: true });
  } catch (err) {
    next(err);
  }
});

// ─── Base de Datos Externa (PostgreSQL) ───────────────────────────────────────

const { Client } = require('pg');

// GET — obtener configuración de base de datos externa
router.get('/api/external-db/config', requireAdmin, requireRol('superadministrador'), async (req, res, next) => {
  try {
    const config = await db.getControllerConfig('external_db_config') || {};
    res.json({
      enabled:      config.enabled || false,
      host:         config.host || '',
      port:         config.port || 5432,
      database:     config.database || '',
      user:         config.user || '',
      password:     '',
      ssl:          config.ssl || false,
      tableName:    config.tableName || '',
      colCedula:    config.colCedula || '',
      colNombres:   config.colNombres || '',
      colApellidos: config.colApellidos || '',
      colEmail:     config.colEmail || '',
      colStatus:    config.colStatus || '',
      allowManualRegistration: config.allowManualRegistration !== false && config.allowManualRegistration !== 'false',
    });
  } catch (err) { next(err); }
});

// PUT — guardar configuración de base de datos externa
router.put('/api/external-db/config', requireAdmin, requireRol('superadministrador'), async (req, res, next) => {
  try {
    const input = req.body;
    const existing = await db.getControllerConfig('external_db_config') || {};
    const newCfg = {
      enabled:      !!input.enabled,
      host:         (input.host || '').trim(),
      port:         parseInt(input.port) || 5432,
      database:     (input.database || '').trim(),
      user:         (input.user || '').trim(),
      password:     input.password || existing.password || '',
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
router.post('/api/external-db/test', requireAdmin, requireRol('superadministrador'), async (req, res, next) => {
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

    res.json({ success: true, schema });
  } catch (err) {
    console.error('[EXT-DB] Error de prueba de conexión externa:', err.message, err.stack);
    res.json({ success: false, error: err.message });
  } finally {
    try {
      await client.end();
    } catch (e) {
      // Ignorar si no se conectó o ya se cerró
    }
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

// ─── Métodos de Autenticación Activos ───

// GET - Listar todos los métodos de autenticación y su estado (abierto a cualquier administrador/operador)
router.get('/api/auth-methods', requireAdmin, async (req, res, next) => {
  try {
    const methods = await db.listAuthMethods();
    res.json(methods);
  } catch (err) { next(err); }
});

// PUT - Modificar estado de un método de autenticación (sólo superadministradores)
router.put('/api/auth-methods/:id', requireAdmin, requireRol('superadministrador'), async (req, res, next) => {
  try {
    const { id } = req.params;
    const { activo } = req.body;
    if (activo === undefined) {
      return res.status(400).json({ error: 'El campo "activo" es obligatorio.' });
    }

    const updated = await db.updateAuthMethodStatus(id, !!activo);
    if (!updated) {
      return res.status(404).json({ error: 'Método de autenticación no encontrado.' });
    }

    await db.logAdminAudit({
      username: req.adminUser,
      ipAddress: getClientIp(req),
      accion: 'MODIFICAR_ESTADO_METODO_AUTH',
      detalles: `Cambió estado del método ${id} a activo=${activo}`
    });

    res.json(updated);
  } catch (err) { next(err); }
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

router.put('/api/admins/:username/password', requireAdmin, requireSelfOrRol('superadministrador'),
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

router.post('/api/maintenance/purge', requireAdmin, requireRol('superadministrador'),
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

router.post('/api/maintenance/schedule', requireAdmin, requireRol('superadministrador'),
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

'use strict';

const express = require('express');
const path = require('path');
const { body, validationResult } = require('express-validator');
const router = express.Router();

const cedula   = require('../services/cedula');
const db       = require('../services/database');
const radius   = require('../services/radius');
const unifi    = require('../services/unifi');
const omadaSvc = require('../services/omada');

// ─── Detección de vendor ─────────────────────────────────────────────────────

/**
 * Detecta el vendor de red según los parámetros GET.
 * MikroTik: tiene link-login
 * UniFi:    tiene cmd (= 'login')
 * Omada:    tiene clientMac y vid
 */
function detectVendor(query) {
  if (query['link-login'] || query['link-login-only']) return 'mikrotik';
  if (query.cmd !== undefined && query.id !== undefined) return 'unifi';
  if (query.clientMac !== undefined) return 'omada';
  return 'unknown';
}

/**
 * Extrae los parámetros relevantes según el vendor.
 */
function extractVendorParams(vendor, query) {
  switch (vendor) {
    case 'mikrotik':
      return {
        mac:           query.mac || '',
        ip:            query.ip || '',
        linkLogin:     query['link-login'] || '',
        linkLoginOnly: query['link-login-only'] || query['link-login'] || '',
        linkOrig:      query['link-orig'] || '',
        username:      query.username || '',
      };
    case 'unifi':
      return {
        clientMac: query.id || '',
        apMac:     query.ap || '',
        ssid:      query.ssid || '',
        timestamp: query.t || '',
        redirectUrl: query.url || '',
      };
    case 'omada':
      return {
        clientMac:   query.clientMac || '',
        apMac:       query.apMac || '',
        ssidName:    query.ssidName || query.ssid || '',
        radioId:     query.radioId || '0',
        vid:         query.vid || '1',
        siteId:      query.siteId || query.site || 'default',
        redirectUrl: query.redirectUrl || query.originUrl || '',
      };
    default:
      return { redirectUrl: query.url || query['link-orig'] || '' };
  }
}

// ─── Config del portal (nombre, logo) ───────────────────────────────────────

router.get('/auth/config', async (req, res, next) => {
  try {
    const branding = await db.getControllerConfig('branding') || {};
    res.json({
      name: branding.portalName || process.env.PORTAL_NAME || 'Portal Wi-Fi',
      logo: branding.logoUrl || process.env.PORTAL_LOGO_URL || '/static/logo.svg',
      primaryColor: branding.primaryColor || '#2563eb',
      accentColor: branding.accentColor || '#1d4ed8',
      welcomeText: branding.welcomeText || 'Ingrese su número de cédula para conectarse',
      termsText: branding.termsText || '',
      termsUpdatedAt: branding.termsUpdatedAt || '2026-07-09T14:50:00.000Z',
      sessionMinutes: parseInt(process.env.SESSION_DURATION_MINUTES || '480'),
    });
  } catch (err) { next(err); }
});

// ─── Páginas estáticas ───────────────────────────────────────────────────────

const PUBLIC = path.join(__dirname, '../../public');

router.get('/', (req, res) => {
  res.sendFile(path.join(PUBLIC, 'index.html'));
});

router.get('/register', (req, res) => {
  res.sendFile(path.join(PUBLIC, 'register.html'));
});

router.get('/success', (req, res) => {
  res.sendFile(path.join(PUBLIC, 'success.html'));
});

router.get('/error', (req, res) => {
  res.sendFile(path.join(PUBLIC, 'error.html'));
});

// ─── API: verificar si MAC del dispositivo está registrada ──────────────────

router.get('/auth/check-mac', async (req, res, next) => {
  try {
    const { mac, vendor } = req.query;
    if (!mac) return res.json({ registered: false });

    if (vendor && ['unifi', 'omada', 'freeradius'].includes(vendor)) {
      const ctrlCfg = await db.getControllerConfig(vendor);
      if (ctrlCfg && (ctrlCfg.activo === false || ctrlCfg.activo === 'false')) {
        console.log(`[AUTH] Autologin bloqueado porque el controlador ${vendor} está desactivado.`);
        return res.json({ registered: false });
      }
    }

    const user = await db.getUserByDeviceMac(mac);
    if (user && user.activo) {
      return res.json({
        registered: true,
        cedula: user.cedula,
        nombre: user.nombres
      });
    }
    return res.json({ registered: false });
  } catch (err) {
    next(err);
  }
});

// ─── API: verificar si cédula existe ────────────────────────────────────────

router.post('/auth/check',
  body('cedula').isString().trim().isLength({ min: 10, max: 10 }).isNumeric(),
  async (req, res, next) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.json({ valid: false, exists: false, error: 'Cédula inválida.' });
      }

      const { cedula: ced } = req.body;

      if (!cedula.validate(ced)) {
        return res.json({ valid: false, exists: false, error: 'Número de cédula no válido.' });
      }

      const exists = await db.userExists(ced);
      if (exists) {
        return res.json({ valid: true, exists: true });
      }

      // Si no existe localmente, verificar validación externa
      const extConfig = await db.getControllerConfig('external_db_config');
      if (extConfig && extConfig.enabled && extConfig.host && extConfig.tableName && extConfig.colCedula) {
        const { Client } = require('pg');
        const extClient = new Client({
          host: extConfig.host,
          port: parseInt(extConfig.port) || 5432,
          database: extConfig.database,
          user: extConfig.user,
          password: extConfig.password,
          ssl: extConfig.ssl ? { rejectUnauthorized: false } : false,
          connectionTimeoutMillis: 4000,
        });

        try {
          await extClient.connect();
          
          // Consulta dinámica segura escapando nombres de tabla y columnas
          const escapedTable = extConfig.tableName.replace(/"/g, '""');
          const escapedCol = extConfig.colCedula.replace(/"/g, '""');
          
          const colsToFetch = [];
          if (extConfig.colNombres) colsToFetch.push(`"${extConfig.colNombres.replace(/"/g, '""')}" AS nombres`);
          if (extConfig.colApellidos) colsToFetch.push(`"${extConfig.colApellidos.replace(/"/g, '""')}" AS apellidos`);
          if (extConfig.colEmail) colsToFetch.push(`"${extConfig.colEmail.replace(/"/g, '""')}" AS email`);
          
          const selectFields = colsToFetch.length > 0 ? colsToFetch.join(', ') : '1';
          const query = `SELECT ${selectFields} FROM "${escapedTable}" WHERE "${escapedCol}" = $1 LIMIT 1`;
          
          const extRes = await extClient.query(query, [ced]);
          await extClient.end();

          const foundExternally = extRes.rowCount > 0;
          let userObj = null;
          if (foundExternally && colsToFetch.length > 0) {
            const row = extRes.rows[0];
            userObj = {
              nombres: row.nombres || '',
              apellidos: row.apellidos || '',
              email: row.email || '',
            };
          }

          if (extConfig.allowManualRegistration === false || extConfig.allowManualRegistration === 'false') {
            if (foundExternally) {
              // Auto-registrar al usuario localmente
              await db.createUser({
                cedula: ced,
                nombres: userObj.nombres || 'Auto',
                apellidos: userObj.apellidos || 'Registrado',
                email: userObj.email || 'auto@registro.com',
                activo: true,
                acepta_terminos: true,
                fecha_acepta_terminos: new Date(),
                tipo_usuario: 'institucional'
              });
              
              // Responder que ya existe (para login directo)
              return res.json({
                valid: true,
                exists: true
              });
            } else {
              // Denegar acceso
              return res.json({
                valid: false,
                exists: false,
                error: 'Acceso denegado. La cédula ingresada no consta en los registros institucionales.'
              });
            }
          }

          return res.json({
            valid: true,
            exists: false,
            external: foundExternally,
            user: userObj
          });
        } catch (extErr) {
          console.error('[EXT-DB] Error de validación en check:', extErr.message);
          // Si falla la conexión externa, por seguridad asumimos que no existe (fail-closed)
          if (extConfig.allowManualRegistration === false || extConfig.allowManualRegistration === 'false') {
            return res.json({
              valid: false,
              exists: false,
              error: 'Error de validación institucional. Intente más tarde.'
            });
          }
          return res.json({ valid: true, exists: false, external: false });
        }
      }

      return res.json({ valid: true, exists: false, external: false });
    } catch (err) {
      next(err);
    }
  }
);

// ─── API: registro de usuario nuevo ─────────────────────────────────────────

router.post('/auth/register',
  body('cedula').isString().trim().isLength({ min: 10, max: 10 }).isNumeric(),
  body('nombres').isString().trim().isLength({ min: 2, max: 100 }),
  body('apellidos').isString().trim().isLength({ min: 2, max: 100 }),
  body('email').isEmail().normalizeEmail(),
  body('terms').custom(val => val === true || val === 'true').withMessage('Debe aceptar los términos de uso.'),
  async (req, res, next) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({
          error: errors.array().map(e => e.msg).join(', ')
        });
      }

      const { cedula: ced, nombres, apellidos, email, vendor, vendorParams } = req.body;
      const clientIp = req.ip || req.connection.remoteAddress;

      if (vendor && ['unifi', 'omada', 'freeradius'].includes(vendor)) {
        const ctrlCfg = await db.getControllerConfig(vendor);
        if (ctrlCfg && (ctrlCfg.activo === false || ctrlCfg.activo === 'false')) {
          return res.status(403).json({ error: 'El servicio de conexión para este controlador está temporalmente desactivado.' });
        }
      }

      // Validar cédula
      if (!cedula.validate(ced)) {
        return res.status(400).json({ error: 'Número de cédula no válido.' });
      }

      // Verificar que no esté ya registrado
      if (await db.userExists(ced)) {
        return res.status(409).json({ error: 'Esta cédula ya está registrada.' });
      }

      // Obtener el texto de términos actual
      const branding = await db.getControllerConfig('branding') || {};
      const DEFAULT_TERMS = `1. Aceptación\nAl conectarse a esta red Wi-Fi pública, usted acepta cumplir con estos términos y condiciones.\n\n2. Uso Permitido\nEsta red está destinada para uso general de navegación, comunicaciones y acceso a información. El uso es personal e intransferible.\n\n3. Uso Prohibido\nEstá prohibido utilizar la red para actividades ilegales, distribución de contenido inapropiado, ataques informáticos o cualquier actividad que viole la ley ecuatoriana.\n\n4. Privacidad\nLos datos de registro son recopilados únicamente para fines de autenticación y no serán compartidos con terceros sin autorización legal.\n\n5. Limitación de Responsabilidad\nEl administrador de la red no se responsabiliza por el contenido accedido por los usuarios ni por interrupciones del servicio.\n\n6. Duración de Sesión\nCada sesión tiene una duración limitada. Al expirar, deberá autenticarse nuevamente.`;
      const terminosAceptados = branding.termsText || DEFAULT_TERMS;

      // Verificar si existe en la base de datos externa para asignarle el tipo
      let tipo_usuario = 'externo';
      const extConfig = await db.getControllerConfig('external_db_config');
      if (extConfig && (extConfig.enabled === true || extConfig.enabled === 'true') && extConfig.host && extConfig.tableName && extConfig.colCedula) {
        const { Client } = require('pg');
        const extClient = new Client({
          host: extConfig.host,
          port: parseInt(extConfig.port) || 5432,
          database: extConfig.database,
          user: extConfig.user,
          password: extConfig.password,
          ssl: extConfig.ssl && (extConfig.ssl === true || extConfig.ssl === 'true') ? { rejectUnauthorized: false } : false,
          connectionTimeoutMillis: 2000,
        });
        try {
          await extClient.connect();
          const escapedTable = extConfig.tableName.replace(/"/g, '""');
          const escapedCol = extConfig.colCedula.replace(/"/g, '""');
          const extRes = await extClient.query(`SELECT 1 FROM "${escapedTable}" WHERE "${escapedCol}" = $1 LIMIT 1`, [ced]);
          if (extRes.rowCount > 0) {
            tipo_usuario = 'institucional';
          }
          await extClient.end();
        } catch (e) {
          console.error('[EXT-DB] Error al consultar tipo de usuario en register:', e.message);
        }
      }

      // Crear usuario (incluye radcheck insert y guardar los términos aceptados)
      const user = await db.createUser({ cedula: ced, nombres, apellidos, email, terminosAceptados, tipo_usuario });

      // Registrar dispositivo del usuario si viene la MAC
      const params = typeof vendorParams === 'object' ? vendorParams : {};
      const mac = params.mac || params.clientMac;
      if (mac) {
        await db.registerUserDevice(ced, mac);
      }

      // Autenticar vía RADIUS
      const radiusOk = await radius.authenticate(ced, user.radius_password);
      if (!radiusOk) {
        console.error(`[AUTH] RADIUS rechazó al usuario recién creado: ${ced}`);
        return res.status(500).json({ error: 'Error al activar la sesión. Contacte al administrador.' });
      }

      let redirectUrl = params.redirectUrl || '/success';

      // Retornar éxito inmediatamente al cliente para evitar reseteos de TCP durante el cambio de ACLs
      res.json({
        success: true,
        nombre: user.nombres,
        redirectUrl: redirectUrl || '/success',
      });

      // Procesar la autorización en el controlador y el log en background
      (async () => {
        try {
          // Un pequeño delay de 300ms permite que el cliente reciba la respuesta HTTP limpia
          await new Promise(resolve => setTimeout(resolve, 300));
          
          await authorizeVendor(vendor, params, ced, user.radius_password);
          
          await db.startAcctSession({
            username: ced,
            macAddress: params.mac || params.clientMac,
            ipAddress: clientIp,
            vendor: vendor
          });
          
          await db.logAccess({
            cedula: ced,
            vendor,
            macAddress: params.mac || params.clientMac,
            ipAddress: clientIp,
            resultado: 'registered',
          });
          
          console.log(`[AUTH] Registro y autorización exitosos (async): ${ced}`);
        } catch (vendorErr) {
          console.error(`[VENDOR] Error autorizando en ${vendor} (async):`, vendorErr.message);
          await db.logAccess({
            cedula: ced,
            vendor,
            macAddress: params.mac || params.clientMac,
            ipAddress: clientIp,
            resultado: 'failed',
          });
        }
      })();
    } catch (err) {
      if (err.code === '23505') {
        return res.status(409).json({ error: 'Esta cédula ya está registrada.' });
      }
      next(err);
    }
  }
);

// ─── API: login de usuario existente ────────────────────────────────────────

router.post('/auth/login',
  body('cedula').isString().trim().isLength({ min: 10, max: 10 }).isNumeric(),
  body('terms').custom(val => val === true || val === 'true').withMessage('Debe aceptar los términos de uso.'),
  async (req, res, next) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({ error: errors.array().map(e => e.msg).join(', ') });
      }

      const { cedula: ced, vendor, vendorParams } = req.body;
      const clientIp = req.ip || req.connection.remoteAddress;
      const params = typeof vendorParams === 'object' ? vendorParams : {};

      if (vendor && ['unifi', 'omada', 'freeradius'].includes(vendor)) {
        const ctrlCfg = await db.getControllerConfig(vendor);
        if (ctrlCfg && (ctrlCfg.activo === false || ctrlCfg.activo === 'false')) {
          return res.status(403).json({ error: 'El servicio de conexión para este controlador está temporalmente desactivado.' });
        }
      }

      if (!cedula.validate(ced)) {
        return res.status(400).json({ error: 'Número de cédula no válido.' });
      }

      const user = await db.getUserByCedula(ced);
      if (!user) {
        return res.status(404).json({ error: 'Usuario no encontrado. Por favor regístrese.' });
      }

      if (!user.activo) {
        const branding = await db.getControllerConfig('branding') || {};
        const warningMsg = branding.inactiveMessage || 'Su usuario ha sido desactivado. Por favor, contacte al administrador.';
        
        await db.logAccess({
          cedula: ced,
          vendor,
          macAddress: params.mac || params.clientMac,
          ipAddress: clientIp,
          resultado: 'failed'
        });
        
        return res.status(403).json({ error: warningMsg });
      }

      let mac = params.mac || params.clientMac;
      let detectedVendor = vendor;
      const finalParams = { ...params };

      if (!mac) {
        // Fallback: buscar MAC registrada en la base de datos
        const dbMacs = await db.getUserDevices(ced);
        if (dbMacs && dbMacs.length > 0) {
          mac = dbMacs[0].mac_address;
          finalParams.clientMac = mac;
          finalParams.mac = mac;
          console.log(`[AUTH] MAC no provista en URL. Usando MAC registrada en DB: ${mac} para cédula ${ced}`);
          
          if (detectedVendor === 'unknown' || !detectedVendor) {
            if (process.env.OMADA_CONTROLLER_URL) {
              detectedVendor = 'omada';
              if (!finalParams.siteId) {
                finalParams.siteId = process.env.OMADA_SITE_ID || 'default';
              }
            } else if (process.env.UNIFI_CONTROLLER_URL) {
              detectedVendor = 'unifi';
              if (!finalParams.apMac) {
                finalParams.apMac = process.env.UNIFI_SITE || 'default';
              }
            }
          }
        }
      }

      // Validar limitación de dispositivos por MAC
      if (mac) {
        const normalizedMac = mac.trim().toUpperCase();
        const isReg = await db.isDeviceRegistered(ced, normalizedMac);
        if (!isReg) {
          const regCount = await db.getUserDevicesCount(ced);
          const maxAllowed = user.max_dispositivos !== null ? user.max_dispositivos : 1;
          
          if (maxAllowed > 0 && regCount >= maxAllowed) {
            await db.logAccess({
              cedula: ced,
              vendor: detectedVendor,
              macAddress: normalizedMac,
              ipAddress: clientIp,
              resultado: 'limit_reached'
            });
            return res.status(400).json({
              error: `Límite de dispositivos alcanzado para esta cédula (Máximo ${maxAllowed} dispositivo${maxAllowed !== 1 ? 's' : ''}).`
            });
          }
          
          // Registrar el nuevo dispositivo
          await db.registerUserDevice(ced, normalizedMac);
        }
      }

      // Autenticar vía RADIUS
      const radiusOk = await radius.authenticate(ced, user.radius_password);
      if (!radiusOk) {
        await db.logAccess({ cedula: ced, vendor: detectedVendor, macAddress: mac || '', ipAddress: clientIp, resultado: 'failed' });
        return res.status(401).json({ error: 'Autenticación fallida. Contacte al administrador.' });
      }

      // Guardar aceptación de términos
      const brandingConfig = await db.getControllerConfig('branding') || {};
      const DEFAULT_TERMS_TEXT = `1. Aceptación\nAl conectarse a esta red Wi-Fi pública, usted acepta cumplir con estos términos y condiciones.\n\n2. Uso Permitido\nEsta red está destinada para uso general de navegación, comunicaciones y acceso a información. El uso es personal e intransferible.\n\n3. Uso Prohibido\nEstá prohibido utilizar la red para actividades ilegales, distribución de contenido inapropiado, ataques informáticos o cualquier actividad que viole la ley ecuatoriana.\n\n4. Privacidad\nLos datos de registro son recopilados únicamente para fines de autenticación y no serán compartidos con terceros sin autorización legal.\n\n5. Limitación de Responsabilidad\nEl administrador de la red no se responsabiliza por el contenido accedido por los usuarios ni por interrupciones del servicio.\n\n6. Duración de Sesión\nCada sesión tiene una duración limitada. Al expirar, deberá autenticarse nuevamente.`;
      const currentTerms = brandingConfig.termsText || DEFAULT_TERMS_TEXT;

      await db.updateTermsAcceptance(ced, currentTerms);

      // Autorizar en el vendor
      let redirectUrl = finalParams.redirectUrl || '/success';

      // Retornar éxito inmediatamente al cliente para evitar reseteos de TCP durante el cambio de ACLs
      res.json({
        success: true,
        nombre: user.nombres,
        redirectUrl: redirectUrl || '/success',
        ...(detectedVendor === 'mikrotik' ? { radiusPassword: user.radius_password } : {}),
      });

      // Procesar la autorización en el controlador y el log en background
      (async () => {
        try {
          // Un pequeño delay de 300ms permite que el cliente reciba la respuesta HTTP limpia
          await new Promise(resolve => setTimeout(resolve, 300));
          
          await authorizeVendor(detectedVendor, finalParams, ced, user.radius_password);
          
          await db.startAcctSession({
            username: ced,
            macAddress: mac || '',
            ipAddress: clientIp,
            vendor: detectedVendor
          });
          
          await db.logAccess({
            cedula: ced,
            vendor: detectedVendor,
            macAddress: mac || '',
            ipAddress: clientIp,
            resultado: 'success',
          });
          
          console.log(`[AUTH] Login exitoso y autorizado (async): ${ced} (${detectedVendor})`);
        } catch (vendorErr) {
          console.error(`[VENDOR] Error autorizando en ${detectedVendor} (async):`, vendorErr.message);
          await db.logAccess({
            cedula: ced,
            vendor: detectedVendor,
            macAddress: mac || '',
            ipAddress: clientIp,
            resultado: 'failed',
          });
        }
      })();
    } catch (err) {
      next(err);
    }
  }
);

// ─── Lógica de autorización por vendor ──────────────────────────────────────

/**
 * Ejecuta la autorización específica del vendor y devuelve la URL de redirección.
 *
 * MikroTik: devuelve la URL de link-login-only con parámetros (la redirección
 *           real la hace el frontend via form auto-submit POST).
 *
 * UniFi/Omada: hace la llamada server-side al controlador.
 *
 * @returns {string} URL a la que redirigir el browser del usuario
 */
async function authorizeVendor(vendor, params, username, password) {
  switch (vendor) {
    case 'mikrotik': {
      // MikroTik espera que el browser haga POST a link-login-only con username y password
      // Devolvemos la info necesaria para que el frontend construya el form de auto-submit
      // La URL real la construye el frontend con estos datos
      const baseUrl = params.linkLoginOnly || params.linkLogin;
      if (!baseUrl) return '/success';
      return `__mikrotik__:${baseUrl}:${username}:${password}`;
    }

    case 'unifi': {
      await unifi.authorizeGuest(params.clientMac, params.apMac);
      return params.redirectUrl || '/success';
    }

    case 'omada': {
      let attempts = 4;
      let lastErr;
      for (let i = 1; i <= attempts; i++) {
        try {
          await omadaSvc.authorizeClient({
            clientMac:   params.clientMac,
            siteId:      params.siteId,
            timeLimit:   parseInt(process.env.SESSION_DURATION_MINUTES || '480'),
          });

          // Forzar la desconexión (kick) del cliente después de 500ms para limpiar la caché del AP y obligar a una reasociación automática
          setTimeout(async () => {
            try {
              await omadaSvc.kickClient({
                clientMac: params.clientMac,
                siteId: params.siteId
              });
            } catch (kickErr) {
              console.error('[OMADA] Falló el kick automático:', kickErr.message);
            }
          }, 500);

          return params.redirectUrl || '/success';
        } catch (err) {
          lastErr = err;
          // Si es el código de error -41009, reintentamos con un delay
          if (err.message.includes('-41009') && i < attempts) {
            console.warn(`[OMADA] Intento ${i} falló con -41009 (sincronización pendiente). Reintentando en 2.5 segundos...`);
            await new Promise(resolve => setTimeout(resolve, 2500));
          } else {
            throw err;
          }
        }
      }
      throw lastErr;
    }

    default:
      return '/success';
  }
}

module.exports = router;

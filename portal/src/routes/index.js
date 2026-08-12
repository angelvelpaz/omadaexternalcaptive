'use strict';

const express = require('express');
const path = require('path');
const { body, validationResult } = require('express-validator');
const axios = require('axios');
const router = express.Router();

const cedula     = require('../services/cedula');
const db         = require('../services/database');
const radius     = require('../services/radius');
const unifi      = require('../services/unifi');
const omadaSvc   = require('../services/omada');
const ldapSvc    = require('../services/ldap');
const externalApi = require('../services/externalApi');

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
    const ssidParam = (req.query.ssid || '').trim();
    let branding = await db.getControllerConfig('branding') || {};
    let secap = await db.getControllerConfig('secap') || {};
    
    let activeAuthType = 'cedula';
    let disableRegistration = branding.disableRegistration === true;
    let adImageUrl = branding.adImageUrl || '';
    let adImageUrlMobile = branding.adImageUrlMobile || '';
    let adSessionMinutes = branding.adSessionMinutes !== undefined ? branding.adSessionMinutes : 30;
    let adAllowDirectRegister = branding.adAllowDirectRegister !== false;
    let ldapEnabled = false;

    // Si hay un SSID provisto, buscar en ssid_config
    let ssidConfig = null;
    if (ssidParam) {
      ssidConfig = await db.getSsidConfig(ssidParam);
    }
    // Fallback al perfil 'default' si no se encuentra el SSID específico
    if (!ssidConfig && ssidParam !== 'default') {
      ssidConfig = await db.getSsidConfig('default');
    }

    if (ssidConfig) {
      activeAuthType = ssidConfig.auth_type;
      const sc = ssidConfig.config || {};
      
      // Sobrescribir variables de branding y secap del perfil de red
      branding = {
        portalName: sc.portalName || branding.portalName,
        logoUrl: sc.logoUrl || branding.logoUrl,
        primaryColor: sc.primaryColor || branding.primaryColor,
        accentColor: sc.accentColor || branding.accentColor,
        welcomeText: sc.welcomeText || branding.welcomeText,
        termsText: sc.termsText || branding.termsText,
        termsUpdatedAt: sc.termsUpdatedAt || branding.termsUpdatedAt,
        inactiveMessage: sc.inactiveMessage || branding.inactiveMessage,
        redirectSeconds: sc.redirectSeconds !== undefined ? sc.redirectSeconds : branding.redirectSeconds,
      };

      secap = {
        activo: sc.secapEnabled === true || sc.secapEnabled === 'true',
        emailOpcional: sc.emailOpcional === true || sc.emailOpcional === 'true',
      };

      if (activeAuthType === 'publicidad') {
        disableRegistration = true;
        adImageUrl = sc.adImageUrl || '';
        adImageUrlMobile = sc.adImageUrlMobile || '';
        adSessionMinutes = sc.adSessionMinutes !== undefined ? sc.adSessionMinutes : adSessionMinutes;
        adAllowDirectRegister = sc.adAllowDirectRegister !== false;
      } else if (activeAuthType === 'ldap') {
        disableRegistration = false;
        ldapEnabled = true;
      } else {
        disableRegistration = false;
      }
    }

    res.json({
      name: branding.portalName || process.env.PORTAL_NAME || 'Portal Wi-Fi',
      logo: branding.logoUrl || process.env.PORTAL_LOGO_URL || '/static/logo.svg',
      primaryColor: branding.primaryColor || '#2563eb',
      accentColor: branding.accentColor || '#1d4ed8',
      welcomeText: branding.welcomeText || 'Ingrese su número de cédula para conectarse',
      termsText: branding.termsText || '',
      termsUpdatedAt: branding.termsUpdatedAt || '2026-07-09T14:50:00.000Z',
      sessionMinutes: branding.sessionDurationMinutes !== undefined ? parseInt(branding.sessionDurationMinutes) : parseInt(process.env.SESSION_DURATION_MINUTES || '480'),
      redirectSeconds: parseInt(branding.redirectSeconds !== undefined ? branding.redirectSeconds : '3'),
      secapEnabled: secap.activo === true || secap.activo === 'true',
      emailOpcional: secap.emailOpcional === true || secap.emailOpcional === 'true',
      disableRegistration: disableRegistration,
      adImageUrl: adImageUrl,
      adImageUrlMobile: adImageUrlMobile,
      adSessionMinutes: parseInt(adSessionMinutes),
      adAllowDirectRegister: adAllowDirectRegister,
      ldapEnabled: ldapEnabled,
      authType: activeAuthType
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
        // Whitelist estricta de tablas y columnas permitidas (admite '*' como comodín general)
        const ALLOWED_TABLES = (process.env.EXT_DB_ALLOWED_TABLES || '').split(',').map(s => s.trim()).filter(Boolean);
        const ALLOWED_COLS = (process.env.EXT_DB_ALLOWED_COLS || 'cedula,nombres,apellidos,email,documento,id').split(',').map(s => s.trim());

        if (ALLOWED_TABLES.length > 0 && !ALLOWED_TABLES.includes('*') && !ALLOWED_TABLES.includes(extConfig.tableName.trim())) {
          console.error(`[EXT-DB] Tabla no autorizada: ${extConfig.tableName}`);
          return res.json({ valid: false, exists: false, error: 'Configuración de base de datos externa no autorizada.' });
        }

        const rawCols = [extConfig.colCedula, extConfig.colNombres, extConfig.colApellidos, extConfig.colEmail].filter(Boolean);
        if (!ALLOWED_COLS.includes('*')) {
          for (const c of rawCols) {
            if (!ALLOWED_COLS.includes(c.trim())) {
              console.error(`[EXT-DB] Columna no autorizada: ${c}`);
              return res.json({ valid: false, exists: false, error: 'Configuración de base de datos externa no autorizada.' });
            }
          }
        }

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
        } finally {
          try {
            await extClient.end();
          } catch (e) {
            // Ignorar
          }
        }
      }

      return res.json({ valid: true, exists: false, external: false });
    } catch (err) {
      next(err);
    }
  }
);

// GET — Valida identidad contra el Registro Civil de Ecuador (SECAP Proxy)
router.get('/api/public/validate-identity', async (req, res, next) => {
  try {
    const ced = String(req.query.cedula || '').trim();
    if (!/^\d{10}$/.test(ced)) {
      return res.status(400).json({ error: 'Cédula debe tener 10 dígitos numéricos.' });
    }

    const secapCfg = await db.getControllerConfig('secap') || {};
    if (!secapCfg.activo || secapCfg.activo === 'false') {
      return res.json({ enabled: false });
    }

    const result = await externalApi.querySecapCivilRegistry(ced);
    res.json({ 
      enabled: true, 
      emailOpcional: secapCfg.emailOpcional === true || secapCfg.emailOpcional === 'true', 
      ...result 
    });
  } catch (err) { next(err); }
});

// ─── API: registro de usuario nuevo ─────────────────────────────────────────

router.post('/auth/register',
  body('cedula').isString().trim().isLength({ min: 10, max: 10 }).isNumeric(),
  body('nombres').isString().trim().isLength({ min: 2, max: 100 }),
  body('apellidos').isString().trim().isLength({ min: 2, max: 100 }),
  body('email').optional({ checkFalsy: true }).isEmail().normalizeEmail(),
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

      // Obtener configuración SECAP y validar nombres legales con timeout inteligente (Fast-Track)
      const secapCfg = await db.getControllerConfig('secap') || {};
      let finalNombres = nombres;
      let finalApellidos = apellidos;

      if (secapCfg.activo && secapCfg.activo !== 'false') {
        try {
          // Intentar obtener nombres de SECAP con una carrera de 400ms máximo
          const secapPromise = externalApi.querySecapCivilRegistry(ced);
          const timeoutPromise = new Promise(resolve => setTimeout(() => resolve({ timeout: true }), 400));
          const result = await Promise.race([secapPromise, timeoutPromise]);

          if (result && result.success) {
            finalNombres = result.nombres;
            finalApellidos = result.apellidos;
            console.log(`[SECAP-FASTTRACK] Nombres verificados síncronos: ${finalNombres} ${finalApellidos}`);
          } else if (result && result.timeout) {
            console.log(`[SECAP-FASTTRACK] Consulta SECAP tomando > 400ms. Otorgando acceso de inmediato y actualizando nombres en segundo plano.`);
            // Disparar actualización de nombres legales en segundo plano cuando la API responda
            secapPromise.then(async (identity) => {
              if (identity && identity.success && identity.nombres) {
                await db.getPool().query(
                  'UPDATE usuarios_portal SET nombres = $1, apellidos = $2 WHERE cedula = $3',
                  [identity.nombres, identity.apellidos, ced]
                );
                console.log(`[SECAP-ASYNC] Nombres actualizados en BD tras respuesta tardía para ${ced}: ${identity.nombres} ${identity.apellidos}`);
              }
            }).catch(e => console.error('[SECAP-ASYNC] Error en actualización en background:', e.message));
          }
        } catch (secapErr) {
          console.error('[SECAP-FASTTRACK] Error al validar SECAP:', secapErr.message);
        }
      }

      // Obtener el texto de términos actual
      const branding = await db.getControllerConfig('branding') || {};
      const DEFAULT_TERMS = `1. Aceptación\nAl conectarse a esta red Wi-Fi pública, usted acepta cumplir con estos términos y condiciones.\n\n2. Uso Permitido\nEsta red está destinada para uso general de navegación, comunicaciones y acceso a información. El uso es personal e intransferible.\n\n3. Uso Prohibido\nEstá prohibido utilizar la red para actividades ilegales, distribución de contenido inapropiado, ataques informáticos o cualquier actividad que viole la ley ecuatoriana.\n\n4. Privacidad\nLos datos de registro son recopilados únicamente para fines de autenticación y no serán compartidos con terceros sin autorización legal.\n\n5. Limitación de Responsabilidad\nEl administrador de la red no se responsabiliza por el contenido accedido por los usuarios ni por interrupciones del servicio.\n\n6. Duración de Sesión\nCada sesión tiene una duración limitada. Al expirar, deberá autenticarse nuevamente.`;
      const terminosAceptados = branding.termsText || DEFAULT_TERMS;

      // Crear usuario (incluye radcheck insert y guardar los términos aceptados)
      const user = await db.createUser({ cedula: ced, nombres: finalNombres, apellidos: finalApellidos, email, terminosAceptados, tipo_usuario: 'externo' });

      // Registrar dispositivo del usuario si viene la MAC
      const params = typeof vendorParams === 'object' ? vendorParams : {};
      const mac = params.mac || params.clientMac;
      if (mac) {
        await db.registerUserDevice(ced, mac);
      }

      let redirectUrl = params.redirectUrl || '/success';
      if (vendor === 'mikrotik') {
        redirectUrl = await authorizeVendor(vendor, params, ced, user.radius_password);
      }

      // Retornar éxito INMEDIATAMENTE al cliente para respuesta ultra-rápida en pantalla (< 150 ms)
      res.json({
        success: true,
        nombre: user.nombres,
        redirectUrl: redirectUrl || '/success',
        ...(vendor === 'mikrotik' ? { radiusPassword: user.radius_password } : {}),
      });

      // Procesar en background: BD externa institucional, RADIUS, controlador Omada y auditoría
      (async () => {
        try {
          await new Promise(resolve => setTimeout(resolve, 150));

          // Verificar si existe en la base de datos externa para asignarle el tipo institucional
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
                await db.updateUserType(ced, 'institucional');
              }
            } catch (e) {
              console.error('[EXT-DB] Error al consultar tipo de usuario en background:', e.message);
            } finally {
              try {
                await extClient.end();
              } catch (errEnd) {
                // Ignorar
              }
            }
          }

          // Autenticar vía RADIUS
          await radius.authenticate(ced, user.radius_password);

          // Autorizar en controlador Omada / MikroTik
          if (vendor !== 'mikrotik') {
            await authorizeVendor(vendor, params, ced, user.radius_password);
          }
          
          await db.startAcctSession({
            username: ced,
            macAddress: mac,
            ipAddress: clientIp,
            vendor: vendor
          });
          
          await db.logAccess({
            cedula: ced,
            vendor,
            macAddress: mac,
            ipAddress: clientIp,
            resultado: 'registered',
          });
          
          console.log(`[AUTH-FASTTRACK] Registro y autorización completados con éxito para ${ced}`);
        } catch (vendorErr) {
          console.error(`[AUTH-FASTTRACK] Error autorizando en ${vendor} (async):`, vendorErr.message);
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

      if (vendor && ['unifi', 'omada', 'freeradius', 'mikrotik'].includes(vendor)) {
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
            const userDevices = await db.getUserDevices(ced);
            return res.status(400).json({
              error: `Límite de dispositivos alcanzado para esta cédula (Máximo ${maxAllowed} dispositivo${maxAllowed !== 1 ? 's' : ''}).`,
              limitReached: true,
              cedula: ced,
              username: ced,
              devices: userDevices.map(d => ({ id: d.id, mac_address: d.mac_address, created_at: d.created_at }))
            });
          }
          
          // Registrar el nuevo dispositivo
          await db.registerUserDevice(ced, normalizedMac);
        } else {
          // Si ya está registrado, refrescar reglas de RADIUS (incluyendo límite de tiempo de sesión)
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
      if (detectedVendor === 'mikrotik') {
        redirectUrl = await authorizeVendor(detectedVendor, finalParams, ced, user.radius_password);
      }

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
          
          if (detectedVendor !== 'mikrotik') {
            await authorizeVendor(detectedVendor, finalParams, ced, user.radius_password);
          }
          
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

router.post('/auth/free-access',
  body('mac').isString().trim(),
  async (req, res, next) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({ error: errors.array().map(e => e.msg).join(', ') });
      }

      const { mac, vendor, vendorParams } = req.body;
      const clientIp = req.ip || req.connection.remoteAddress;
      const params = typeof vendorParams === 'object' ? vendorParams : {};

      if (!mac) {
        return res.status(400).json({ error: 'La dirección MAC es obligatoria.' });
      }

      // Recuperar la duración configurada para la sesión publicitaria
      let adSessionMinutes = 30;
      const ssidParam = (params.ssid || '').trim();
      let ssidConfig = null;
      if (ssidParam) {
        ssidConfig = await db.getSsidConfig(ssidParam);
      }
      if (!ssidConfig && ssidParam !== 'default') {
        ssidConfig = await db.getSsidConfig('default');
      }
      if (ssidConfig && ssidConfig.config) {
        const sc = ssidConfig.config;
        if (sc.adSessionMinutes !== undefined) {
          adSessionMinutes = parseInt(sc.adSessionMinutes);
        }
      } else {
        const branding = await db.getControllerConfig('branding') || {};
        if (branding.adSessionMinutes !== undefined) {
          adSessionMinutes = parseInt(branding.adSessionMinutes);
        }
      }

      // Si el tiempo es 0 (ilimitado), heredamos el límite máximo global de sesión del portal
      if (adSessionMinutes === 0) {
        const branding = await db.getControllerConfig('branding') || {};
        adSessionMinutes = branding.sessionDurationMinutes !== undefined ? parseInt(branding.sessionDurationMinutes) : parseInt(process.env.SESSION_DURATION_MINUTES || '480');
      }

      // 1. Asegurar que el usuario genérico 9999999999 existe
      let user = await db.getUserByCedula('9999999999');
      if (!user) {
        user = await db.createUser({
          cedula: '9999999999',
          nombres: 'Acceso Libre',
          apellidos: 'Publicitario',
          email: 'acceso.libre@wifi.local',
          terminosAceptados: 'Aceptado en Modo Publicitario',
          tipo_usuario: 'externo'
        });
        // Asegurar que el usuario genérico tenga límite ilimitado
        await db.setUserMaxDevices('9999999999', 0);
      }

      const normalizedMac = mac.trim().toUpperCase().replace(/:/g, '-');
      let detectedVendor = vendor;
      const finalParams = { ...params };

      // Forzar que los parámetros usen la MAC correcta si no venían
      if (!finalParams.clientMac) finalParams.clientMac = normalizedMac;
      if (!finalParams.mac) finalParams.mac = normalizedMac;

      // 2. Asociar el dispositivo al usuario genérico y actualizar reglas en RADIUS (incluyendo límite de tiempo)
      await db.registerUserDevice('9999999999', normalizedMac, adSessionMinutes);

      // Autenticar vía RADIUS (para garantizar consistencia con FreeRADIUS)
      const radiusOk = await radius.authenticate('9999999999', user.radius_password);
      if (!radiusOk) {
        return res.status(401).json({ error: 'Autenticación RADIUS del usuario genérico fallida.' });
      }

      // Guardar aceptación de términos
      await db.updateTermsAcceptance('9999999999', 'Aceptado en Modo Publicitario');

      let redirectUrl = finalParams.redirectUrl || '/success';
      if (detectedVendor === 'mikrotik') {
        redirectUrl = await authorizeVendor(detectedVendor, finalParams, '9999999999', user.radius_password, adSessionMinutes);
      }

      // 3. Responder de inmediato al cliente
      res.json({
        success: true,
        nombre: 'Invitado',
        redirectUrl: redirectUrl || '/success',
        ...(detectedVendor === 'mikrotik' ? { radiusPassword: user.radius_password } : {}),
      });

      // 4. Procesar la autorización en el controlador y el log en background
      (async () => {
        try {
          await new Promise(resolve => setTimeout(resolve, 300));
          
          if (detectedVendor !== 'mikrotik') {
            await authorizeVendor(detectedVendor, finalParams, '9999999999', user.radius_password, adSessionMinutes);
          }
          
          await db.startAcctSession({
            username: '9999999999',
            macAddress: normalizedMac,
            ipAddress: clientIp,
            vendor: detectedVendor
          });
          
          await db.logAccess({
            cedula: '9999999999',
            vendor: detectedVendor,
            macAddress: normalizedMac,
            ipAddress: clientIp,
            resultado: 'success'
          });
        } catch (bgErr) {
          console.error('[AUTH-FREE-BG] Error en el proceso de fondo:', bgErr.message);
        }
      })();

    } catch (err) { next(err); }
  }
);

router.post('/auth/ldap',
  body('username').isString().trim().notEmpty().withMessage('El usuario es obligatorio.'),
  body('password').isString().notEmpty().withMessage('La contraseña es obligatoria.'),
  body('mac').isString().trim().notEmpty().withMessage('La dirección MAC es obligatoria.'),
  async (req, res, next) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({ error: errors.array().map(e => e.msg).join(', ') });
      }

      const { username, password, mac, ssid, vendor, vendorParams } = req.body;
      const clientIp = req.ip || req.connection.remoteAddress;
      const params = typeof vendorParams === 'object' ? vendorParams : {};

      // 1. Resolver configuración LDAP según tabla global controller_config y SSID específico
      let ldapUrl = process.env.LDAP_SERVER_URL;
      let ldapBindDN = process.env.LDAP_BIND_DN;
      let ldapBindPassword = process.env.LDAP_BIND_PASSWORD;
      let ldapSearchBase = process.env.LDAP_SEARCH_BASE;
      let ldapAllowedGroup = process.env.LDAP_ALLOWED_GROUP;

      try {
        const ldapConfig = await db.getControllerConfig('ldap');
        if (ldapConfig) {
          if (ldapConfig.ldapServerUrl) ldapUrl = ldapConfig.ldapServerUrl;
          if (ldapConfig.ldapBindDN) ldapBindDN = ldapConfig.ldapBindDN;
          if (ldapConfig.ldapBindCredentials) ldapBindPassword = ldapConfig.ldapBindCredentials;
          if (ldapConfig.ldapSearchBase) ldapSearchBase = ldapConfig.ldapSearchBase;
          if (ldapConfig.ldapAllowedGroup !== undefined) ldapAllowedGroup = ldapConfig.ldapAllowedGroup;
        }
      } catch (dbErr) {
        console.warn('[LDAP-Auth] No se pudo leer la configuración global de LDAP:', dbErr.message);
      }

      // Buscar si el SSID actual tiene un grupo LDAP específico para anular el global
      const ssidParam = (ssid || '').trim();
      if (ssidParam) {
        try {
          let ssidConfig = await db.getSsidConfig(ssidParam);
          if (!ssidConfig && ssidParam !== 'default') {
            ssidConfig = await db.getSsidConfig('default');
          }
          const sc = ssidConfig ? (ssidConfig.config || {}) : {};
          if (sc.ldapAllowedGroup) {
            ldapAllowedGroup = sc.ldapAllowedGroup;
          }
        } catch (dbErr) {
          console.warn('[LDAP-Auth] No se pudo leer la configuración específica de SSID:', dbErr.message);
        }
      }

      if (!ldapUrl || !ldapBindDN || !ldapSearchBase) {
        return res.status(400).json({ error: 'La autenticación LDAP no está configurada para esta red o servidor.' });
      }

      // 2. Autenticar en el Directorio Activo / LDAP
      const authResult = await ldapSvc.authenticate({
        url: ldapUrl,
        bindDN: ldapBindDN,
        bindPassword: ldapBindPassword,
        searchBase: ldapSearchBase,
        allowedGroup: ldapAllowedGroup,
        username,
        password
      });

      if (!authResult.success) {
        // Guardar logs de acceso fallido
        await db.logAccess({
          cedula: username.substring(0, 15),
          vendor: vendor || 'unknown',
          macAddress: mac.trim().toUpperCase().replace(/:/g, '-'),
          ipAddress: clientIp,
          resultado: 'failure: ldap_invalid_credentials'
        });
        return res.status(401).json({ error: authResult.error || 'Credenciales LDAP incorrectas.' });
      }

      // 3. LDAP exitoso: asegurar que el usuario existe en DB local del portal
      const normalizedUsername = username.trim().toLowerCase();
      let user = await db.getUserByCedula(normalizedUsername);
      if (!user) {
        user = await db.createUser({
          cedula: normalizedUsername,
          nombres: authResult.nombres,
          apellidos: authResult.apellidos,
          email: authResult.email,
          terminosAceptados: 'Aceptado por Login LDAP',
          tipo_usuario: 'externo'
        });
        await db.setUserMaxDevices(normalizedUsername, 1);
      } else if (!user.activo) {
        // Bloquear acceso de inmediato si el usuario está desactivado en el portal
        const branding = await db.getControllerConfig('branding') || {};
        const warningMsg = branding.inactiveMessage || 'Su usuario ha sido desactivado. Por favor, contacte al administrador.';
        
        await db.logAccess({
          cedula: normalizedUsername,
          vendor: vendor || 'unknown',
          macAddress: mac.trim().toUpperCase().replace(/:/g, '-'),
          ipAddress: clientIp,
          resultado: 'failed'
        });
        
        return res.status(403).json({ error: warningMsg });
      }

      const normalizedMac = mac.trim().toUpperCase().replace(/:/g, '-');
      let detectedVendor = vendor;
      const finalParams = { ...params };
      if (!finalParams.clientMac) finalParams.clientMac = normalizedMac;
      if (!finalParams.mac) finalParams.mac = normalizedMac;

      // 4. Registrar dispositivo del usuario LDAP (Validando límites)
      const isReg = await db.isDeviceRegistered(normalizedUsername, normalizedMac);
      if (!isReg) {
        const regCount = await db.getUserDevicesCount(normalizedUsername);
        
        // Obtener la configuración fresca del límite de dispositivos del usuario
        const dbUser = await db.getUserByCedula(normalizedUsername);
        const maxAllowed = (dbUser && dbUser.max_dispositivos !== null) ? dbUser.max_dispositivos : 1;

        if (maxAllowed > 0 && regCount >= maxAllowed) {
          await db.logAccess({
            cedula: normalizedUsername,
            vendor: detectedVendor || 'unknown',
            macAddress: normalizedMac,
            ipAddress: clientIp,
            resultado: 'limit_reached'
          });
          const userDevices = await db.getUserDevices(normalizedUsername);
          return res.status(400).json({
            error: `Límite de dispositivos alcanzado para su usuario (Máximo ${maxAllowed} dispositivo${maxAllowed !== 1 ? 's' : ''}).`,
            limitReached: true,
            cedula: normalizedUsername,
            username: normalizedUsername,
            devices: userDevices.map(d => ({ id: d.id, mac_address: d.mac_address, created_at: d.created_at }))
          });
        }

        await db.registerUserDevice(normalizedUsername, normalizedMac);
      }

      // Autenticar vía RADIUS
      const radiusOk = await radius.authenticate(normalizedUsername, user.radius_password);
      if (!radiusOk) {
        return res.status(401).json({ error: 'Fallo al autenticar la cuenta local en RADIUS.' });
      }

      // Guardar aceptación de términos
      await db.updateTermsAcceptance(normalizedUsername, 'Aceptado por Login LDAP');

      let redirectUrl = finalParams.redirectUrl || '/success';
      if (detectedVendor === 'mikrotik') {
        redirectUrl = await authorizeVendor(detectedVendor, finalParams, normalizedUsername, user.radius_password);
      }

      // 5. Responder al cliente
      res.json({
        success: true,
        nombre: authResult.nombres,
        redirectUrl: redirectUrl || '/success',
        ...(detectedVendor === 'mikrotik' ? { radiusPassword: user.radius_password } : {}),
      });

      // 6. Autorización del vendor en background
      (async () => {
        try {
          await new Promise(resolve => setTimeout(resolve, 300));
          
          if (detectedVendor !== 'mikrotik') {
            await authorizeVendor(detectedVendor, finalParams, normalizedUsername, user.radius_password);
          }
          
          await db.startAcctSession({
            username: normalizedUsername,
            macAddress: normalizedMac,
            ipAddress: clientIp,
            vendor: detectedVendor
          });
          
          await db.logAccess({
            cedula: normalizedUsername,
            vendor: detectedVendor,
            macAddress: normalizedMac,
            ipAddress: clientIp,
            resultado: 'success'
          });
        } catch (bgErr) {
          console.error('[AUTH-LDAP-BG] Error en el proceso de fondo:', bgErr.message);
        }
      })();

    } catch (err) { next(err); }
  }
);

// ── Hoteles y Restaurantes: Autenticación ────────────────────────────────────

const months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
function formatExpirationDate(date) {
  const d = new Date(date);
  const day = String(d.getDate()).padStart(2, '0');
  const month = months[d.getMonth()];
  const year = d.getFullYear();
  const hours = String(d.getHours()).padStart(2, '0');
  const minutes = String(d.getMinutes()).padStart(2, '0');
  const seconds = String(d.getSeconds()).padStart(2, '0');
  return `${day} ${month} ${year} ${hours}:${minutes}:${seconds}`;
}

router.post('/auth/hotel',
  body('habitacion').isString().trim().notEmpty().withMessage('La habitación es obligatoria.'),
  body('apellido').isString().trim().notEmpty().withMessage('El apellido es obligatorio.'),
  body('mac').isString().trim().notEmpty().withMessage('La dirección MAC es obligatoria.'),
  async (req, res, next) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({ error: errors.array().map(e => e.msg).join(', ') });
      }

      const { habitacion, apellido, mac, ssid, vendor, vendorParams } = req.body;
      const clientIp = req.ip || req.connection.remoteAddress;
      const params = typeof vendorParams === 'object' ? vendorParams : {};

      // 1. Buscar huésped en base de datos
      const guest = await db.getHotelGuest(habitacion, apellido);
      if (!guest) {
        return res.status(401).json({ error: 'Número de habitación o apellido no coinciden con ningún huésped registrado.' });
      }

      const now = new Date();
      const checkout = new Date(guest.fecha_checkout);
      if (checkout <= now) {
        return res.status(401).json({ error: 'Su estadía en el hotel ha expirado.' });
      }

      // 2. Generar nombre de usuario único y persistente para la habitación
      const normalizedUsername = `hotel_${habitacion.trim()}_${apellido.trim().toLowerCase().replace(/[^a-z0-9]/g, '')}`;
      const normalizedMac = mac.trim().toUpperCase().replace(/:/g, '-');
      let detectedVendor = vendor;
      const finalParams = { ...params };
      if (!finalParams.clientMac) finalParams.clientMac = normalizedMac;
      if (!finalParams.mac) finalParams.mac = normalizedMac;

      // 3. Crear usuario en usuarios_portal si no existe
      let user = await db.getUserByCedula(normalizedUsername);
      if (!user) {
        user = await db.createUser({
          cedula: normalizedUsername,
          nombres: guest.nombre || 'Huésped',
          apellidos: guest.apellido,
          email: 'guest@hotel.local',
          terminosAceptados: 'Aceptado por Login Hotel',
          tipo_usuario: 'hotel'
        });
        await db.setUserMaxDevices(normalizedUsername, 3); // Límite de 3 dispositivos por habitación
      } else if (!user.activo) {
        return res.status(403).json({ error: 'Su acceso ha sido temporalmente desactivado.' });
      }

      // 4. Escribir/actualizar atributo Expiration en radcheck para FreeRADIUS
      const expirationStr = formatExpirationDate(guest.fecha_checkout);
      const pool = db.getPool();
      await pool.query("DELETE FROM radcheck WHERE username = $1 AND attribute = 'Expiration'", [normalizedUsername]);
      await pool.query("INSERT INTO radcheck (username, attribute, op, value) VALUES ($1, 'Expiration', ':=', $2)", [normalizedUsername, expirationStr]);

      // 5. Validar límites de dispositivos para esta cuenta de hotel
      const isReg = await db.isDeviceRegistered(normalizedUsername, normalizedMac);
      if (!isReg) {
        const regCount = await db.getUserDevicesCount(normalizedUsername);
        const maxAllowed = user.max_dispositivos !== null ? user.max_dispositivos : 3;

        if (maxAllowed > 0 && regCount >= maxAllowed) {
          await db.logAccess({
            cedula: normalizedUsername,
            vendor: detectedVendor || 'unknown',
            macAddress: normalizedMac,
            ipAddress: clientIp,
            resultado: 'limit_reached'
          });
          const userDevices = await db.getUserDevices(normalizedUsername);
          return res.status(400).json({
            error: `Límite de dispositivos alcanzado para su habitación (Máximo ${maxAllowed} dispositivos).`,
            limitReached: true,
            cedula: normalizedUsername,
            username: normalizedUsername,
            devices: userDevices.map(d => ({ id: d.id, mac_address: d.mac_address, created_at: d.created_at }))
          });
        }
        await db.registerUserDevice(normalizedUsername, normalizedMac);
      }

      // 6. Autenticar en RADIUS
      const radiusOk = await radius.authenticate(normalizedUsername, user.radius_password);
      if (!radiusOk) {
        return res.status(401).json({ error: 'Fallo de autenticación en RADIUS.' });
      }

      await db.updateTermsAcceptance(normalizedUsername, 'Aceptado por Login Hotel');

      let redirectUrl = finalParams.redirectUrl || '/success';
      if (detectedVendor === 'mikrotik') {
        redirectUrl = await authorizeVendor(detectedVendor, finalParams, normalizedUsername, user.radius_password);
      }

      res.json({
        success: true,
        nombre: guest.nombre || 'Huésped',
        redirectUrl: redirectUrl || '/success',
        ...(detectedVendor === 'mikrotik' ? { radiusPassword: user.radius_password } : {}),
      });

      // Autorización de fondo
      (async () => {
        try {
          await new Promise(resolve => setTimeout(resolve, 300));
          if (detectedVendor !== 'mikrotik') {
            await authorizeVendor(detectedVendor, finalParams, normalizedUsername, user.radius_password);
          }
          await db.startAcctSession({
            username: normalizedUsername,
            macAddress: normalizedMac,
            ipAddress: clientIp,
            vendor: detectedVendor
          });
          await db.logAccess({
            cedula: normalizedUsername,
            vendor: detectedVendor,
            macAddress: normalizedMac,
            ipAddress: clientIp,
            resultado: 'success'
          });
        } catch (bgErr) {
          console.error('[AUTH-HOTEL-BG] Error en segundo plano:', bgErr.message);
        }
      })();

    } catch (err) { next(err); }
  }
);

router.post('/auth/restaurant',
  body('pin').isString().trim().notEmpty().withMessage('El código PIN es obligatorio.'),
  body('mac').isString().trim().notEmpty().withMessage('La dirección MAC es obligatoria.'),
  async (req, res, next) => {
    try {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        return res.status(400).json({ error: errors.array().map(e => e.msg).join(', ') });
      }

      const { pin, mac, ssid, vendor, vendorParams } = req.body;
      const clientIp = req.ip || req.connection.remoteAddress;
      const params = typeof vendorParams === 'object' ? vendorParams : {};

      // 1. Validar PIN
      const pinObj = await db.getRestaurantPin(pin);
      if (!pinObj) {
        return res.status(401).json({ error: 'El código PIN de ticket ingresado no es válido o ya expiró.' });
      }

      const now = new Date();
      if (pinObj.expira_el && new Date(pinObj.expira_el) <= now) {
        return res.status(401).json({ error: 'El código de ticket ha expirado.' });
      }

      if (pinObj.dispositivos_usados >= pinObj.limite_dispositivos) {
        return res.status(401).json({ error: 'Este código PIN ya alcanzó el límite de dispositivos conectados.' });
      }

      const normalizedUsername = `pin_${pinObj.pin}`;
      const normalizedMac = mac.trim().toUpperCase().replace(/:/g, '-');
      let detectedVendor = vendor;
      const finalParams = { ...params };
      if (!finalParams.clientMac) finalParams.clientMac = normalizedMac;
      if (!finalParams.mac) finalParams.mac = normalizedMac;

      // 2. Crear usuario local en usuarios_portal si no existe
      let user = await db.getUserByCedula(normalizedUsername);
      if (!user) {
        user = await db.createUser({
          cedula: normalizedUsername,
          nombres: 'Cliente',
          apellidos: 'Restaurante',
          email: 'client@restaurant.local',
          terminosAceptados: 'Aceptado por Login PIN Restaurante',
          tipo_usuario: 'restaurant'
        });
        await db.setUserMaxDevices(normalizedUsername, pinObj.limite_dispositivos);
      }

      // 3. Registrar dispositivo del usuario (validando límites de dispositivos)
      const isReg = await db.isDeviceRegistered(normalizedUsername, normalizedMac);
      if (!isReg) {
        const regCount = await db.getUserDevicesCount(normalizedUsername);
        const maxAllowed = user.max_dispositivos !== null ? user.max_dispositivos : pinObj.limite_dispositivos;

        if (maxAllowed > 0 && regCount >= maxAllowed) {
          await db.logAccess({
            cedula: normalizedUsername,
            vendor: detectedVendor || 'unknown',
            macAddress: normalizedMac,
            ipAddress: clientIp,
            resultado: 'limit_reached'
          });
          return res.status(400).json({ error: `Límite de dispositivos alcanzado para este PIN.` });
        }
        await db.registerUserDevice(normalizedUsername, normalizedMac);
      }

      // 4. Si es la primera conexión del PIN, iniciar el contador absoluto de tiempo
      let finalExpirationDate = pinObj.expira_el;
      if (pinObj.dispositivos_usados === 0) {
        const sessionDurationMs = pinObj.duracion_minutos * 60 * 1000;
        finalExpirationDate = new Date(now.getTime() + sessionDurationMs);

        // Guardar la expiración calculada en la tabla restaurant_pins
        const pool = db.getPool();
        await pool.query(
          "UPDATE restaurant_pins SET expira_el = $1 WHERE pin = $2",
          [finalExpirationDate, pinObj.pin]
        );
      }

      // Incrementar el uso del PIN
      await db.incrementPinUsage(pinObj.pin);

      // Escribir/actualizar atributo Expiration en radcheck para FreeRADIUS
      const expirationStr = formatExpirationDate(finalExpirationDate);
      const pool = db.getPool();
      await pool.query("DELETE FROM radcheck WHERE username = $1 AND attribute = 'Expiration'", [normalizedUsername]);
      await pool.query("INSERT INTO radcheck (username, attribute, op, value) VALUES ($1, 'Expiration', ':=', $2)", [normalizedUsername, expirationStr]);

      // 5. Autenticar en RADIUS
      const radiusOk = await radius.authenticate(normalizedUsername, user.radius_password);
      if (!radiusOk) {
        return res.status(401).json({ error: 'Fallo de autenticación en RADIUS.' });
      }

      let redirectUrl = finalParams.redirectUrl || '/success';
      if (detectedVendor === 'mikrotik') {
        redirectUrl = await authorizeVendor(detectedVendor, finalParams, normalizedUsername, user.radius_password);
      }

      res.json({
        success: true,
        nombre: 'Cliente',
        redirectUrl: redirectUrl || '/success',
        ...(detectedVendor === 'mikrotik' ? { radiusPassword: user.radius_password } : {}),
      });

      // Autorización de fondo
      (async () => {
        try {
          await new Promise(resolve => setTimeout(resolve, 300));
          if (detectedVendor !== 'mikrotik') {
            await authorizeVendor(detectedVendor, finalParams, normalizedUsername, user.radius_password);
          }
          await db.startAcctSession({
            username: normalizedUsername,
            macAddress: normalizedMac,
            ipAddress: clientIp,
            vendor: detectedVendor
          });
          await db.logAccess({
            cedula: normalizedUsername,
            vendor: detectedVendor,
            macAddress: normalizedMac,
            ipAddress: clientIp,
            resultado: 'success'
          });
        } catch (bgErr) {
          console.error('[AUTH-RESTAURANT-BG] Error en segundo plano:', bgErr.message);
        }
      })();

    } catch (err) { next(err); }
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
async function authorizeVendor(vendor, params, username, password, customTimeLimit) {
  switch (vendor) {
    case 'mikrotik': {
      // MikroTik espera que el browser haga POST a link-login-only con username y password
      // Devolvemos la info necesaria para que el frontend construya el form de auto-submit
      // La URL real la construye el frontend con estos datos
      const baseUrl = params.linkLoginOnly || params.linkLogin;
      if (!baseUrl) return '/success';
      return `__mikrotik__:${baseUrl}:${username}:${password}`;
    }

    case 'coovachilli':
    case 'openwrt': {
      // CoovaChilli espera que el navegador envíe los parámetros de inicio de sesión a su pasarela UAM local.
      // Retornamos los datos estructurados con el delimitador '||' para evitar problemas de colón.
      const logonUrl = `http://${params.uamip}:${params.uamport || '3990'}/logon`;
      return `__coovachilli__||${logonUrl}||${username}||${password}||${params.redirectUrl || params.userurl || ''}`;
    }

    case 'unifi': {
      let limit = customTimeLimit;
      if (limit === undefined || limit === null) {
        const branding = await db.getControllerConfig('branding') || {};
        limit = branding.sessionDurationMinutes !== undefined ? parseInt(branding.sessionDurationMinutes) : parseInt(process.env.SESSION_DURATION_MINUTES || '480');
      }
      await unifi.authorizeGuest(params.clientMac, params.apMac, limit);
      return params.redirectUrl || '/success';
    }

    case 'omada': {
      let attempts = 4;
      let lastErr;
      for (let i = 1; i <= attempts; i++) {
        try {
          let limit = customTimeLimit;
          if (limit === undefined || limit === null) {
            const branding = await db.getControllerConfig('branding') || {};
            limit = branding.sessionDurationMinutes !== undefined ? parseInt(branding.sessionDurationMinutes) : parseInt(process.env.SESSION_DURATION_MINUTES || '480');
          }
          await omadaSvc.authorizeClient({
            clientMac:   params.clientMac,
            siteId:      params.siteId,
            timeLimit:   parseInt(limit),
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

// ─── API: auto-liberación de dispositivos (autoservicio) ────────────────────
router.post('/auth/self-release',
  body('username').isString().trim().notEmpty(),
  body('macToDelete').isString().trim().notEmpty(),
  body('type').isString().trim().isIn(['cedula', 'ldap']),
  async (req, res, next) => {
    try {
      const { username, password, macToDelete, type, vendor, vendorParams } = req.body;
      const clientIp = req.ip || req.connection.remoteAddress;
      const params = typeof vendorParams === 'object' ? vendorParams : {};
      const newMac = (params.mac || params.clientMac || '').trim().toUpperCase().replace(/:/g, '-');
      const cleanMacToDelete = macToDelete.trim().toUpperCase().replace(/:/g, '-');

      if (!newMac) {
        return res.status(400).json({ error: 'No se detectó la MAC del dispositivo actual.' });
      }

      // 1. Validar credenciales según el tipo
      let user = await db.getUserByCedula(username.trim().toLowerCase());
      if (!user) {
        return res.status(404).json({ error: 'Usuario no encontrado.' });
      }
      if (!user.activo) {
        return res.status(403).json({ error: 'Su usuario ha sido desactivado.' });
      }

      if (type === 'ldap') {
        const ldapSvc = require('../services/ldap');
        const authResult = await ldapSvc.authenticate({ username, password });
        if (!authResult.success) {
          return res.status(401).json({ error: 'Credenciales institucionales incorrectas.' });
        }
      } else {
        // Para tipo cédula, validamos contra la cuenta local en RADIUS
        const radiusOk = await radius.authenticate(user.cedula, user.radius_password);
        if (!radiusOk) {
          return res.status(401).json({ error: 'Autenticación fallida.' });
        }
      }

      // 2. Verificar que la MAC a eliminar pertenezca al usuario
      const devices = await db.getUserDevices(user.cedula);
      const hasDevice = devices.some(d => d.mac_address.toUpperCase().replace(/:/g, '-') === cleanMacToDelete);
      if (!hasDevice) {
        return res.status(400).json({ error: 'El dispositivo seleccionado no pertenece a su usuario.' });
      }

      // 3. Eliminar dispositivo viejo de la base de datos
      await db.deleteUserDevice(user.cedula, cleanMacToDelete);
      console.log(`[SELF-RELEASE] Dispositivo viejo ${cleanMacToDelete} eliminado para usuario ${user.cedula}`);

      // 4. Desautorizar (kick/unauth) el dispositivo viejo en el controlador de red
      let detectedVendor = vendor || 'unknown';
      if (detectedVendor === 'unknown' || !detectedVendor) {
        if (process.env.OMADA_CONTROLLER_URL) detectedVendor = 'omada';
        else if (process.env.UNIFI_CONTROLLER_URL) detectedVendor = 'unifi';
      }

      if (detectedVendor === 'omada' && process.env.OMADA_CONTROLLER_URL) {
        const omadaSvc = require('../services/omada');
        omadaSvc.unauthorizeClient({ clientMac: cleanMacToDelete }).catch(err => {
          console.error(`[SELF-RELEASE] Error al desautorizar MAC vieja ${cleanMacToDelete} en Omada:`, err.message);
        });
      }

      // 5. Registrar el nuevo dispositivo (esto también aplica su perfil de velocidad)
      await db.registerUserDevice(user.cedula, newMac);
      console.log(`[SELF-RELEASE] Nuevo dispositivo ${newMac} registrado para usuario ${user.cedula}`);

      // 6. Autorizar el nuevo dispositivo
      let redirectUrl = params.redirectUrl || '/success';
      const finalParams = { ...params };
      if (!finalParams.clientMac) finalParams.clientMac = newMac;
      if (!finalParams.mac) finalParams.mac = newMac;

      if (detectedVendor === 'mikrotik') {
        redirectUrl = await authorizeVendor(detectedVendor, finalParams, user.cedula, user.radius_password);
      }

      res.json({
        success: true,
        nombre: user.nombres,
        redirectUrl: redirectUrl || '/success',
        ...(detectedVendor === 'mikrotik' ? { radiusPassword: user.radius_password } : {}),
      });

      // Procesar la autorización en background
      (async () => {
        try {
          await new Promise(resolve => setTimeout(resolve, 300));

          if (detectedVendor !== 'mikrotik') {
            await authorizeVendor(detectedVendor, finalParams, user.cedula, user.radius_password);
          }
          
          await db.startAcctSession({
            username: user.cedula,
            macAddress: newMac,
            ipAddress: clientIp,
            vendor: detectedVendor
          });
          
          await db.logAccess({
            cedula: user.cedula,
            vendor: detectedVendor,
            macAddress: newMac,
            ipAddress: clientIp,
            resultado: 'success',
          });
          
          console.log(`[SELF-RELEASE] Nuevo dispositivo ${newMac} autorizado exitosamente para ${user.cedula}`);
        } catch (vendorErr) {
          console.error(`[SELF-RELEASE] Error autorizando nuevo dispositivo en ${detectedVendor} (async):`, vendorErr.message);
        }
      })();

    } catch (err) {
      next(err);
    }
  }
);

module.exports = router;

'use strict';

const { Pool } = require('pg');
const { v4: uuidv4 } = require('uuid');

let pool;

async function connect() {
  pool = new Pool({
    host:     process.env.POSTGRES_HOST || 'postgres',
    port:     parseInt(process.env.POSTGRES_PORT || '5432'),
    database: process.env.POSTGRES_DB,
    user:     process.env.POSTGRES_USER,
    password: process.env.POSTGRES_PASSWORD,
    max: parseInt(process.env.DB_POOL_MAX || '40'),
    idleTimeoutMillis: parseInt(process.env.DB_POOL_IDLE_TIMEOUT || '10000'),
    connectionTimeoutMillis: parseInt(process.env.DB_POOL_CONN_TIMEOUT || '3000'),
  });

  // Verificar conexión e inicializar esquema adicional
  const client = await pool.connect();
  await client.query('SELECT 1');
  await client.query(`
    CREATE TABLE IF NOT EXISTS controller_config (
      vendor      TEXT PRIMARY KEY,
      config      JSONB NOT NULL DEFAULT '{}',
      updated_at  TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  // Crear tablas para administración multiusuario y auditoría
  await client.query(`
    CREATE TABLE IF NOT EXISTS administradores (
      id             SERIAL PRIMARY KEY,
      username       VARCHAR(50) UNIQUE NOT NULL,
      password_hash  VARCHAR(255) NOT NULL,
      nombres        VARCHAR(100) NOT NULL,
      activo         BOOLEAN DEFAULT TRUE,
      created_at     TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  await client.query(`
    CREATE TABLE IF NOT EXISTS admin_sessions (
      token       VARCHAR(255) PRIMARY KEY,
      username    VARCHAR(50) NOT NULL REFERENCES administradores(username) ON DELETE CASCADE,
      created_at  TIMESTAMPTZ DEFAULT NOW(),
      expires_at  TIMESTAMPTZ NOT NULL
    )
  `);

  await client.query(`
    CREATE TABLE IF NOT EXISTS auditoria_admin (
      id          SERIAL PRIMARY KEY,
      username    VARCHAR(50) NOT NULL,
      ip_address  VARCHAR(45) NOT NULL,
      accion      VARCHAR(100) NOT NULL,
      detalles    TEXT NOT NULL,
      created_at  TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  // Insertar administrador inicial por defecto si la tabla está vacía
  const adminCheck = await client.query('SELECT 1 FROM administradores LIMIT 1');
  if (adminCheck.rowCount === 0) {
    const adminSecret = process.env.ADMIN_SECRET || 'admin_secret_cambia_esto';
    const crypto = require('crypto');
    const salt = crypto.randomBytes(16).toString('hex');
    const hash = crypto.pbkdf2Sync(adminSecret, salt, 1000, 64, 'sha512').toString('hex');
    const dbHash = `${salt}:${hash}`;
    
    await client.query(
      `INSERT INTO administradores (username, password_hash, nombres, activo)
       VALUES ('admin', $1, 'Administrador Principal', TRUE)`,
      [dbHash]
    );
    console.log('[DB] Administrador principal ("admin") creado por defecto.');
  }

  // Asegurar que la columna terminos_aceptados exista en usuarios_portal
  try {
    await client.query(`
      ALTER TABLE usuarios_portal 
      ADD COLUMN IF NOT EXISTS terminos_aceptados TEXT;
    `);
  } catch (colErr) {
    console.error('[DB] Advertencia al validar columna terminos_aceptados:', colErr.message);
  }

  client.release();
  console.log('[DB] Conexión a PostgreSQL establecida');
}

/**
 * Verifica si un usuario existe por cédula.
 * @returns {boolean}
 */
async function userExists(cedula) {
  const result = await pool.query(
    'SELECT 1 FROM usuarios_portal WHERE cedula = $1 LIMIT 1',
    [cedula]
  );
  return result.rowCount > 0;
}

/**
 * Obtiene un usuario por cédula.
 * @returns {Object|null}
 */
async function getUserByCedula(cedula) {
  const result = await pool.query(
    'SELECT id, cedula, nombres, apellidos, email, radius_password, max_dispositivos, activo FROM usuarios_portal WHERE cedula = $1 LIMIT 1',
    [cedula]
  );
  return result.rows[0] || null;
}

/**
 * Crea un usuario nuevo y lo registra en radcheck para FreeRADIUS.
 * Usa una transacción para garantizar consistencia.
 * @returns {Object} usuario creado
 */
async function createUser({ cedula, nombres, apellidos, email, terminosAceptados }) {
  const radiusPassword = uuidv4();
  const client = await pool.connect();

  try {
    await client.query('BEGIN');

    // Insertar en tabla de usuarios del portal
    const userResult = await client.query(
      `INSERT INTO usuarios_portal (cedula, nombres, apellidos, email, radius_password, acepta_terminos, fecha_acepta_terminos, terminos_aceptados)
       VALUES ($1, $2, $3, $4, $5, TRUE, NOW(), $6)
       RETURNING id, cedula, nombres, apellidos, email, radius_password`,
      [cedula, nombres.trim(), apellidos.trim(), email.trim().toLowerCase(), radiusPassword, terminosAceptados || null]
    );

    const user = userResult.rows[0];

    // Insertar en radcheck para FreeRADIUS
    await client.query(
      `INSERT INTO radcheck (username, attribute, op, value)
       VALUES ($1, 'Cleartext-Password', ':=', $2)`,
      [cedula, radiusPassword]
    );

    // Asignar al grupo base
    await client.query(
      `INSERT INTO radusergroup (username, groupname, priority)
       VALUES ($1, 'captive-portal-users', 1)
       ON CONFLICT DO NOTHING`,
      [cedula]
    );

    await client.query('COMMIT');
    console.log(`[DB] Usuario registrado: ${cedula}`);
    return user;
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}

/**
 * Registra un evento de acceso para auditoría.
 */
async function logAccess({ cedula, vendor, macAddress, ipAddress, resultado }) {
  try {
    await pool.query(
      `INSERT INTO access_log (cedula, vendor, mac_address, ip_address, resultado)
       VALUES ($1, $2, $3, $4::inet, $5)`,
      [cedula, vendor || null, macAddress || null, ipAddress || null, resultado]
    );
  } catch (err) {
    // El log no debe fallar la autenticación
    console.error('[DB] Error al registrar acceso:', err.message);
  }
}

/**
 * Actualiza la aceptación de términos para un usuario existente.
 */
async function updateTermsAcceptance(cedula, terminosAceptados) {
  try {
    await pool.query(
      `UPDATE usuarios_portal
       SET acepta_terminos = TRUE, fecha_acepta_terminos = NOW(), terminos_aceptados = $2
       WHERE cedula = $1`,
      [cedula, terminosAceptados || null]
    );
  } catch (err) {
    console.error('[DB] Error al actualizar aceptación de términos:', err.message);
  }
}

// ─── Admin: Usuarios ─────────────────────────────────────────────────────────

/**
 * Lista usuarios con búsqueda y paginación.
 */
async function listUsers({ search = '', limit = 50, offset = 0 } = {}) {
  const where = search
    ? `WHERE cedula ILIKE $3 OR nombres ILIKE $3 OR apellidos ILIKE $3 OR email ILIKE $3`
    : '';
  const params = search
    ? [limit, offset, `%${search}%`]
    : [limit, offset];

  const result = await pool.query(
    `SELECT id, cedula, nombres, apellidos, email, activo, fecha_registro
     FROM usuarios_portal
     ${where}
     ORDER BY fecha_registro DESC
     LIMIT $1 OFFSET $2`,
    params
  );

  const total = await pool.query(
    `SELECT COUNT(*) FROM usuarios_portal ${where}`,
    search ? [`%${search}%`] : []
  );

  return { users: result.rows, total: parseInt(total.rows[0].count) };
}

/**
 * Detalle de un usuario: datos + grupos RADIUS + últimos accesos.
 */
async function getUserDetail(cedula) {
  const [user, groups, logs, devices] = await Promise.all([
    pool.query(
      `SELECT id, cedula, nombres, apellidos, email, activo, fecha_registro, max_dispositivos, acepta_terminos, fecha_acepta_terminos, terminos_aceptados
       FROM usuarios_portal WHERE cedula = $1`,
      [cedula]
    ),
    pool.query(
      `SELECT ug.groupname, ug.priority
       FROM radusergroup ug WHERE ug.username = $1 ORDER BY ug.priority`,
      [cedula]
    ),
    pool.query(
      `SELECT vendor, mac_address, ip_address, resultado, created_at
       FROM access_log WHERE cedula = $1 ORDER BY created_at DESC LIMIT 20`,
      [cedula]
    ),
    pool.query(
      `SELECT id, mac_address, created_at
       FROM dispositivos_usuario WHERE cedula = $1 ORDER BY created_at DESC`,
      [cedula]
    ),
  ]);

  if (!user.rows[0]) return null;
  return {
    ...user.rows[0],
    groups: groups.rows,
    recentLogs: logs.rows,
    devices: devices.rows,
  };
}

/**
 * Activa o desactiva un usuario (también habilita/deshabilita en radcheck).
 */
async function setUserActive(cedula, active) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query(
      `UPDATE usuarios_portal SET activo = $2 WHERE cedula = $1`,
      [cedula, active]
    );
    if (active) {
      // Re-insertar radcheck si fue eliminado
      const u = await client.query(
        `SELECT radius_password FROM usuarios_portal WHERE cedula = $1`,
        [cedula]
      );
      if (u.rows[0]) {
        await client.query(
          `INSERT INTO radcheck (username, attribute, op, value)
           VALUES ($1, 'Cleartext-Password', ':=', $2)
           ON CONFLICT DO NOTHING`,
          [cedula, u.rows[0].radius_password]
        );
      }
    } else {
      await client.query(
        `DELETE FROM radcheck WHERE username = $1 AND attribute = 'Cleartext-Password'`,
        [cedula]
      );
    }
    await client.query('COMMIT');
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}

/**
 * Elimina un usuario y todos sus registros RADIUS.
 */
async function deleteUser(cedula) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query(`DELETE FROM radcheck    WHERE username = $1`, [cedula]);
    await client.query(`DELETE FROM radreply    WHERE username = $1`, [cedula]);
    await client.query(`DELETE FROM radusergroup WHERE username = $1`, [cedula]);
    await client.query(`DELETE FROM usuarios_portal WHERE cedula = $1`, [cedula]);
    await client.query('COMMIT');
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}

/**
 * Asigna los grupos RADIUS de un usuario (reemplaza todos).
 */
async function setUserGroups(cedula, groups) {
  // groups: [{ groupname, priority }]
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query(`DELETE FROM radusergroup WHERE username = $1`, [cedula]);
    for (const g of groups) {
      await client.query(
        `INSERT INTO radusergroup (username, groupname, priority) VALUES ($1, $2, $3)`,
        [cedula, g.groupname, g.priority || 1]
      );
    }
    await client.query('COMMIT');
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}

// ─── Admin: Grupos RADIUS ─────────────────────────────────────────────────────

/**
 * Lista todos los grupos con sus atributos de respuesta.
 */
async function listGroups() {
  const groups = await pool.query(
    `SELECT DISTINCT groupname FROM radgroupreply ORDER BY groupname`
  );

  const attrs = await pool.query(
    `SELECT id, groupname, attribute, op, value FROM radgroupreply ORDER BY groupname, id`
  );

  // Contar usuarios por grupo
  const counts = await pool.query(
    `SELECT groupname, COUNT(*) as total FROM radusergroup GROUP BY groupname`
  );
  const countMap = {};
  counts.rows.forEach(r => { countMap[r.groupname] = parseInt(r.total); });

  const attrsByGroup = {};
  attrs.rows.forEach(r => {
    if (!attrsByGroup[r.groupname]) attrsByGroup[r.groupname] = [];
    attrsByGroup[r.groupname].push(r);
  });

  return groups.rows.map(g => ({
    groupname: g.groupname,
    userCount: countMap[g.groupname] || 0,
    attributes: attrsByGroup[g.groupname] || [],
  }));
}

/**
 * Agrega un atributo a un grupo.
 */
async function addGroupAttribute({ groupname, attribute, op, value }) {
  const result = await pool.query(
    `INSERT INTO radgroupreply (groupname, attribute, op, value)
     VALUES ($1, $2, $3, $4) RETURNING *`,
    [groupname, attribute, op, value]
  );
  return result.rows[0];
}

/**
 * Elimina un atributo de grupo por ID.
 */
async function deleteGroupAttribute(id) {
  await pool.query(`DELETE FROM radgroupreply WHERE id = $1`, [id]);
}

/**
 * Elimina un grupo completo y desvincula usuarios.
 */
async function deleteGroup(groupname) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query(`DELETE FROM radgroupreply  WHERE groupname = $1`, [groupname]);
    await client.query(`DELETE FROM radgroupcheck  WHERE groupname = $1`, [groupname]);
    await client.query(`DELETE FROM radusergroup   WHERE groupname = $1`, [groupname]);
    await client.query('COMMIT');
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}

// ─── Admin: Estadísticas ──────────────────────────────────────────────────────

async function getStats() {
  const [totals, today, byVendor, byResult, recentLogs] = await Promise.all([
    pool.query(`
      SELECT
        COUNT(*) FILTER (WHERE activo = TRUE)  AS active_users,
        COUNT(*) FILTER (WHERE activo = FALSE) AS inactive_users,
        COUNT(*)                               AS total_users
      FROM usuarios_portal
    `),
    pool.query(`
      SELECT COUNT(*) AS today_logins
      FROM access_log
      WHERE created_at >= CURRENT_DATE AND resultado = 'success'
    `),
    pool.query(`
      SELECT vendor, COUNT(*) AS total
      FROM access_log
      WHERE created_at >= NOW() - INTERVAL '7 days'
      GROUP BY vendor ORDER BY total DESC
    `),
    pool.query(`
      SELECT resultado, COUNT(*) AS total
      FROM access_log
      WHERE created_at >= NOW() - INTERVAL '7 days'
      GROUP BY resultado
    `),
    pool.query(`
      SELECT a.cedula, u.nombres, u.apellidos, a.vendor, a.resultado, a.created_at
      FROM access_log a
      LEFT JOIN usuarios_portal u ON u.cedula = a.cedula
      ORDER BY a.created_at DESC LIMIT 10
    `),
  ]);

  return {
    ...totals.rows[0],
    todayLogins: parseInt(today.rows[0].today_logins),
    byVendor: byVendor.rows,
    byResult: byResult.rows,
    recentLogs: recentLogs.rows,
  };
}

// ─── Admin: Configuración de controladores ────────────────────────────────────

async function getControllerConfig(vendor) {
  const result = await pool.query(
    'SELECT config FROM controller_config WHERE vendor = $1',
    [vendor]
  );
  return result.rows[0]?.config || null;
}

async function saveControllerConfig(vendor, config) {
  await pool.query(
    `INSERT INTO controller_config (vendor, config, updated_at)
     VALUES ($1, $2, NOW())
     ON CONFLICT (vendor) DO UPDATE SET config = EXCLUDED.config, updated_at = NOW()`,
    [vendor, JSON.stringify(config)]
  );
}

async function getUsersReport({ search = '', startDate, endDate, limit = 50, offset = 0 } = {}) {
  let query = `
    SELECT id, cedula, nombres, apellidos, email, activo, fecha_registro, acepta_terminos, fecha_acepta_terminos,
           (SELECT mac_address FROM access_log WHERE cedula = usuarios_portal.cedula AND mac_address IS NOT NULL AND mac_address != '' ORDER BY created_at DESC LIMIT 1) AS mac_address
    FROM usuarios_portal
    WHERE 1=1
  `;
  const params = [];
  let paramIdx = 1;

  if (search) {
    query += ` AND (cedula ILIKE $${paramIdx} OR nombres ILIKE $${paramIdx} OR apellidos ILIKE $${paramIdx} OR email ILIKE $${paramIdx} OR EXISTS (SELECT 1 FROM access_log WHERE cedula = usuarios_portal.cedula AND mac_address ILIKE $${paramIdx}))`;
    params.push(`%${search}%`);
    paramIdx++;
  }

  if (startDate) {
    query += ` AND fecha_registro >= $${paramIdx}`;
    params.push(startDate);
    paramIdx++;
  }

  if (endDate) {
    query += ` AND fecha_registro <= $${paramIdx}`;
    params.push(endDate);
    paramIdx++;
  }

  // Get total count
  const countQuery = `SELECT COUNT(*) FROM (${query}) AS total`;
  const totalRes = await pool.query(countQuery, params);

  query += ` ORDER BY fecha_registro DESC LIMIT $${paramIdx} OFFSET $${paramIdx + 1}`;
  params.push(limit, offset);

  const res = await pool.query(query, params);

  return { data: res.rows, total: parseInt(totalRes.rows[0].count) };
}

async function getConnectionsReport({ search = '', startDate, endDate, limit = 50, offset = 0 } = {}) {
  let query = `
    SELECT r.radacctid, r.username, u.nombres, u.apellidos, r.callingstationid AS mac_address,
           r.framedipaddress AS ip_address, r.acctstarttime AS start_time, r.acctstoptime AS stop_time,
           r.acctsessiontime AS duration, r.acctinputoctets AS upload, r.acctoutputoctets AS download
    FROM radacct r
    LEFT JOIN usuarios_portal u ON r.username = u.cedula
    WHERE 1=1
  `;
  const params = [];
  let paramIdx = 1;

  if (search) {
    query += ` AND (r.username ILIKE $${paramIdx} OR u.nombres ILIKE $${paramIdx} OR u.apellidos ILIKE $${paramIdx} OR r.callingstationid ILIKE $${paramIdx} OR CAST(r.framedipaddress AS TEXT) ILIKE $${paramIdx})`;
    params.push(`%${search}%`);
    paramIdx++;
  }

  if (startDate) {
    query += ` AND r.acctstarttime >= $${paramIdx}`;
    params.push(startDate);
    paramIdx++;
  }

  if (endDate) {
    query += ` AND r.acctstarttime <= $${paramIdx}`;
    params.push(endDate);
    paramIdx++;
  }

  // Get total count
  const countQuery = `SELECT COUNT(*) FROM (${query}) AS total`;
  const totalRes = await pool.query(countQuery, params);

  query += ` ORDER BY r.acctstarttime DESC LIMIT $${paramIdx} OFFSET $${paramIdx + 1}`;
  params.push(limit, offset);

  const res = await pool.query(query, params);

  return { data: res.rows, total: parseInt(totalRes.rows[0].count) };
}

async function getAccessLogReport({ search = '', startDate, endDate, limit = 50, offset = 0 } = {}) {
  let query = `
    SELECT a.id, a.cedula, u.nombres, u.apellidos, a.vendor, a.mac_address, a.ip_address, a.resultado, a.created_at
    FROM access_log a
    LEFT JOIN usuarios_portal u ON a.cedula = u.cedula
    WHERE 1=1
  `;
  const params = [];
  let paramIdx = 1;

  if (search) {
    query += ` AND (a.cedula ILIKE $${paramIdx} OR u.nombres ILIKE $${paramIdx} OR u.apellidos ILIKE $${paramIdx} OR a.mac_address ILIKE $${paramIdx} OR CAST(a.ip_address AS TEXT) ILIKE $${paramIdx})`;
    params.push(`%${search}%`);
    paramIdx++;
  }

  if (startDate) {
    query += ` AND a.created_at >= $${paramIdx}`;
    params.push(startDate);
    paramIdx++;
  }

  if (endDate) {
    query += ` AND a.created_at <= $${paramIdx}`;
    params.push(endDate);
    paramIdx++;
  }

  // Get total count
  const countQuery = `SELECT COUNT(*) FROM (${query}) AS total`;
  const totalRes = await pool.query(countQuery, params);

  query += ` ORDER BY a.created_at DESC LIMIT $${paramIdx} OFFSET $${paramIdx + 1}`;
  params.push(limit, offset);

  const res = await pool.query(query, params);

  return { data: res.rows, total: parseInt(totalRes.rows[0].count) };
}

// ─── Dispositivos por Usuario ────────────────────────────────────────────────
async function getUserDevices(cedula) {
  const res = await pool.query(
    'SELECT id, mac_address, created_at FROM dispositivos_usuario WHERE cedula = $1 ORDER BY created_at DESC',
    [cedula]
  );
  return res.rows;
}

async function registerUserDevice(cedula, macAddress) {
  if (!macAddress) return;
  await pool.query(
    `INSERT INTO dispositivos_usuario (cedula, mac_address)
     VALUES ($1, $2)
     ON CONFLICT (cedula, mac_address) DO NOTHING`,
    [cedula, macAddress.trim().toUpperCase()]
  );
}

async function deleteUserDevice(cedula, macAddress) {
  if (!macAddress) return;
  await pool.query(
    'DELETE FROM dispositivos_usuario WHERE cedula = $1 AND mac_address = $2',
    [cedula, macAddress.trim().toUpperCase()]
  );
}

async function setUserMaxDevices(cedula, maxDevices) {
  await pool.query(
    'UPDATE usuarios_portal SET max_dispositivos = $2 WHERE cedula = $1',
    [cedula, maxDevices === null ? null : (parseInt(maxDevices) || 0)]
  );
}

async function getUserDevicesCount(cedula) {
  const res = await pool.query(
    'SELECT COUNT(*) FROM dispositivos_usuario WHERE cedula = $1',
    [cedula]
  );
  return parseInt(res.rows[0].count);
}

async function isDeviceRegistered(cedula, macAddress) {
  if (!macAddress) return false;
  const res = await pool.query(
    'SELECT 1 FROM dispositivos_usuario WHERE cedula = $1 AND mac_address = $2 LIMIT 1',
    [cedula, macAddress.trim().toUpperCase()]
  );
  return res.rowCount > 0;
}

async function getUserByDeviceMac(macAddress) {
  if (!macAddress) return null;
  const res = await pool.query(
    `SELECT u.cedula, u.nombres, u.activo 
     FROM usuarios_portal u
     JOIN dispositivos_usuario d ON u.cedula = d.cedula
     WHERE d.mac_address = $1 LIMIT 1`,
    [macAddress.trim().toUpperCase()]
  );
  return res.rows[0] || null;
}

// ─── Gestión de administradores y auditoría ────────────────────────────────────
const crypto = require('crypto');

function hashAdminPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.pbkdf2Sync(password, salt, 1000, 64, 'sha512').toString('hex');
  return `${salt}:${hash}`;
}

function verifyAdminPassword(password, storedHash) {
  const [salt, hash] = storedHash.split(':');
  const checkHash = crypto.pbkdf2Sync(password, salt, 1000, 64, 'sha512').toString('hex');
  return hash === checkHash;
}

async function verifyAdminLogin(username, password) {
  const res = await pool.query(
    'SELECT username, password_hash, nombres, activo FROM administradores WHERE username = $1 LIMIT 1',
    [username.trim().toLowerCase()]
  );
  const admin = res.rows[0];
  if (!admin || !admin.activo) return null;
  if (verifyAdminPassword(password, admin.password_hash)) {
    return { username: admin.username, nombres: admin.nombres };
  }
  return null;
}

async function createAdminSession(username) {
  const token = crypto.randomBytes(32).toString('hex');
  const expiresAt = new Date(Date.now() + 2 * 60 * 60 * 1000); // 2 horas
  await pool.query(
    `INSERT INTO admin_sessions (token, username, expires_at)
     VALUES ($1, $2, $3)`,
    [token, username, expiresAt]
  );
  return { token, expiresAt };
}

async function getAdminBySessionToken(token) {
  const res = await pool.query(
    `SELECT username FROM admin_sessions
     WHERE token = $1 AND expires_at > NOW() LIMIT 1`,
    [token]
  );
  const session = res.rows[0];
  if (!session) return null;
  
  // Renovar expiración por 2 horas más
  const newExpiresAt = new Date(Date.now() + 2 * 60 * 60 * 1000);
  await pool.query(
    'UPDATE admin_sessions SET expires_at = $1 WHERE token = $2',
    [newExpiresAt, token]
  );
  
  return session.username;
}

async function deleteAdminSession(token) {
  await pool.query('DELETE FROM admin_sessions WHERE token = $1', [token]);
}

async function logAdminAudit({ username, ipAddress, accion, detalles }) {
  await pool.query(
    `INSERT INTO auditoria_admin (username, ip_address, accion, detalles)
     VALUES ($1, $2, $3, $4)`,
    [username, ipAddress, accion, detalles]
  );
}

async function listAdmins() {
  const res = await pool.query(
    'SELECT id, username, nombres, activo, created_at FROM administradores ORDER BY username ASC'
  );
  return res.rows;
}

async function createAdmin({ username, password, nombres }) {
  const hash = hashAdminPassword(password);
  const res = await pool.query(
    `INSERT INTO administradores (username, password_hash, nombres, activo)
     VALUES ($1, $2, $3, TRUE)
     RETURNING id, username, nombres`,
    [username.trim().toLowerCase(), hash, nombres.trim()]
  );
  return res.rows[0];
}

async function updateAdminStatus(username, activo) {
  if (username.trim().toLowerCase() === 'admin') {
    throw new Error('No se puede desactivar al administrador principal "admin".');
  }
  await pool.query(
    'UPDATE administradores SET activo = $1 WHERE username = $2',
    [activo, username.trim().toLowerCase()]
  );
}

async function updateAdminPassword(username, newPassword) {
  const hash = hashAdminPassword(newPassword);
  await pool.query(
    'UPDATE administradores SET password_hash = $1 WHERE username = $2',
    [hash, username.trim().toLowerCase()]
  );
}

async function deleteAdmin(username) {
  const userLower = username.trim().toLowerCase();
  if (userLower === 'admin') {
    throw new Error('No se puede eliminar al administrador principal "admin".');
  }
  await pool.query('DELETE FROM administradores WHERE username = $1', [userLower]);
}

async function getAdminAuditLogs({ search = '', limit = 50, offset = 0 }) {
  let queryStr = 'SELECT id, username, ip_address, accion, detalles, created_at FROM auditoria_admin ';
  const params = [];
  
  if (search) {
    queryStr += 'WHERE username ILIKE $1 OR accion ILIKE $1 OR detalles ILIKE $1 ';
    params.push(`%${search}%`);
  }
  
  queryStr += 'ORDER BY created_at DESC LIMIT $' + (params.length + 1) + ' OFFSET $' + (params.length + 2);
  params.push(limit, offset);
  
  const res = await pool.query(queryStr, params);
  
  let countQuery = 'SELECT COUNT(*) FROM auditoria_admin ';
  const countParams = [];
  if (search) {
    countQuery += 'WHERE username ILIKE $1 OR accion ILIKE $1 OR detalles ILIKE $1';
    countParams.push(`%${search}%`);
  }
  const countRes = await pool.query(countQuery, countParams);
  
  return {
    logs: res.rows,
    total: parseInt(countRes.rows[0].count, 10),
  };
}

module.exports = {
  connect,
  userExists, getUserByCedula, createUser, logAccess, updateTermsAcceptance,
  // admin
  listUsers, getUserDetail, setUserActive, deleteUser, setUserGroups,
  listGroups, addGroupAttribute, deleteGroupAttribute, deleteGroup,
  getStats,
  getControllerConfig, saveControllerConfig,
  getUsersReport, getConnectionsReport, getAccessLogReport,
  // dispositivos
  getUserDevices, registerUserDevice, deleteUserDevice, setUserMaxDevices,
  getUserDevicesCount, isDeviceRegistered, getUserByDeviceMac,
  // administradores y auditoría
  verifyAdminLogin, createAdminSession, getAdminBySessionToken, deleteAdminSession,
  logAdminAudit, listAdmins, createAdmin, updateAdminStatus, updateAdminPassword,
  deleteAdmin, getAdminAuditLogs,
};

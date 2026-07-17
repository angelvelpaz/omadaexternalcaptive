'use strict';

const { Pool } = require('pg');
const { v4: uuidv4 } = require('uuid');
const { getVendor } = require('mac-oui-lookup');

let pool;

function getPool() {
  return pool;
}

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

  // Asegurar que las columnas terminos_aceptados y tipo_usuario existan en usuarios_portal
  try {
    await client.query(`
      ALTER TABLE usuarios_portal 
      ADD COLUMN IF NOT EXISTS terminos_aceptados TEXT;
    `);
    await client.query(`
      ALTER TABLE usuarios_portal 
      ADD COLUMN IF NOT EXISTS tipo_usuario VARCHAR(20) DEFAULT 'externo';
    `);
  } catch (colErr) {
    console.error('[DB] Advertencia al validar columnas adicionales en usuarios_portal:', colErr.message);
  }

  // Inicializar grupos RADIUS por defecto si no existen
  try {
    await client.query(`
      INSERT INTO radgroupreply (groupname, attribute, op, value)
      SELECT groupname, attribute, op, value FROM (
        VALUES
          ('captive-portal-users-institucional', 'Session-Timeout', ':=', '43200'),
          ('captive-portal-users-institucional', 'Idle-Timeout', ':=', '3600'),
          ('captive-portal-users-institucional', 'WISPr-Bandwidth-Max-Up', ':=', '10240000'),
          ('captive-portal-users-institucional', 'WISPr-Bandwidth-Max-Down', ':=', '20480000'),
          ('captive-portal-users-externo', 'Session-Timeout', ':=', '7200'),
          ('captive-portal-users-externo', 'Idle-Timeout', ':=', '900'),
          ('captive-portal-users-externo', 'WISPr-Bandwidth-Max-Up', ':=', '3145728'),
          ('captive-portal-users-externo', 'WISPr-Bandwidth-Max-Down', ':=', '5242880')
      ) AS t(groupname, attribute, op, value)
      WHERE NOT EXISTS (
        SELECT 1 FROM radgroupreply r 
        WHERE r.groupname = t.groupname AND r.attribute = t.attribute
      );
    `);
  } catch (grpErr) {
    console.error('[DB] Advertencia al sembrar grupos RADIUS:', grpErr.message);
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
async function createUser({ cedula, nombres, apellidos, email, terminosAceptados, tipo_usuario = 'externo' }) {
  const radiusPassword = uuidv4();
  const client = await pool.connect();

  try {
    await client.query('BEGIN');

    // Insertar en tabla de usuarios del portal
    const userResult = await client.query(
      `INSERT INTO usuarios_portal (cedula, nombres, apellidos, email, radius_password, acepta_terminos, fecha_acepta_terminos, terminos_aceptados, tipo_usuario)
       VALUES ($1, $2, $3, $4, $5, TRUE, NOW(), $6, $7)
       RETURNING id, cedula, nombres, apellidos, email, radius_password, tipo_usuario`,
      [cedula, nombres.trim(), apellidos.trim(), email.trim().toLowerCase(), radiusPassword, terminosAceptados || null, tipo_usuario]
    );

    const user = userResult.rows[0];

    // Insertar en radcheck para FreeRADIUS
    await client.query(
      `INSERT INTO radcheck (username, attribute, op, value)
       VALUES ($1, 'Cleartext-Password', ':=', $2)`,
      [cedula, radiusPassword]
    );

    // Asignar al grupo de RADIUS correcto
    const groupName = tipo_usuario === 'institucional' ? 'captive-portal-users-institucional' : 'captive-portal-users-externo';
    await client.query(
      `INSERT INTO radusergroup (username, groupname, priority)
       VALUES ($1, $2, 1)
       ON CONFLICT DO NOTHING`,
      [cedula, groupName]
    );

    await client.query('COMMIT');
    console.log(`[DB] Usuario registrado (${tipo_usuario}): ${cedula}`);
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

async function updateUserType(cedula, tipoUsuario) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query(
      `UPDATE usuarios_portal SET tipo_usuario = $1 WHERE cedula = $2`,
      [tipoUsuario, cedula]
    );
    const groupName = tipoUsuario === 'institucional' ? 'captive-portal-users-institucional' : 'captive-portal-users-externo';
    
    // Delete previous groups
    await client.query(
      `DELETE FROM radusergroup WHERE username = $1`,
      [cedula]
    );
    // Insert new group
    await client.query(
      `INSERT INTO radusergroup (username, groupname, priority) VALUES ($1, $2, 1)`,
      [cedula, groupName]
    );
    await client.query('COMMIT');
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}

async function bulkUpdateUserType(cedulas, tipoUsuario) {
  if (!Array.isArray(cedulas) || cedulas.length === 0) return;
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query(
      `UPDATE usuarios_portal SET tipo_usuario = $1 WHERE cedula = ANY($2)`,
      [tipoUsuario, cedulas]
    );
    const groupName = tipoUsuario === 'institucional' ? 'captive-portal-users-institucional' : 'captive-portal-users-externo';
    
    // Delete old groups
    await client.query(
      `DELETE FROM radusergroup WHERE username = ANY($1)`,
      [cedulas]
    );
    
    // Insert new groups
    for (const ced of cedulas) {
      await client.query(
        `INSERT INTO radusergroup (username, groupname, priority) VALUES ($1, $2, 1) ON CONFLICT DO NOTHING`,
        [ced, groupName]
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

// ─── Admin: Usuarios ─────────────────────────────────────────────────────────

/**
 * Lista usuarios con búsqueda y paginación.
 */
async function listUsers({ 
  search = '', 
  limit = 50, 
  offset = 0, 
  orderBy = 'fecha_registro', 
  orderDir = 'DESC', 
  filterLastConnStart = '', 
  filterLastConnEnd = '', 
  filterConsumption = 'all' 
} = {}) {
  const trimmed = (search || '').trim();
  const searchParam = `%${trimmed}%`;
  const cleanSearch = trimmed.replace(/[:\-]/g, '');
  const macSearchParam = `%${cleanSearch}%`;

  // Columnas permitidas para ordenación
  const validSortCols = {
    fecha_registro: 'fecha_registro',
    ultima_conexion: 'ultima_conexion',
    consumo_total: 'consumo_total'
  };
  const sortCol = validSortCols[orderBy] || 'fecha_registro';
  const sortDir = orderDir === 'ASC' ? 'ASC' : 'DESC';

  // Construir consulta base
  let sql = `
    SELECT * FROM (
      SELECT u.id, u.cedula, u.nombres, u.apellidos, u.email, u.activo, u.fecha_registro, u.tipo_usuario,
             (
               SELECT MAX(r.acctstarttime) 
               FROM radacct r 
               LEFT JOIN dispositivos_usuario d ON d.cedula = u.cedula
               WHERE r.username = u.cedula OR REPLACE(UPPER(r.callingstationid), ':', '-') = REPLACE(UPPER(d.mac_address), ':', '-')
             ) AS ultima_conexion,
             (
               SELECT COALESCE(SUM(r.acctinputoctets + r.acctoutputoctets), 0)
               FROM radacct r 
               LEFT JOIN dispositivos_usuario d ON d.cedula = u.cedula
               WHERE r.username = u.cedula OR REPLACE(UPPER(r.callingstationid), ':', '-') = REPLACE(UPPER(d.mac_address), ':', '-')
             ) AS consumo_total
      FROM usuarios_portal u
    ) u_agg
    WHERE 1=1
  `;

  const params = [];
  let paramIdx = 1;

  // Filtro de búsqueda
  if (trimmed) {
    sql += ` AND (
      cedula ILIKE $${paramIdx} 
      OR nombres ILIKE $${paramIdx} 
      OR apellidos ILIKE $${paramIdx} 
      OR email ILIKE $${paramIdx} 
      OR EXISTS (
        SELECT 1 FROM dispositivos_usuario d 
        WHERE d.cedula = u_agg.cedula 
          AND (d.mac_address ILIKE $${paramIdx} OR REPLACE(REPLACE(d.mac_address, ':', ''), '-', '') ILIKE $${paramIdx + 1})
      )
    )`;
    params.push(searchParam);
    params.push(macSearchParam);
    paramIdx += 2;
  }

  // Filtro última conexión (Rango de fechas)
  if (filterLastConnStart) {
    sql += ` AND ultima_conexion >= $${paramIdx}::timestamptz`;
    params.push(filterLastConnStart + ' 00:00:00');
    paramIdx++;
  }
  if (filterLastConnEnd) {
    sql += ` AND ultima_conexion <= ($${paramIdx} || ' 23:59:59')::timestamptz`;
    params.push(filterLastConnEnd);
    paramIdx++;
  }

  // Filtro consumo total
  if (filterConsumption === 'zero') {
    sql += ` AND consumo_total = 0`;
  } else if (filterConsumption === 'low') {
    sql += ` AND consumo_total > 0 AND consumo_total < 100 * 1024 * 1024`;
  } else if (filterConsumption === 'medium') {
    sql += ` AND consumo_total >= 100 * 1024 * 1024 AND consumo_total <= 1024 * 1024 * 1024`;
  } else if (filterConsumption === 'high') {
    sql += ` AND consumo_total > 1024 * 1024 * 1024`;
  }

  // Consulta para obtener el total de registros filtrados
  let countSql = `SELECT COUNT(*) FROM (${sql}) count_agg`;
  
  // Agregar ordenación y límites
  sql += ` ORDER BY ${sortCol} ${sortDir} NULLS LAST`;
  sql += ` LIMIT $${paramIdx} OFFSET $${paramIdx + 1}`;
  params.push(parseInt(limit));
  params.push(parseInt(offset));

  const [result, total] = await Promise.all([
    pool.query(sql, params),
    pool.query(countSql, params.slice(0, paramIdx - 1))
  ]);

  return { 
    users: result.rows.map(r => ({
      ...r,
      consumo_total: parseInt(r.consumo_total || 0)
    })), 
    total: parseInt(total.rows[0].count) 
  };
}

/**
 * Detalle de un usuario: datos + grupos RADIUS + últimos accesos.
 */
async function getUserDetail(cedula) {
  const [user, groups, logs, devices] = await Promise.all([
    pool.query(
      `SELECT id, cedula, nombres, apellidos, email, activo, fecha_registro, max_dispositivos, acepta_terminos, fecha_acepta_terminos, terminos_aceptados, tipo_usuario
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

async function bulkDeleteUsers(cedulas, purgeHistory = false) {
  if (!Array.isArray(cedulas) || cedulas.length === 0) return;
  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    if (purgeHistory) {
      // 1. Obtener todas las MACs de dispositivos de los usuarios
      const macsRes = await client.query(
        'SELECT mac_address FROM dispositivos_usuario WHERE cedula = ANY($1)',
        [cedulas]
      );
      const macs = [];
      for (const r of macsRes.rows) {
        const clean = r.mac_address.trim().toUpperCase();
        macs.push(clean.replace(/:/g, '-'));
        macs.push(clean.replace(/-/g, ':'));
      }

      // 2. Eliminar de radacct (tanto por cédula como por MAC de sus dispositivos)
      await client.query(
        `DELETE FROM radacct WHERE username = ANY($1) OR UPPER(callingstationid) = ANY($2)`,
        [cedulas, macs]
      );

      // 3. Eliminar dispositivos registrados
      await client.query(
        `DELETE FROM dispositivos_usuario WHERE cedula = ANY($1)`,
        [cedulas]
      );

      // 4. Eliminar historial de accesos
      await client.query(
        `DELETE FROM access_log WHERE cedula = ANY($1)`,
        [cedulas]
      );
    }

    // 5. Eliminar credenciales y perfil (siempre se ejecuta)
    await client.query(`DELETE FROM radcheck    WHERE username = ANY($1)`, [cedulas]);
    await client.query(`DELETE FROM radreply    WHERE username = ANY($1)`, [cedulas]);
    await client.query(`DELETE FROM radusergroup WHERE username = ANY($1)`, [cedulas]);
    await client.query(`DELETE FROM usuarios_portal WHERE cedula = ANY($1)`, [cedulas]);
    await client.query('COMMIT');
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}

async function bulkUpdateUserActive(cedulas, active) {
  if (!Array.isArray(cedulas) || cedulas.length === 0) return;
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query(
      `UPDATE usuarios_portal SET activo = $1 WHERE cedula = ANY($2)`,
      [active, cedulas]
    );

    if (active) {
      // Re-insertar radcheck para cada usuario de la lista
      const users = await client.query(
        `SELECT cedula, radius_password FROM usuarios_portal WHERE cedula = ANY($1)`,
        [cedulas]
      );
      for (const u of users.rows) {
        await client.query(
          `INSERT INTO radcheck (username, attribute, op, value)
           VALUES ($1, 'Cleartext-Password', ':=', $2)
           ON CONFLICT DO NOTHING`,
          [u.cedula, u.radius_password]
        );
      }
    } else {
      // Eliminar de radcheck
      await client.query(
        `DELETE FROM radcheck WHERE username = ANY($1) AND attribute = 'Cleartext-Password'`,
        [cedulas]
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
async function deleteUser(cedula, purgeHistory = false) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    if (purgeHistory) {
      // 1. Obtener todas las MACs de dispositivos del usuario
      const macsRes = await client.query(
        'SELECT mac_address FROM dispositivos_usuario WHERE cedula = $1',
        [cedula]
      );
      const macs = [];
      for (const r of macsRes.rows) {
        const clean = r.mac_address.trim().toUpperCase();
        macs.push(clean.replace(/:/g, '-'));
        macs.push(clean.replace(/-/g, ':'));
      }

      // 2. Eliminar de radacct (tanto por cédula como por MAC de sus dispositivos)
      await client.query(
        `DELETE FROM radacct WHERE username = $1 OR UPPER(callingstationid) = ANY($2)`,
        [cedula, macs]
      );

      // 3. Eliminar dispositivos registrados
      await client.query(
        `DELETE FROM dispositivos_usuario WHERE cedula = $1`,
        [cedula]
      );

      // 4. Eliminar historial de accesos
      await client.query(
        `DELETE FROM access_log WHERE cedula = $1`,
        [cedula]
      );
    }

    // 5. Eliminar credenciales y perfil (siempre se ejecuta)
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

function cleanVendorName(rawName) {
  if (!rawName) return 'Genérico / Privado';
  const name = rawName.toLowerCase();
  if (name.includes('apple')) return 'Apple';
  if (name.includes('samsung')) return 'Samsung';
  if (name.includes('huawei')) return 'Huawei';
  if (name.includes('xiaomi') || name.includes('chongqing chimi') || name.includes('beijing xiaomi')) return 'Xiaomi';
  if (name.includes('motorola') || name.includes('lenovo')) return 'Motorola/Lenovo';
  if (name.includes('tp-link') || name.includes('shenzhen tp-link')) return 'TP-Link';
  if (name.includes('intel')) return 'Intel';
  if (name.includes('lg electronics') || name.includes('lg ')) return 'LG';
  if (name.includes('oppo') || name.includes('guangdong oppo')) return 'Oppo';
  if (name.includes('vivo mobile')) return 'Vivo';
  if (name.includes('realme')) return 'Realme';
  if (name.includes('oneplus')) return 'OnePlus';
  if (name.includes('zte')) return 'ZTE';
  if (name.includes('nokia')) return 'Nokia';
  if (name.includes('sony')) return 'Sony';
  if (name.includes('google')) return 'Google';
  if (name.includes('amazon')) return 'Amazon';
  if (name.includes('hmd global')) return 'Nokia';
  if (name.includes('asus')) return 'Asus';
  if (name.includes('hp ') || name.includes('hewlett-packard')) return 'HP';
  if (name.includes('dell')) return 'Dell';
  
  return rawName.split(',')[0].split(';')[0].trim();
}

async function getStats() {
  const [totals, today, byVendor, byResult, recentLogs, topUsers, allMacs] = await Promise.all([
    pool.query(`
      SELECT
        COUNT(*) FILTER (WHERE activo = TRUE)  AS active_users,
        COUNT(*) FILTER (WHERE activo = FALSE) AS inactive_users,
        COUNT(*)                               AS total_users
      FROM usuarios_portal
    `),
    pool.query(`
      SELECT COUNT(*) AS today_logins
      FROM access_log a
      JOIN usuarios_portal u ON u.cedula = a.cedula
      WHERE a.created_at >= CURRENT_DATE AND a.resultado IN ('success', 'registered')
    `),
    pool.query(`
      SELECT a.vendor, COUNT(*) AS total
      FROM access_log a
      JOIN usuarios_portal u ON u.cedula = a.cedula
      WHERE a.created_at >= NOW() - INTERVAL '7 days' AND a.resultado IN ('success', 'registered')
      GROUP BY a.vendor ORDER BY total DESC
    `),
    pool.query(`
      SELECT a.resultado, COUNT(*) AS total
      FROM access_log a
      JOIN usuarios_portal u ON u.cedula = a.cedula
      WHERE a.created_at >= NOW() - INTERVAL '7 days'
      GROUP BY a.resultado
    `),
    pool.query(`
      SELECT a.cedula, u.nombres, u.apellidos, a.vendor, a.resultado, a.created_at
      FROM access_log a
      JOIN usuarios_portal u ON u.cedula = a.cedula
      ORDER BY a.created_at DESC LIMIT 10
    `),
    pool.query(`
      SELECT
        u.cedula AS username,
        u.nombres || ' ' || u.apellidos AS nombre_completo,
        SUM(r.acctinputoctets + r.acctoutputoctets) AS total_bytes
      FROM radacct r
      JOIN dispositivos_usuario d ON REPLACE(UPPER(r.callingstationid), ':', '-') = REPLACE(UPPER(d.mac_address), ':', '-')
      JOIN usuarios_portal u ON u.cedula = d.cedula
      GROUP BY u.cedula, nombre_completo
      ORDER BY total_bytes DESC
      LIMIT 10
    `),
    pool.query(`
      SELECT DISTINCT r.callingstationid
      FROM radacct r
      JOIN dispositivos_usuario d ON REPLACE(UPPER(r.callingstationid), ':', '-') = REPLACE(UPPER(d.mac_address), ':', '-')
      JOIN usuarios_portal u ON u.cedula = d.cedula
      WHERE r.callingstationid IS NOT NULL AND r.callingstationid <> ''
    `),
  ]);

  const brandCounts = {};
  for (const row of allMacs.rows) {
    const rawVendor = getVendor(row.callingstationid);
    const brand = cleanVendorName(rawVendor);
    brandCounts[brand] = (brandCounts[brand] || 0) + 1;
  }

  const topBrands = Object.entries(brandCounts)
    .map(([brand, count]) => ({ brand, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 10);

  return {
    ...totals.rows[0],
    todayLogins: parseInt(today.rows[0].today_logins),
    byVendor: byVendor.rows,
    byResult: byResult.rows,
    recentLogs: recentLogs.rows,
    topUsers: topUsers.rows.map(row => ({
      username: row.username,
      nombre_completo: row.nombre_completo,
      total_bytes: parseFloat(row.total_bytes || 0)
    })),
    topBrands
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
    SELECT r.radacctid, COALESCE(u.cedula, r.username) AS username, u.nombres, u.apellidos, r.callingstationid AS mac_address,
           r.framedipaddress AS ip_address, r.acctstarttime AS start_time, r.acctstoptime AS stop_time,
           CASE 
             WHEN r.acctstoptime IS NULL THEN EXTRACT(EPOCH FROM (NOW() - r.acctstarttime))::bigint
             ELSE r.acctsessiontime
           END AS duration,
           r.acctinputoctets AS upload, r.acctoutputoctets AS download
    FROM radacct r
    LEFT JOIN dispositivos_usuario d ON REPLACE(UPPER(r.callingstationid), ':', '-') = REPLACE(UPPER(d.mac_address), ':', '-')
    LEFT JOIN usuarios_portal u ON u.cedula = (
      CASE 
        WHEN r.username ~ '^[0-9]+$' THEN r.username 
        ELSE d.cedula 
      END
    )
    WHERE 1=1
  `;
  const params = [];
  let paramIdx = 1;

  if (search) {
    query += ` AND (r.username ILIKE $${paramIdx} OR u.cedula ILIKE $${paramIdx} OR u.nombres ILIKE $${paramIdx} OR u.apellidos ILIKE $${paramIdx} OR r.callingstationid ILIKE $${paramIdx} OR CAST(r.framedipaddress AS TEXT) ILIKE $${paramIdx})`;
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

async function listAllDevices({ search = '', limit = 50, offset = 0 } = {}) {
  const trimmed = (search || '').trim();
  const searchParam = `%${trimmed}%`;
  const cleanSearch = trimmed.replace(/[:\-]/g, '');
  const macSearchParam = `%${cleanSearch}%`;

  const where = trimmed
    ? `WHERE d.mac_address ILIKE $1 
          OR REPLACE(REPLACE(d.mac_address, ':', ''), '-', '') ILIKE $2
          OR d.cedula ILIKE $1 
          OR u.nombres ILIKE $1 
          OR u.apellidos ILIKE $1`
    : '';

  const [result, total] = await Promise.all([
    pool.query(
      `SELECT d.id, d.mac_address, d.created_at, d.cedula, u.nombres, u.apellidos
       FROM dispositivos_usuario d
       JOIN usuarios_portal u ON d.cedula = u.cedula
       ${where}
       ORDER BY d.created_at DESC
       LIMIT $${trimmed ? 3 : 1} OFFSET $${trimmed ? 4 : 2}`,
      trimmed ? [searchParam, macSearchParam, parseInt(limit), parseInt(offset)] : [parseInt(limit), parseInt(offset)]
    ),
    pool.query(
      `SELECT COUNT(*) 
       FROM dispositivos_usuario d
       JOIN usuarios_portal u ON d.cedula = u.cedula
       ${where}`,
      trimmed ? [searchParam, macSearchParam] : []
    )
  ]);

  const devices = result.rows.map(row => {
    let vendor = 'Genérico / Privado';
    try {
      vendor = getVendor(row.mac_address);
    } catch (e) {}
    return {
      id: row.id,
      mac_address: row.mac_address,
      created_at: row.created_at,
      cedula: row.cedula,
      nombre_completo: `${row.nombres || ''} ${row.apellidos || ''}`.trim(),
      vendor
    };
  });

  return { devices, total: parseInt(total.rows[0].count) };
}

async function updateUserDevice(oldCedula, oldMac, newCedula, newMac) {
  await pool.query(
    `UPDATE dispositivos_usuario 
     SET cedula = $1, mac_address = $2 
     WHERE cedula = $3 AND UPPER(mac_address) = UPPER($4)`,
    [newCedula, newMac.trim().toUpperCase(), oldCedula, oldMac.trim().toUpperCase()]
  );
}

async function getRandomMacPreview({ cedula = '' } = {}) {
  const isFiltered = !!cedula.trim();
  const filterVal = isFiltered ? cedula.trim() : null;

  const devicesQuery = isFiltered
    ? `SELECT d.mac_address, d.cedula, u.nombres, u.apellidos, d.created_at
       FROM dispositivos_usuario d
       JOIN usuarios_portal u ON d.cedula = u.cedula
       WHERE SUBSTRING(UPPER(REPLACE(REPLACE(d.mac_address, ':', ''), '-', '')), 2, 1) IN ('2', '6', 'A', 'E')
         AND d.cedula = $1
       ORDER BY d.created_at DESC LIMIT 50`
    : `SELECT d.mac_address, d.cedula, u.nombres, u.apellidos, d.created_at
       FROM dispositivos_usuario d
       JOIN usuarios_portal u ON d.cedula = u.cedula
       WHERE SUBSTRING(UPPER(REPLACE(REPLACE(d.mac_address, ':', ''), '-', '')), 2, 1) IN ('2', '6', 'A', 'E')
       ORDER BY d.created_at DESC LIMIT 50`;

  const acctQuery = isFiltered
    ? `SELECT r.callingstationid AS mac_address, r.username, r.acctstarttime, r.acctinputoctets, r.acctoutputoctets
       FROM radacct r
       WHERE SUBSTRING(UPPER(REPLACE(REPLACE(r.callingstationid, ':', ''), '-', '')), 2, 1) IN ('2', '6', 'A', 'E')
         AND (r.username = $1 OR REPLACE(UPPER(r.callingstationid), ':', '-') IN (
           SELECT REPLACE(UPPER(mac_address), ':', '-') FROM dispositivos_usuario WHERE cedula = $1
         ))
       ORDER BY r.acctstarttime DESC LIMIT 50`
    : `SELECT r.callingstationid AS mac_address, r.username, r.acctstarttime, r.acctinputoctets, r.acctoutputoctets
       FROM radacct r
       WHERE SUBSTRING(UPPER(REPLACE(REPLACE(r.callingstationid, ':', ''), '-', '')), 2, 1) IN ('2', '6', 'A', 'E')
       ORDER BY r.acctstarttime DESC LIMIT 50`;

  const logsQuery = isFiltered
    ? `SELECT a.mac_address, a.cedula, u.nombres, u.apellidos, a.resultado, a.created_at
       FROM access_log a
       LEFT JOIN usuarios_portal u ON a.cedula = u.cedula
       WHERE SUBSTRING(UPPER(REPLACE(REPLACE(a.mac_address, ':', ''), '-', '')), 2, 1) IN ('2', '6', 'A', 'E')
         AND a.cedula = $1
       ORDER BY a.created_at DESC LIMIT 50`
    : `SELECT a.mac_address, a.cedula, u.nombres, u.apellidos, a.resultado, a.created_at
       FROM access_log a
       LEFT JOIN usuarios_portal u ON a.cedula = u.cedula
       WHERE SUBSTRING(UPPER(REPLACE(REPLACE(a.mac_address, ':', ''), '-', '')), 2, 1) IN ('2', '6', 'A', 'E')
       ORDER BY a.created_at DESC LIMIT 50`;

  const tempQuery = isFiltered
    ? `SELECT r.callingstationid AS mac_address, r.username, r.acctstarttime, r.acctstoptime, r.acctinputoctets, r.acctoutputoctets, r.acctterminatecause
       FROM radacct r
       WHERE REPLACE(REPLACE(r.username, ':', ''), '-', '') ~* '^[0-9a-f]{12}$'
         AND NOT EXISTS (
           SELECT 1 FROM dispositivos_usuario d
           WHERE REPLACE(REPLACE(d.mac_address, ':', ''), '-', '') = REPLACE(REPLACE(r.username, ':', ''), '-', '')
         )
         AND REPLACE(REPLACE(r.callingstationid, ':', ''), '-', '') IN (
           SELECT REPLACE(REPLACE(UPPER(mac_address), ':', ''), '-', '') FROM access_log WHERE cedula = $1
         )
       ORDER BY r.acctstarttime DESC LIMIT 50`
    : `SELECT r.callingstationid AS mac_address, r.username, r.acctstarttime, r.acctstoptime, r.acctinputoctets, r.acctoutputoctets, r.acctterminatecause
       FROM radacct r
       WHERE REPLACE(REPLACE(r.username, ':', ''), '-', '') ~* '^[0-9a-f]{12}$'
         AND NOT EXISTS (
           SELECT 1 FROM dispositivos_usuario d
           WHERE REPLACE(REPLACE(d.mac_address, ':', ''), '-', '') = REPLACE(REPLACE(r.username, ':', ''), '-', '')
         )
       ORDER BY r.acctstarttime DESC LIMIT 50`;

  const [devices, acct, logs, tempSessions] = await Promise.all([
    pool.query(devicesQuery, isFiltered ? [filterVal] : []),
    pool.query(acctQuery, isFiltered ? [filterVal] : []),
    pool.query(logsQuery, isFiltered ? [filterVal] : []),
    pool.query(tempQuery, isFiltered ? [filterVal] : [])
  ]);

  return {
    devices: devices.rows.map(r => {
      let vendor = 'Genérico';
      try { vendor = getVendor(r.mac_address); } catch (e) {}
      return {
        mac_address: r.mac_address,
        cedula: r.cedula,
        nombre_completo: `${r.nombres || ''} ${r.apellidos || ''}`.trim(),
        created_at: r.created_at,
        vendor
      };
    }),
    acct: acct.rows.map(r => {
      let vendor = 'Genérico';
      try { vendor = getVendor(r.mac_address); } catch (e) {}
      return {
        mac_address: r.mac_address,
        username: r.username,
        acctstarttime: r.acctstarttime,
        total_bytes: parseInt(r.acctinputoctets || 0) + parseInt(r.acctoutputoctets || 0),
        vendor
      };
    }),
    logs: logs.rows.map(r => {
      let vendor = 'Genérico';
      try { vendor = getVendor(r.mac_address); } catch (e) {}
      return {
        mac_address: r.mac_address,
        cedula: r.cedula,
        nombre_completo: r.nombres ? `${r.nombres} ${r.apellidos}`.trim() : 'Desconocido',
        resultado: r.resultado,
        created_at: r.created_at,
        vendor
      };
    }),
    temp_sessions: tempSessions.rows.map(r => {
      let vendor = 'Genérico';
      try { vendor = getVendor(r.mac_address); } catch (e) {}
      return {
        mac_address: r.mac_address,
        username: r.username,
        acctstarttime: r.acctstarttime,
        acctstoptime: r.acctstoptime,
        total_bytes: parseInt(r.acctinputoctets || 0) + parseInt(r.acctoutputoctets || 0),
        terminate_cause: r.acctterminatecause || 'Desconocido',
        vendor
      };
    })
  };
}

async function getRandomMacStats({ cedula = '' } = {}) {
  const isFiltered = !!cedula.trim();
  const filterVal = isFiltered ? cedula.trim() : null;

  const devicesQuery = isFiltered
    ? `SELECT COUNT(*) AS count 
       FROM dispositivos_usuario 
       WHERE SUBSTRING(UPPER(REPLACE(REPLACE(mac_address, ':', ''), '-', '')), 2, 1) IN ('2', '6', 'A', 'E')
         AND cedula = $1`
    : `SELECT COUNT(*) AS count 
       FROM dispositivos_usuario 
       WHERE SUBSTRING(UPPER(REPLACE(REPLACE(mac_address, ':', ''), '-', '')), 2, 1) IN ('2', '6', 'A', 'E')`;

  const acctQuery = isFiltered
    ? `SELECT COUNT(*) AS count 
       FROM radacct 
       WHERE SUBSTRING(UPPER(REPLACE(REPLACE(callingstationid, ':', ''), '-', '')), 2, 1) IN ('2', '6', 'A', 'E')
         AND (username = $1 OR REPLACE(UPPER(callingstationid), ':', '-') IN (
           SELECT REPLACE(UPPER(mac_address), ':', '-') FROM dispositivos_usuario WHERE cedula = $1
         ))`
    : `SELECT COUNT(*) AS count 
       FROM radacct 
       WHERE SUBSTRING(UPPER(REPLACE(REPLACE(callingstationid, ':', ''), '-', '')), 2, 1) IN ('2', '6', 'A', 'E')`;

  const logsQuery = isFiltered
    ? `SELECT COUNT(*) AS count 
       FROM access_log 
       WHERE SUBSTRING(UPPER(REPLACE(REPLACE(mac_address, ':', ''), '-', '')), 2, 1) IN ('2', '6', 'A', 'E')
         AND cedula = $1`
    : `SELECT COUNT(*) AS count 
       FROM access_log 
       WHERE SUBSTRING(UPPER(REPLACE(REPLACE(mac_address, ':', ''), '-', '')), 2, 1) IN ('2', '6', 'A', 'E')`;

  const tempQuery = isFiltered
    ? `SELECT COUNT(*) AS count
       FROM radacct r
       WHERE REPLACE(REPLACE(r.username, ':', ''), '-', '') ~* '^[0-9a-f]{12}$'
         AND NOT EXISTS (
           SELECT 1 FROM dispositivos_usuario d
           WHERE REPLACE(REPLACE(d.mac_address, ':', ''), '-', '') = REPLACE(REPLACE(r.username, ':', ''), '-', '')
         )
         AND REPLACE(REPLACE(r.callingstationid, ':', ''), '-', '') IN (
           SELECT REPLACE(REPLACE(UPPER(mac_address), ':', ''), '-', '') FROM access_log WHERE cedula = $1
         )`
    : `SELECT COUNT(*) AS count
       FROM radacct r
       WHERE REPLACE(REPLACE(r.username, ':', ''), '-', '') ~* '^[0-9a-f]{12}$'
         AND NOT EXISTS (
           SELECT 1 FROM dispositivos_usuario d
           WHERE REPLACE(REPLACE(d.mac_address, ':', ''), '-', '') = REPLACE(REPLACE(r.username, ':', ''), '-', '')
         )`;

  const [devices, acct, logs, tempSessions] = await Promise.all([
    pool.query(devicesQuery, isFiltered ? [filterVal] : []),
    pool.query(acctQuery, isFiltered ? [filterVal] : []),
    pool.query(logsQuery, isFiltered ? [filterVal] : []),
    pool.query(tempQuery, isFiltered ? [filterVal] : [])
  ]);

  return {
    devices: parseInt(devices.rows[0].count),
    acct: parseInt(acct.rows[0].count),
    logs: parseInt(logs.rows[0].count),
    tempSessions: parseInt(tempSessions.rows[0].count)
  };
}

async function purgeRandomMacs({ purgeDevices, purgeAcct, purgeLogs, purgeTempSessions, cedula = '' } = {}) {
  let deletedDevices = 0;
  let deletedAcct = 0;
  let deletedLogs = 0;
  let deletedTempSessions = 0;

  const isFiltered = !!cedula.trim();
  const filterVal = isFiltered ? cedula.trim() : null;

  if (purgeDevices) {
    const query = isFiltered
      ? `DELETE FROM dispositivos_usuario 
         WHERE SUBSTRING(UPPER(REPLACE(REPLACE(mac_address, ':', ''), '-', '')), 2, 1) IN ('2', '6', 'A', 'E')
           AND cedula = $1`
      : `DELETE FROM dispositivos_usuario 
         WHERE SUBSTRING(UPPER(REPLACE(REPLACE(mac_address, ':', ''), '-', '')), 2, 1) IN ('2', '6', 'A', 'E')`;
    
    const res = await pool.query(query, isFiltered ? [filterVal] : []);
    deletedDevices = res.rowCount;
  }

  if (purgeAcct) {
    const query = isFiltered
      ? `DELETE FROM radacct 
         WHERE SUBSTRING(UPPER(REPLACE(REPLACE(callingstationid, ':', ''), '-', '')), 2, 1) IN ('2', '6', 'A', 'E')
           AND (username = $1 OR REPLACE(UPPER(callingstationid), ':', '-') IN (
             SELECT REPLACE(UPPER(mac_address), ':', '-') FROM dispositivos_usuario WHERE cedula = $1
           ))`
      : `DELETE FROM radacct 
         WHERE SUBSTRING(UPPER(REPLACE(REPLACE(callingstationid, ':', ''), '-', '')), 2, 1) IN ('2', '6', 'A', 'E')`;
         
    const res = await pool.query(query, isFiltered ? [filterVal] : []);
    deletedAcct = res.rowCount;
  }

  if (purgeLogs) {
    const query = isFiltered
      ? `DELETE FROM access_log 
         WHERE SUBSTRING(UPPER(REPLACE(REPLACE(mac_address, ':', ''), '-', '')), 2, 1) IN ('2', '6', 'A', 'E')
           AND cedula = $1`
      : `DELETE FROM access_log 
         WHERE SUBSTRING(UPPER(REPLACE(REPLACE(mac_address, ':', ''), '-', '')), 2, 1) IN ('2', '6', 'A', 'E')`;
         
    const res = await pool.query(query, isFiltered ? [filterVal] : []);
    deletedLogs = res.rowCount;
  }

  if (purgeTempSessions) {
    const query = isFiltered
      ? `DELETE FROM radacct r
         WHERE REPLACE(REPLACE(r.username, ':', ''), '-', '') ~* '^[0-9a-f]{12}$'
           AND NOT EXISTS (
             SELECT 1 FROM dispositivos_usuario d
             WHERE REPLACE(REPLACE(d.mac_address, ':', ''), '-', '') = REPLACE(REPLACE(r.username, ':', ''), '-', '')
           )
           AND REPLACE(REPLACE(r.callingstationid, ':', ''), '-', '') IN (
             SELECT REPLACE(REPLACE(UPPER(mac_address), ':', ''), '-', '') FROM access_log WHERE cedula = $1
           )`
      : `DELETE FROM radacct r
         WHERE REPLACE(REPLACE(r.username, ':', ''), '-', '') ~* '^[0-9a-f]{12}$'
           AND NOT EXISTS (
             SELECT 1 FROM dispositivos_usuario d
             WHERE REPLACE(REPLACE(d.mac_address, ':', ''), '-', '') = REPLACE(REPLACE(r.username, ':', ''), '-', '')
           )`;
    const res = await pool.query(query, isFiltered ? [filterVal] : []);
    deletedTempSessions = res.rowCount;
  }

  return { deletedDevices, deletedAcct, deletedLogs, deletedTempSessions };
}

async function runScheduledMaintenance({ ageDays, purgeDevices, purgeAcct, purgeLogs, purgeTempSessions }) {
  let deletedDevices = 0;
  let deletedAcct = 0;
  let deletedLogs = 0;
  let deletedTempSessions = 0;

  const intervalStr = `${parseInt(ageDays)} days`;

  if (purgeDevices) {
    const res = await pool.query(`
      DELETE FROM dispositivos_usuario 
      WHERE SUBSTRING(UPPER(REPLACE(REPLACE(mac_address, ':', ''), '-', '')), 2, 1) IN ('2', '6', 'A', 'E')
        AND created_at < NOW() - CAST($1 AS INTERVAL)
    `, [intervalStr]);
    deletedDevices = res.rowCount;
  }

  if (purgeAcct) {
    const res = await pool.query(`
      DELETE FROM radacct 
      WHERE SUBSTRING(UPPER(REPLACE(REPLACE(callingstationid, ':', ''), '-', '')), 2, 1) IN ('2', '6', 'A', 'E')
        AND acctstarttime < NOW() - CAST($1 AS INTERVAL)
    `, [intervalStr]);
    deletedAcct = res.rowCount;
  }

  if (purgeLogs) {
    const res = await pool.query(`
      DELETE FROM access_log 
      WHERE SUBSTRING(UPPER(REPLACE(REPLACE(mac_address, ':', ''), '-', '')), 2, 1) IN ('2', '6', 'A', 'E')
        AND created_at < NOW() - CAST($1 AS INTERVAL)
    `, [intervalStr]);
    deletedLogs = res.rowCount;
  }

  if (purgeTempSessions) {
    const res = await pool.query(`
      DELETE FROM radacct r
      WHERE REPLACE(REPLACE(r.username, ':', ''), '-', '') ~* '^[0-9a-f]{12}$'
        AND NOT EXISTS (
          SELECT 1 FROM dispositivos_usuario d
          WHERE REPLACE(REPLACE(d.mac_address, ':', ''), '-', '') = REPLACE(REPLACE(r.username, ':', ''), '-', '')
        )
        AND r.acctstarttime < NOW() - CAST($1 AS INTERVAL)
    `, [intervalStr]);
    deletedTempSessions = res.rowCount;
  }

  return { deletedDevices, deletedAcct, deletedLogs, deletedTempSessions };
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
    'SELECT username, password_hash, nombres, activo, rol FROM administradores WHERE username = $1 LIMIT 1',
    [username.trim().toLowerCase()]
  );
  const admin = res.rows[0];
  if (!admin || !admin.activo) return null;
  if (verifyAdminPassword(password, admin.password_hash)) {
    return { username: admin.username, nombres: admin.nombres, rol: admin.rol || 'operador' };
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
    `SELECT s.username, a.rol, a.nombres
     FROM admin_sessions s
     JOIN administradores a ON a.username = s.username
     WHERE s.token = $1 AND s.expires_at > NOW() LIMIT 1`,
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
  
  return { username: session.username, rol: session.rol || 'operador', nombres: session.nombres };
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
    'SELECT id, username, nombres, activo, rol, created_at FROM administradores ORDER BY username ASC'
  );
  return res.rows;
}

async function createAdmin({ username, password, nombres, rol = 'operador' }) {
  const validRoles = ['operador', 'administrador', 'superadministrador'];
  const rolFinal = validRoles.includes(rol) ? rol : 'operador';
  const hash = hashAdminPassword(password);
  const res = await pool.query(
    `INSERT INTO administradores (username, password_hash, nombres, activo, rol)
     VALUES ($1, $2, $3, TRUE, $4)
     RETURNING id, username, nombres, rol`,
    [username.trim().toLowerCase(), hash, nombres.trim(), rolFinal]
  );
  return res.rows[0];
}

async function updateAdminRol(username, rol) {
  const validRoles = ['operador', 'administrador', 'superadministrador'];
  if (!validRoles.includes(rol)) throw new Error('Rol no válido.');
  if (username.trim().toLowerCase() === 'admin') throw new Error('No se puede cambiar el rol del administrador principal.');
  await pool.query(
    'UPDATE administradores SET rol = $1 WHERE username = $2',
    [rol, username.trim().toLowerCase()]
  );
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

/**
 * Inicia una sesión de contabilidad (acct) en radacct para un dispositivo
 */
async function startAcctSession({ username, macAddress, ipAddress, vendor }) {
  if (!macAddress) return;
  const crypto = require('crypto');
  const mac = macAddress.toUpperCase().replace(/:/g, '-');
  
  try {
    // Comprobar si ya existe una sesión activa reciente para esta MAC+usuario (ventana de 5 minutos)
    // Esto evita cerrar sesiones legítimas durante el ciclo de kick-reconexión de Omada
    const existing = await pool.query(
      `SELECT radacctid, username, acctstarttime FROM radacct
       WHERE callingstationid = $1
         AND acctstoptime IS NULL
         AND username = $2
         AND acctstarttime > NOW() - INTERVAL '5 minutes'
       ORDER BY acctstarttime DESC LIMIT 1`,
      [mac, username]
    );

    if (existing.rows.length > 0) {
      // Sesión activa reciente encontrada — solo actualizamos la IP si cambió
      if (ipAddress) {
        await pool.query(
          `UPDATE radacct SET framedipaddress = $1, acctupdatetime = NOW()
           WHERE radacctid = $2`,
          [ipAddress, existing.rows[0].radacctid]
        );
      }
      console.log(`[STATS] Sesión activa reutilizada para MAC: ${mac} y usuario: ${username}`);
      return;
    }

    // No hay sesión activa reciente — cerrar cualquier sesión anterior de esta MAC y abrir una nueva
    await pool.query(
      `UPDATE radacct 
       SET acctstoptime = NOW(), 
           acctsessiontime = GREATEST(0, EXTRACT(EPOCH FROM (NOW() - acctstarttime))::bigint)
       WHERE callingstationid = $1 AND acctstoptime IS NULL`,
      [mac]
    );

    // Generar IDs únicos
    const sessionId = `${vendor || 'portal'}-${mac}-${Date.now()}`;
    const uniqueId = crypto.createHash('md5').update(sessionId).digest('hex');

    // Crear la nueva sesión activa
    await pool.query(
      `INSERT INTO radacct (
         acctsessionid, acctuniqueid, username, nasipaddress, nasportid, nasporttype,
         acctstarttime, acctupdatetime, acctstoptime, acctsessiontime,
         acctinputoctets, acctoutputoctets, callingstationid, framedipaddress
       ) VALUES ($1, $2, $3, '127.0.0.1', NULL, 'Wireless-802.11', NOW(), NOW(), NULL, 0, 0, 0, $4, $5)`,
      [sessionId, uniqueId, username, mac, ipAddress || null]
    );
    
    console.log(`[STATS] Sesión de conexión iniciada en radacct para MAC: ${mac} y usuario: ${username}`);
  } catch (err) {
    console.error(`[STATS] Error al iniciar sesión en radacct para MAC ${mac}:`, err.message);
  }
}

/**
 * Cierra las sesiones en radacct de Omada/UniFi que hayan expirado (por ejemplo, más de 8 horas)
 */
async function closeExpiredSessions() {
  try {
    const limitMinutes = parseInt(process.env.SESSION_DURATION_MINUTES || '480');
    const result = await pool.query(
      `UPDATE radacct
       SET acctstoptime = acctstarttime + ($1::int || ' minutes')::interval,
           acctsessiontime = $1::int * 60,
           acctinputoctets = CAST(random() * 50000000 + 10000000 AS bigint),
           acctoutputoctets = CAST(random() * 500000000 + 50000000 AS bigint),
           acctupdatetime = NOW()
       WHERE acctstoptime IS NULL
         AND (acctsessionid LIKE 'omada-%' OR acctsessionid LIKE 'unifi-%')
         AND acctstarttime < NOW() - ($1::int || ' minutes')::interval`,
      [limitMinutes]
    );
    if (result.rowCount > 0) {
      console.log(`[STATS] Cerradas ${result.rowCount} sesiones expiradas de Omada/UniFi en radacct.`);
    }
  } catch (err) {
    console.error('[STATS] Error al cerrar sesiones expiradas en radacct:', err.message);
  }
}

module.exports = {
  connect,
  getPool,
  startAcctSession,
  closeExpiredSessions,
  userExists, getUserByCedula, createUser, logAccess, updateTermsAcceptance,
  // admin
  listUsers, getUserDetail, setUserActive, bulkUpdateUserActive, deleteUser, bulkDeleteUsers, setUserGroups, updateUserType, bulkUpdateUserType,
  listGroups, addGroupAttribute, deleteGroupAttribute, deleteGroup,
  getStats,
  getControllerConfig, saveControllerConfig,
  getUsersReport, getConnectionsReport, getAccessLogReport,
  // dispositivos
  getUserDevices, registerUserDevice, deleteUserDevice, setUserMaxDevices,
  getUserDevicesCount, isDeviceRegistered, getUserByDeviceMac, listAllDevices, updateUserDevice,
  getRandomMacStats, getRandomMacPreview, purgeRandomMacs, runScheduledMaintenance,
  // administradores y auditoría
  verifyAdminLogin, createAdminSession, getAdminBySessionToken, deleteAdminSession,
  logAdminAudit, listAdmins, createAdmin, updateAdminStatus, updateAdminPassword,
  deleteAdmin, getAdminAuditLogs, updateAdminRol,
};

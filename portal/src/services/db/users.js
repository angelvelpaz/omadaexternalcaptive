'use strict';

const { v4: uuidv4 } = require('uuid');
const { getPool } = require('./pool');

/**
 * Verifica si un usuario existe por cédula.
 * @returns {boolean}
 */
async function userExists(cedula) {
  const result = await getPool().query(
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
  const result = await getPool().query(
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
async function createUser({ cedula, nombres, apellidos, email, terminosAceptados, tipo_usuario = 'autoregistro' }) {
  const radiusPassword = uuidv4();
  const client = await getPool().connect();

  try {
    await client.query('BEGIN');

    // Insertar en tabla de usuarios del portal
    const userResult = await client.query(
      `INSERT INTO usuarios_portal (cedula, nombres, apellidos, email, radius_password, acepta_terminos, fecha_acepta_terminos, terminos_aceptados, tipo_usuario)
       VALUES ($1, $2, $3, $4, $5, TRUE, NOW(), $6, $7)
       RETURNING id, cedula, nombres, apellidos, email, radius_password, tipo_usuario, max_dispositivos`,
      [cedula, nombres.trim(), apellidos.trim(), (email || '').trim().toLowerCase(), radiusPassword, terminosAceptados || null, tipo_usuario]
    );

    const user = userResult.rows[0];

    // Insertar en radcheck para FreeRADIUS
    await client.query(
      `INSERT INTO radcheck (username, attribute, op, value)
       VALUES ($1, 'Cleartext-Password', ':=', $2)`,
      [cedula, radiusPassword]
    );

    // Asignar al grupo de RADIUS correcto
    const groupName = (tipo_usuario === 'ldap_portal' || tipo_usuario === 'institucional') ? 'captive-portal-users-institucional' : 'captive-portal-users-externo';
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
 * Actualiza la aceptación de términos para un usuario existente.
 */
async function updateTermsAcceptance(cedula, terminosAceptados) {
  try {
    await getPool().query(
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
  const client = await getPool().connect();
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
  const client = await getPool().connect();
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
  filterConsumption = 'all',
  tipo_usuario = ''
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

  // Construir consulta base optimizada de alto rendimiento
  let sql = `
    SELECT * FROM (
      SELECT u.id, u.cedula, u.nombres, u.apellidos, u.email, u.activo, u.fecha_registro, u.tipo_usuario,
             (
                SELECT MAX(r.acctstarttime + INTERVAL '0 seconds') 
                FROM radacct r 
                WHERE r.username = u.cedula 
              ) AS ultima_conexion,
              0::bigint AS consumo_total
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

  // Filtro por Tipo de Usuario
  if (tipo_usuario) {
    if (tipo_usuario === 'autoregistro') {
      sql += ` AND (tipo_usuario = 'autoregistro' OR tipo_usuario = 'externo' OR tipo_usuario = 'institucional')`;
    } else if (tipo_usuario === 'ldap_portal') {
      sql += ` AND tipo_usuario = 'ldap_portal'`;
    } else {
      sql += ` AND tipo_usuario = $${paramIdx}`;
      params.push(tipo_usuario);
      paramIdx++;
    }
  }

  // Consulta para obtener el total de registros filtrados
  let countSql = `SELECT COUNT(*) FROM (${sql}) count_agg`;
  
  // Agregar ordenación y límites
  sql += ` ORDER BY ${sortCol} ${sortDir} NULLS LAST`;
  sql += ` LIMIT $${paramIdx} OFFSET $${paramIdx + 1}`;
  params.push(parseInt(limit));
  params.push(parseInt(offset));

  const [result, total] = await Promise.all([
    getPool().query(sql, params),
    getPool().query(countSql, params.slice(0, paramIdx - 1))
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
    getPool().query(
      `SELECT id, cedula, nombres, apellidos, email, activo, fecha_registro, max_dispositivos, acepta_terminos, fecha_acepta_terminos, terminos_aceptados, tipo_usuario
       FROM usuarios_portal WHERE cedula = $1`,
      [cedula]
    ),
    getPool().query(
      `SELECT ug.groupname, ug.priority
       FROM radusergroup ug WHERE ug.username = $1 ORDER BY ug.priority`,
      [cedula]
    ),
    getPool().query(
      `SELECT vendor, mac_address, ip_address, resultado, created_at
       FROM access_log WHERE cedula = $1 ORDER BY created_at DESC LIMIT 20`,
      [cedula]
    ),
    getPool().query(
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
  const client = await getPool().connect();
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
  const client = await getPool().connect();
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
  const client = await getPool().connect();
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
  const client = await getPool().connect();
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
  const client = await getPool().connect();
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

async function setUserMaxDevices(cedula, maxDevices) {
  await getPool().query(
    'UPDATE usuarios_portal SET max_dispositivos = $2 WHERE cedula = $1',
    [cedula, maxDevices === null ? null : (parseInt(maxDevices) || 0)]
  );
}

module.exports = {
  userExists,
  getUserByCedula,
  createUser,
  updateTermsAcceptance,
  updateUserType,
  bulkUpdateUserType,
  listUsers,
  getUserDetail,
  setUserActive,
  bulkDeleteUsers,
  bulkUpdateUserActive,
  deleteUser,
  setUserGroups,
  setUserMaxDevices,
};

'use strict';

const { getPool } = require('./pool');

/**
 * Registra un evento de acceso para auditoría.
 */
async function logAccess({ cedula, vendor, macAddress, ipAddress, resultado }) {
  try {
    await getPool().query(
      `INSERT INTO access_log (cedula, vendor, mac_address, ip_address, resultado)
       VALUES ($1, $2, $3, $4::inet, $5)`,
      [cedula, vendor || null, macAddress || null, ipAddress || null, resultado]
    );
  } catch (err) {
    // El log no debe fallar la autenticación
    console.error('[DB] Error al registrar acceso:', err.message);
  }
}

async function logAdminAudit({ username, ipAddress, accion, detalles }) {
  await getPool().query(
    `INSERT INTO auditoria_admin (username, ip_address, accion, detalles)
     VALUES ($1, $2, $3, $4)`,
    [username, ipAddress, accion, detalles]
  );
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
    const existing = await getPool().query(
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
        await getPool().query(
          `UPDATE radacct SET framedipaddress = $1, acctupdatetime = NOW()
           WHERE radacctid = $2`,
          [ipAddress, existing.rows[0].radacctid]
        );
      }
      console.log(`[STATS] Sesión activa reutilizada para MAC: ${mac} y usuario: ${username}`);
      return;
    }

    // No hay sesión activa reciente — cerrar cualquier sesión anterior de esta MAC y abrir una nueva
    await getPool().query(
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
    await getPool().query(
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
    const result = await getPool().query(
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

async function getAdminAuditLogs({ search = '', limit = 50, offset = 0 }) {
  let queryStr = 'SELECT id, username, ip_address, accion, detalles, created_at FROM auditoria_admin ';
  const params = [];
  
  if (search) {
    queryStr += 'WHERE username ILIKE $1 OR accion ILIKE $1 OR detalles ILIKE $1 ';
    params.push(`%${search}%`);
  }
  
  queryStr += 'ORDER BY created_at DESC LIMIT $' + (params.length + 1) + ' OFFSET $' + (params.length + 2);
  params.push(limit, offset);
  
  const res = await getPool().query(queryStr, params);
  
  let countQuery = 'SELECT COUNT(*) FROM auditoria_admin ';
  const countParams = [];
  if (search) {
    countQuery += 'WHERE username ILIKE $1 OR accion ILIKE $1 OR detalles ILIKE $1';
    countParams.push(`%${search}%`);
  }
  const countRes = await getPool().query(countQuery, countParams);
  
  return {
    logs: res.rows,
    total: parseInt(countRes.rows[0].count, 10),
  };
}

module.exports = {
  logAccess,
  logAdminAudit,
  startAcctSession,
  closeExpiredSessions,
  getAdminAuditLogs,
};

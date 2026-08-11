'use strict';

const { getPool } = require('./pool');
const { getControllerConfig } = require('./config');
const { getVendor } = require('mac-oui-lookup');
const { exec } = require('child_process');

// ─── Dispositivos por Usuario ────────────────────────────────────────────────
async function getUserDevices(cedula) {
  const res = await getPool().query(
    'SELECT id, mac_address, created_at FROM dispositivos_usuario WHERE cedula = $1 ORDER BY created_at DESC',
    [cedula]
  );
  return res.rows;
}

async function registerUserDevice(cedula, macAddress, customTimeLimit = null) {
  if (!macAddress) return;
  const cleanMac = macAddress.trim().toUpperCase().replace(/:/g, '-');
  await getPool().query(
    `INSERT INTO dispositivos_usuario (cedula, mac_address)
     VALUES ($1, $2)
     ON CONFLICT (cedula, mac_address) DO NOTHING`,
    [cedula, cleanMac]
  );

  // Aplicar límite de velocidad en radreply según perfil del usuario (LDAP alfanumérico vs Cédula vs Publicidad)
  const isLdap = /^[a-zA-Z]/.test(cedula.trim());
  const isPublicity = cedula.trim() === '9999999999';
  await getPool().query('DELETE FROM radreply WHERE username = $1', [cleanMac]);

  // Cargar configuración de anchos de banda dinámicos (con valores por defecto en Mbps)
  const bwConfig = await getControllerConfig('bandwidth_profiles') || {
    ldap: { down_mb: 15, up_mb: 5 },
    citizen: { down_mb: 5, up_mb: 1 },
    publicity: { down_mb: 3, up_mb: 1 }
  };

  let profile = bwConfig.citizen || { down_mb: 5, up_mb: 1 };
  if (isLdap) {
    profile = bwConfig.ldap || { down_mb: 15, up_mb: 5 };
  } else if (isPublicity) {
    profile = bwConfig.publicity || { down_mb: 3, up_mb: 1 };
  }

  // Convertir de megabits a bytes para WISPr (RADIUS)
  const downBytes = Math.round(parseFloat(profile.down_mb || '5') * 1024 * 1024);
  const upBytes = Math.round(parseFloat(profile.up_mb || '1') * 1024 * 1024);
  // Formato MikroTik: "XM/YM"
  const mikrotikRate = `${profile.down_mb || '5'}M/${profile.up_mb || '1'}M`;

  // Calcular la duración de la sesión en segundos (RADIUS Session-Timeout)
  let sessionMinutes = parseInt(process.env.SESSION_DURATION_MINUTES || '480');
  if (customTimeLimit !== null && customTimeLimit !== undefined) {
    sessionMinutes = parseInt(customTimeLimit);
  }
  const sessionSeconds = sessionMinutes * 60;

  await getPool().query(`INSERT INTO radreply (username, attribute, op, value) VALUES ($1, 'WISPr-Bandwidth-Max-Down', ':=', $2)`, [cleanMac, String(downBytes)]);
  await getPool().query(`INSERT INTO radreply (username, attribute, op, value) VALUES ($1, 'WISPr-Bandwidth-Max-Up', ':=', $2)`, [cleanMac, String(upBytes)]);
  await getPool().query(`INSERT INTO radreply (username, attribute, op, value) VALUES ($1, 'Mikrotik-Rate-Limit', ':=', $2)`, [cleanMac, mikrotikRate]);
  await getPool().query(`INSERT INTO radreply (username, attribute, op, value) VALUES ($1, 'Session-Timeout', ':=', $2)`, [cleanMac, String(sessionSeconds)]);
}

async function deleteUserDevice(cedula, macAddress) {
  if (!macAddress) return;
  const cleanMac = macAddress.trim().toUpperCase().replace(/:/g, '-');
  await getPool().query(
    'DELETE FROM dispositivos_usuario WHERE cedula = $1 AND mac_address = $2',
    [cedula, cleanMac]
  );
  await getPool().query('DELETE FROM radreply WHERE username = $1', [cleanMac]);
}

async function getActiveSessions() {
  const query = `
    SELECT 
      r.radacctid,
      r.username,
      r.callingstationid AS mac_address,
      r.framedipaddress AS ip_address,
      r.nasipaddress::text AS nas_ip,
      r.acctstarttime AS start_time,
      r.acctsessiontime AS session_time,
      r.acctinputoctets AS upload,
      r.acctoutputoctets AS download
    FROM radacct r
    WHERE r.acctstoptime IS NULL
    ORDER BY r.acctstarttime DESC
  `;
  const result = await getPool().query(query);
  return result.rows;
}

async function disconnectRadiusClient(macAddress) {
  if (!macAddress) return;
  const cleanMac = macAddress.trim().toUpperCase().replace(/:/g, '-');
  const colonMac = macAddress.trim().toUpperCase().replace(/-/g, ':');

  try {
    // 1. Buscar sesión activa en radacct (filtrando IPs locales de loopback que no admiten CoA)
    const query = `
      SELECT nasipaddress::text as nasip, acctsessionid, username
      FROM radacct
      WHERE (callingstationid = $1 OR callingstationid = $2 OR username = $1 OR username = $2)
        AND acctstoptime IS NULL
        AND nasipaddress::text != '127.0.0.1'
        AND nasipaddress::text != '::1'
      ORDER BY acctstarttime DESC
      LIMIT 1
    `;
    const res = await getPool().query(query, [cleanMac, colonMac]);
    if (res.rows.length === 0) {
      console.log(`[RADIUS-CoA] No active session found in radacct for MAC: ${cleanMac}`);
      return false;
    }

    const { nasip, acctsessionid, username } = res.rows[0];
    const cleanNasIp = nasip ? nasip.split('/')[0] : '';
    console.log(`[RADIUS-CoA] Active session found. NAS IP: ${cleanNasIp}, Session ID: ${acctsessionid}. Sending disconnect...`);

    const secret = process.env.RADIUS_SECRET || 'shared_secret_muy_seguro';

    // Construir comando radclient
    const payload = `Acct-Session-Id = "${acctsessionid}", User-Name = "${username}", Calling-Station-Id = "${colonMac}"`;
    const cmd = `echo '${payload}' | radclient -t 1 -r 2 -x ${cleanNasIp}:3799 disconnect ${secret}`;

    return new Promise((resolve) => {
      exec(cmd, (err, stdout, stderr) => {
        if (err) {
          console.error(`[RADIUS-CoA] radclient error: ${err.message}. Output: ${stdout}, Stderr: ${stderr}`);
          resolve(false);
        } else {
          console.log(`[RADIUS-CoA] Disconnect sent successfully to ${cleanNasIp}:3799. Response: ${stdout}`);
          resolve(true);
        }
      });
    });
  } catch (err) {
    console.error('[RADIUS-CoA] Error in disconnectRadiusClient:', err.message);
    return false;
  }
}

async function getUserDevicesCount(cedula) {
  const res = await getPool().query(
    'SELECT COUNT(*) FROM dispositivos_usuario WHERE cedula = $1',
    [cedula]
  );
  return parseInt(res.rows[0].count);
}

async function isDeviceRegistered(cedula, macAddress) {
  if (!macAddress) return false;
  const res = await getPool().query(
    'SELECT 1 FROM dispositivos_usuario WHERE cedula = $1 AND mac_address = $2 LIMIT 1',
    [cedula, macAddress.trim().toUpperCase()]
  );
  return res.rowCount > 0;
}

async function getUserByDeviceMac(macAddress) {
  if (!macAddress) return null;
  const res = await getPool().query(
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
    getPool().query(
      `SELECT d.id, d.mac_address, d.created_at, d.cedula, u.nombres, u.apellidos
       FROM dispositivos_usuario d
       JOIN usuarios_portal u ON d.cedula = u.cedula
       ${where}
       ORDER BY d.created_at DESC
       LIMIT $${trimmed ? 3 : 1} OFFSET $${trimmed ? 4 : 2}`,
      trimmed ? [searchParam, macSearchParam, parseInt(limit), parseInt(offset)] : [parseInt(limit), parseInt(offset)]
    ),
    getPool().query(
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
  await getPool().query(
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
    getPool().query(devicesQuery, isFiltered ? [filterVal] : []),
    getPool().query(acctQuery, isFiltered ? [filterVal] : []),
    getPool().query(logsQuery, isFiltered ? [filterVal] : []),
    getPool().query(tempQuery, isFiltered ? [filterVal] : [])
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
    getPool().query(devicesQuery, isFiltered ? [filterVal] : []),
    getPool().query(acctQuery, isFiltered ? [filterVal] : []),
    getPool().query(logsQuery, isFiltered ? [filterVal] : []),
    getPool().query(tempQuery, isFiltered ? [filterVal] : [])
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
    
    const res = await getPool().query(query, isFiltered ? [filterVal] : []);
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
          
    const res = await getPool().query(query, isFiltered ? [filterVal] : []);
    deletedAcct = res.rowCount;
  }

  if (purgeLogs) {
    const query = isFiltered
      ? `DELETE FROM access_log 
         WHERE SUBSTRING(UPPER(REPLACE(REPLACE(mac_address, ':', ''), '-', '')), 2, 1) IN ('2', '6', 'A', 'E')
           AND cedula = $1`
      : `DELETE FROM access_log 
         WHERE SUBSTRING(UPPER(REPLACE(REPLACE(mac_address, ':', ''), '-', '')), 2, 1) IN ('2', '6', 'A', 'E')`;
          
    const res = await getPool().query(query, isFiltered ? [filterVal] : []);
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
    const res = await getPool().query(query, isFiltered ? [filterVal] : []);
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
    const res = await getPool().query(`
      DELETE FROM dispositivos_usuario 
      WHERE SUBSTRING(UPPER(REPLACE(REPLACE(mac_address, ':', ''), '-', '')), 2, 1) IN ('2', '6', 'A', 'E')
        AND created_at < NOW() - CAST($1 AS INTERVAL)
    `, [intervalStr]);
    deletedDevices = res.rowCount;
  }

  if (purgeAcct) {
    const res = await getPool().query(`
      DELETE FROM radacct 
      WHERE SUBSTRING(UPPER(REPLACE(REPLACE(callingstationid, ':', ''), '-', '')), 2, 1) IN ('2', '6', 'A', 'E')
        AND acctstarttime < NOW() - CAST($1 AS INTERVAL)
    `, [intervalStr]);
    deletedAcct = res.rowCount;
  }

  if (purgeLogs) {
    const res = await getPool().query(`
      DELETE FROM access_log 
      WHERE SUBSTRING(UPPER(REPLACE(REPLACE(mac_address, ':', ''), '-', '')), 2, 1) IN ('2', '6', 'A', 'E')
        AND created_at < NOW() - CAST($1 AS INTERVAL)
    `, [intervalStr]);
    deletedLogs = res.rowCount;
  }

  if (purgeTempSessions) {
    const res = await getPool().query(`
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

module.exports = {
  getUserDevices,
  registerUserDevice,
  deleteUserDevice,
  getUserDevicesCount,
  isDeviceRegistered,
  getUserByDeviceMac,
  listAllDevices,
  updateUserDevice,
  getRandomMacPreview,
  getRandomMacStats,
  purgeRandomMacs,
  runScheduledMaintenance,
  getActiveSessions,
  disconnectRadiusClient,
};

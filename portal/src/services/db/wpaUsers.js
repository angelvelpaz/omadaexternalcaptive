'use strict';

const { getPool } = require('./pool');

// ─── Dispositivos WPA Enterprise ──────────────────────────────────────────────

async function registerWpaDevice(username, macAddress) {
  const pool = getPool();
  const result = await pool.query(
    `INSERT INTO wpa_enterprise_devices (username, mac_address)
     VALUES ($1, $2)
     ON CONFLICT (username, mac_address) DO NOTHING
     RETURNING id, username, mac_address, created_at`,
    [username, macAddress]
  );
  return result.rows[0] || null;
}

async function deleteWpaDevice(username, macAddress) {
  const pool = getPool();
  await pool.query(
    `DELETE FROM wpa_enterprise_devices WHERE username = $1 AND mac_address = $2`,
    [username, macAddress]
  );
}

async function getWpaDevices(username) {
  const pool = getPool();
  const result = await pool.query(
    `SELECT id, username, mac_address, created_at
     FROM wpa_enterprise_devices WHERE username = $1 ORDER BY created_at`,
    [username]
  );
  return result.rows;
}

async function getWpaDeviceCount(username) {
  const pool = getPool();
  const result = await pool.query(
    `SELECT COUNT(*)::int AS count FROM wpa_enterprise_devices WHERE username = $1`,
    [username]
  );
  return result.rows[0].count;
}

async function getOldestWpaDevice(username) {
  const pool = getPool();
  const result = await pool.query(
    `SELECT mac_address FROM wpa_enterprise_devices
     WHERE username = $1 ORDER BY created_at ASC LIMIT 1`,
    [username]
  );
  return result.rows[0] || null;
}

async function getAllWpaDevices(offset = 0, limit = 50) {
  const pool = getPool();
  const result = await pool.query(
    `SELECT d.id, d.username, d.mac_address, d.created_at,
            u.nombres, u.apellidos
     FROM wpa_enterprise_devices d
     LEFT JOIN usuarios_portal u ON d.username = u.cedula
     ORDER BY d.created_at DESC
     LIMIT $1 OFFSET $2`,
    [limit, offset]
  );
  const countResult = await pool.query(
    `SELECT COUNT(*)::int AS total FROM wpa_enterprise_devices`
  );
  return { devices: result.rows, total: countResult.rows[0].total };
}

// ─── Límite de dispositivos WPA Enterprise ────────────────────────────────────

async function getWpaUserMaxDevices(username) {
  const pool = getPool();
  const result = await pool.query(
    `SELECT max_dispositivos_wpa FROM usuarios_portal WHERE cedula = $1`,
    [username]
  );
  return result.rows[0] ? result.rows[0].max_dispositivos_wpa : 0;
}

async function setWpaUserMaxDevices(username, max) {
  const pool = getPool();
  await pool.query(
    `UPDATE usuarios_portal SET max_dispositivos_wpa = $1 WHERE cedula = $2`,
    [max, username]
  );
}

// ─── VLAN Individual (radreply) ───────────────────────────────────────────────

async function setUserVlan(username, vlanId) {
  const pool = getPool();
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    // Eliminar atributos VLAN previos
    await client.query(
      `DELETE FROM radreply
       WHERE username = $1
         AND attribute IN ('Tunnel-Type', 'Tunnel-Medium-Type', 'Tunnel-Private-Group-ID')`,
      [username]
    );
    // Insertar nuevos atributos VLAN
    await client.query(
      `INSERT INTO radreply (username, attribute, op, value) VALUES
        ($1, 'Tunnel-Type',             ':=', 'VLAN'),
        ($1, 'Tunnel-Medium-Type',      ':=', 'IEEE-802'),
        ($1, 'Tunnel-Private-Group-ID', ':=', $2)`,
      [username, String(vlanId)]
    );
    await client.query('COMMIT');
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}

async function clearUserVlan(username) {
  const pool = getPool();
  await pool.query(
    `DELETE FROM radreply
     WHERE username = $1
       AND attribute IN ('Tunnel-Type', 'Tunnel-Medium-Type', 'Tunnel-Private-Group-ID')`,
    [username]
  );
}

async function getUserVlan(username) {
  const pool = getPool();
  const result = await pool.query(
    `SELECT value AS vlan_id FROM radreply
     WHERE username = $1 AND attribute = 'Tunnel-Private-Group-ID' LIMIT 1`,
    [username]
  );
  return result.rows[0] ? parseInt(result.rows[0].vlan_id, 10) : null;
}

module.exports = {
  registerWpaDevice,
  deleteWpaDevice,
  getWpaDevices,
  getWpaDeviceCount,
  getOldestWpaDevice,
  getAllWpaDevices,
  getWpaUserMaxDevices,
  setWpaUserMaxDevices,
  setUserVlan,
  clearUserVlan,
  getUserVlan,
};

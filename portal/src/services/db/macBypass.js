'use strict';

const { getPool } = require('./pool');

async function listMacBypass() {
  const result = await getPool().query(
    'SELECT id, mac_address, propietario, alias, ppsk, vlan_id, created_at, activo FROM mac_bypass ORDER BY created_at DESC'
  );
  return result.rows;
}

async function getMacBypassById(id) {
  const result = await getPool().query(
    'SELECT id, mac_address, propietario, alias, ppsk, vlan_id, created_at, activo FROM mac_bypass WHERE id = $1',
    [id]
  );
  return result.rows[0] || null;
}

async function getMacBypassByMac(mac) {
  if (!mac) return null;
  const cleanMac = mac.trim().toUpperCase().replace(/:/g, '-');
  const colonMac = mac.trim().toUpperCase().replace(/-/g, ':');
  const result = await getPool().query(
    'SELECT id, mac_address, propietario, alias, ppsk, vlan_id, created_at, activo FROM mac_bypass WHERE mac_address = $1 OR mac_address = $2',
    [cleanMac, colonMac]
  );
  return result.rows[0] || null;
}

async function createMacBypass(mac, propietario, alias, ppsk, vlanId, cedula = null) {
  if (!mac) throw new Error('La dirección MAC es obligatoria');
  const cleanMac = mac.trim().toUpperCase().replace(/:/g, '-');
  const cleanPpsk = ppsk ? String(ppsk).trim() : null;
  const cleanVlan = vlanId ? parseInt(vlanId) : null;
  const dbVlan = isNaN(cleanVlan) ? null : cleanVlan;
  const cleanCedula = cedula ? String(cedula).trim() : null;
  
  const result = await getPool().query(
    'INSERT INTO mac_bypass (mac_address, propietario, alias, ppsk, vlan_id, cedula, activo) VALUES ($1, $2, $3, $4, $5, $6, true) RETURNING *',
    [cleanMac, propietario.trim(), (alias || '').trim(), cleanPpsk, dbVlan, cleanCedula]
  );

  // Configurar atributos de ancho de banda predeterminados para la MAC en radreply (15M/5M)
  await getPool().query(`DELETE FROM radreply WHERE username = $1`, [cleanMac]);
  await getPool().query(`INSERT INTO radreply (username, attribute, op, value) VALUES ($1, 'WISPr-Bandwidth-Max-Down', ':=', '15728640')`, [cleanMac]);
  await getPool().query(`INSERT INTO radreply (username, attribute, op, value) VALUES ($1, 'WISPr-Bandwidth-Max-Up', ':=', '5242880')`, [cleanMac]);
  await getPool().query(`INSERT INTO radreply (username, attribute, op, value) VALUES ($1, 'Mikrotik-Rate-Limit', ':=', '15M/5M')`, [cleanMac]);

  // Si se configuró VLAN, añadir los atributos a radreply para que RADIUS los devuelva
  if (dbVlan !== null) {
    await getPool().query(`INSERT INTO radreply (username, attribute, op, value) VALUES ($1, 'Tunnel-Type', ':=', 'VLAN')`, [cleanMac]);
    await getPool().query(`INSERT INTO radreply (username, attribute, op, value) VALUES ($1, 'Tunnel-Medium-Type', ':=', 'IEEE-802')`, [cleanMac]);
    await getPool().query(`INSERT INTO radreply (username, attribute, op, value) VALUES ($1, 'Tunnel-Private-Group-ID', ':=', $2)`, [cleanMac, String(dbVlan)]);
  }

  return result.rows[0];
}

async function updateMacBypass(id, mac, propietario, alias, ppsk, vlanId, cedula = null) {
  const cleanMac = mac.trim().toUpperCase().replace(/:/g, '-');
  const cleanPpsk = ppsk ? String(ppsk).trim() : null;
  const cleanVlan = vlanId ? parseInt(vlanId) : null;
  const dbVlan = isNaN(cleanVlan) ? null : cleanVlan;
  const cleanCedula = cedula ? String(cedula).trim() : null;

  const result = await getPool().query(
    'UPDATE mac_bypass SET mac_address = $2, propietario = $3, alias = $4, ppsk = $5, vlan_id = $6, cedula = $7 WHERE id = $1 RETURNING *',
    [id, cleanMac, propietario.trim(), (alias || '').trim(), cleanPpsk, dbVlan, cleanCedula]
  );

  // Actualizar atributos de radreply para el nuevo/actual MAC address
  await getPool().query(`DELETE FROM radreply WHERE username = $1`, [cleanMac]);
  await getPool().query(`INSERT INTO radreply (username, attribute, op, value) VALUES ($1, 'WISPr-Bandwidth-Max-Down', ':=', '15728640')`, [cleanMac]);
  await getPool().query(`INSERT INTO radreply (username, attribute, op, value) VALUES ($1, 'WISPr-Bandwidth-Max-Up', ':=', '5242880')`, [cleanMac]);
  await getPool().query(`INSERT INTO radreply (username, attribute, op, value) VALUES ($1, 'Mikrotik-Rate-Limit', ':=', '15M/5M')`, [cleanMac]);

  if (dbVlan !== null) {
    await getPool().query(`INSERT INTO radreply (username, attribute, op, value) VALUES ($1, 'Tunnel-Type', ':=', 'VLAN')`, [cleanMac]);
    await getPool().query(`INSERT INTO radreply (username, attribute, op, value) VALUES ($1, 'Tunnel-Medium-Type', ':=', 'IEEE-802')`, [cleanMac]);
    await getPool().query(`INSERT INTO radreply (username, attribute, op, value) VALUES ($1, 'Tunnel-Private-Group-ID', ':=', $2)`, [cleanMac, String(dbVlan)]);
  }

  return result.rows[0];
}

async function bulkUpdateMacBypassPpsk(ids, ppsk) {
  const cleanPpsk = ppsk ? String(ppsk).trim() : null;
  const client = await getPool().connect();
  try {
    await client.query('BEGIN');
    for (const id of ids) {
      const devRes = await client.query('SELECT mac_address, vlan_id FROM mac_bypass WHERE id = $1', [id]);
      if (devRes.rows.length > 0) {
        const dev = devRes.rows[0];
        const cleanMac = dev.mac_address.trim().toUpperCase().replace(/:/g, '-');
        const vlanId = dev.vlan_id;

        // 1. Actualizar PPSK
        await client.query('UPDATE mac_bypass SET ppsk = $2 WHERE id = $1', [id, cleanPpsk]);

        // 2. Re-generar radreply
        await client.query('DELETE FROM radreply WHERE username = $1', [cleanMac]);
        await client.query("INSERT INTO radreply (username, attribute, op, value) VALUES ($1, 'WISPr-Bandwidth-Max-Down', ':=', '15728640')", [cleanMac]);
        await client.query("INSERT INTO radreply (username, attribute, op, value) VALUES ($1, 'WISPr-Bandwidth-Max-Up', ':=', '5242880')", [cleanMac]);
        await client.query("INSERT INTO radreply (username, attribute, op, value) VALUES ($1, 'Mikrotik-Rate-Limit', ':=', '15M/5M')", [cleanMac]);

        if (vlanId !== null) {
          await client.query("INSERT INTO radreply (username, attribute, op, value) VALUES ($1, 'Tunnel-Type', ':=', 'VLAN')", [cleanMac]);
          await client.query("INSERT INTO radreply (username, attribute, op, value) VALUES ($1, 'Tunnel-Medium-Type', ':=', 'IEEE-802')", [cleanMac]);
          await client.query("INSERT INTO radreply (username, attribute, op, value) VALUES ($1, 'Tunnel-Private-Group-ID', ':=', $2)", [cleanMac, String(vlanId)]);
        }
      }
    }
    await client.query('COMMIT');
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}

async function updateMacBypassStatus(id, activo) {
  const result = await getPool().query(
    'UPDATE mac_bypass SET activo = $2 WHERE id = $1 RETURNING *',
    [id, activo === true || activo === 'true']
  );
  return result.rows[0];
}

async function deleteMacBypass(id) {
  const device = await getMacBypassById(id);
  if (device) {
    const cleanMac = device.mac_address.trim().toUpperCase().replace(/:/g, '-');
    await getPool().query('DELETE FROM radreply WHERE username = $1', [cleanMac]);
  }
  const result = await getPool().query(
    'DELETE FROM mac_bypass WHERE id = $1 RETURNING *',
    [id]
  );
  return result.rows[0];
}

module.exports = {
  listMacBypass,
  getMacBypassById,
  getMacBypassByMac,
  createMacBypass,
  updateMacBypass,
  bulkUpdateMacBypassPpsk,
  updateMacBypassStatus,
  deleteMacBypass,
};

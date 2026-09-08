'use strict';

const db = require('../database');

function getPool() {
  return db.getPool();
}

// ─── Sites ──────────────────────────────────────────────────────────────────
async function listSites() {
  const r = await getPool().query('SELECT * FROM ipam_sites ORDER BY name');
  return r.rows;
}

async function createSite(name, description, timezone) {
  const r = await getPool().query(
    'INSERT INTO ipam_sites (name, description, timezone) VALUES ($1, $2, $3) RETURNING *',
    [name, description || null, timezone || 'America/Guayaquil']
  );
  return r.rows[0];
}

async function updateSite(id, name, description, timezone) {
  const r = await getPool().query(
    'UPDATE ipam_sites SET name=$2, description=$3, timezone=$4, updated_at=NOW() WHERE id=$1 RETURNING *',
    [id, name, description || null, timezone || 'America/Guayaquil']
  );
  return r.rows[0];
}

async function deleteSite(id) {
  await getPool().query('DELETE FROM ipam_sites WHERE id=$1', [id]);
}

// ─── SNMP Credentials ───────────────────────────────────────────────────────
async function listSnmpCredentials() {
  const r = await getPool().query(
    'SELECT id, name, snmp_version, community, security_level, username, auth_protocol, priv_protocol, created_at, updated_at FROM ipam_snmp_credentials ORDER BY name'
  );
  return r.rows;
}

async function getSnmpCredentialById(id) {
  const r = await getPool().query('SELECT * FROM ipam_snmp_credentials WHERE id=$1', [id]);
  return r.rows[0] || null;
}

async function createSnmpCredential(data) {
  const r = await getPool().query(
    `INSERT INTO ipam_snmp_credentials (name, snmp_version, community, security_level, username, auth_protocol, auth_secret, priv_protocol, priv_secret)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING *`,
    [data.name, data.snmp_version || '3', data.community || null, data.security_level || null,
     data.username || null, data.auth_protocol || null, data.auth_secret || null,
     data.priv_protocol || null, data.priv_secret || null]
  );
  return r.rows[0];
}

async function updateSnmpCredential(id, data) {
  const r = await getPool().query(
    `UPDATE ipam_snmp_credentials SET name=$2, snmp_version=$3, community=$4, security_level=$5,
     username=$6, auth_protocol=$7, auth_secret=$8, priv_protocol=$9, priv_secret=$10, updated_at=NOW()
     WHERE id=$1 RETURNING *`,
    [id, data.name, data.snmp_version || '3', data.community || null, data.security_level || null,
     data.username || null, data.auth_protocol || null, data.auth_secret || null,
     data.priv_protocol || null, data.priv_secret || null]
  );
  return r.rows[0];
}

async function deleteSnmpCredential(id) {
  await getPool().query('DELETE FROM ipam_snmp_credentials WHERE id=$1', [id]);
}

// ─── Network Devices ────────────────────────────────────────────────────────
async function listNetworkDevices() {
  const r = await getPool().query(`
    SELECT d.*, s.name AS site_name, c.name AS credential_name
    FROM ipam_network_devices d
    LEFT JOIN ipam_sites s ON d.site_id = s.id
    LEFT JOIN ipam_snmp_credentials c ON d.snmp_credential_id = c.id
    ORDER BY d.name
  `);
  return r.rows;
}

async function getNetworkDeviceById(id) {
  const r = await getPool().query(
    'SELECT * FROM ipam_network_devices WHERE id=$1', [id]
  );
  return r.rows[0] || null;
}

async function createNetworkDevice(data) {
  const trunkPorts = Array.isArray(data.trunk_ports) ? data.trunk_ports : null;
  const relatedSwitches = Array.isArray(data.related_switches) ? data.related_switches : null;
  const r = await getPool().query(
    `INSERT INTO ipam_network_devices (site_id, name, hostname, management_ip, vendor, model, device_type, enabled, snmp_port, snmp_timeout_ms, snmp_retries, snmp_credential_id, trunk_ports, related_switches)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14) RETURNING *`,
    [data.site_id || null, data.name, data.hostname || null, data.management_ip,
     data.vendor || 'generic', data.model || null, data.device_type || 'switch',
     data.enabled !== false, data.snmp_port || 161, data.snmp_timeout_ms || 5000,
     data.snmp_retries || 2, data.snmp_credential_id || null, trunkPorts, relatedSwitches]
  );
  return r.rows[0];
}

async function updateNetworkDevice(id, data) {
  const trunkPorts = Array.isArray(data.trunk_ports) ? data.trunk_ports : null;
  const relatedSwitches = Array.isArray(data.related_switches) ? data.related_switches : null;
  const r = await getPool().query(
    `UPDATE ipam_network_devices SET site_id=$2, name=$3, hostname=$4, management_ip=$5, vendor=$6,
     model=$7, device_type=$8, enabled=$9, snmp_port=$10, snmp_timeout_ms=$11, snmp_retries=$12,
     snmp_credential_id=$13, trunk_ports=$14, related_switches=$15, updated_at=NOW() WHERE id=$1 RETURNING *`,
    [id, data.site_id || null, data.name, data.hostname || null, data.management_ip,
     data.vendor || 'generic', data.model || null, data.device_type || 'switch',
     data.enabled !== false, data.snmp_port || 161, data.snmp_timeout_ms || 5000,
     data.snmp_retries || 2, data.snmp_credential_id || null, trunkPorts, relatedSwitches]
  );
  return r.rows[0];
}

async function updateNetworkDevicePollStatus(id, status, error) {
  await getPool().query(
    'UPDATE ipam_network_devices SET last_poll_at=NOW(), last_poll_status=$2, last_poll_error=$3, updated_at=NOW() WHERE id=$1',
    [id, status, error || null]
  );
}

async function updateNetworkDeviceInfo(id, sysDescr, sysUptime) {
  await getPool().query(
    'UPDATE ipam_network_devices SET sys_descr=$2, sys_uptime=$3, updated_at=NOW() WHERE id=$1',
    [id, sysDescr || null, sysUptime || null]
  );
}

async function deleteNetworkDevice(id) {
  await getPool().query('DELETE FROM ipam_network_devices WHERE id=$1', [id]);
}

// ─── VLANs ──────────────────────────────────────────────────────────────────
async function listVlans(siteId) {
  let q = 'SELECT * FROM ipam_vlans';
  const params = [];
  if (siteId) {
    q += ' WHERE site_id=$1';
    params.push(siteId);
  }
  q += ' ORDER BY vlan_id';
  const r = await getPool().query(q, params);
  return r.rows;
}

async function getVlanById(id) {
  const r = await getPool().query('SELECT * FROM ipam_vlans WHERE id=$1', [id]);
  return r.rows[0] || null;
}

async function createVlan(data) {
  const r = await getPool().query(
    `INSERT INTO ipam_vlans (site_id, vlan_id, name, description, network, gateway, dhcp_source, enabled)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *`,
    [data.site_id || null, data.vlan_id, data.name || null, data.description || null,
     data.network || null, data.gateway || null, data.dhcp_source || null, data.enabled !== false]
  );
  return r.rows[0];
}

async function updateVlan(id, data) {
  const r = await getPool().query(
    `UPDATE ipam_vlans SET site_id=$2, vlan_id=$3, name=$4, description=$5, network=$6,
     gateway=$7, dhcp_source=$8, enabled=$9, updated_at=NOW() WHERE id=$1 RETURNING *`,
    [id, data.site_id || null, data.vlan_id, data.name || null, data.description || null,
     data.network || null, data.gateway || null, data.dhcp_source || null, data.enabled !== false]
  );
  return r.rows[0];
}

async function deleteVlan(id) {
  await getPool().query('DELETE FROM ipam_vlans WHERE id=$1', [id]);
}

// ─── Addresses ──────────────────────────────────────────────────────────────
async function listAddresses(filters) {
  let q = `SELECT a.*, v.vlan_id AS vlan_number, v.name AS vlan_name
           FROM ipam_addresses a LEFT JOIN ipam_vlans v ON a.vlan_id = v.id`;
  const conds = [];
  const params = [];

  if (filters.vlan_id) { params.push(filters.vlan_id); conds.push(`a.vlan_id=$${params.length}`); }
  if (filters.status) { params.push(filters.status); conds.push(`a.status=$${params.length}`); }
  if (filters.source) { params.push(filters.source); conds.push(`a.source=$${params.length}`); }
  if (filters.mac_address) {
    params.push(filters.mac_address.toUpperCase().replace(/:/g, '-'));
    conds.push(`a.mac_address=$${params.length}`);
  }
  if (filters.search) {
    params.push(`%${filters.search}%`);
    const idx = params.length;
    conds.push(`(a.address::text ILIKE $${idx} OR a.hostname ILIKE $${idx} OR a.owner ILIKE $${idx} OR a.mac_address ILIKE $${idx} OR a.description ILIKE $${idx})`);
  }

  if (conds.length) q += ' WHERE ' + conds.join(' AND ');
  q += ' ORDER BY a.address';

  if (filters.limit) {
    params.push(filters.limit);
    q += ` LIMIT $${params.length}`;
  }
  if (filters.offset) {
    params.push(filters.offset);
    q += ` OFFSET $${params.length}`;
  }

  const r = await getPool().query(q, params);
  return r.rows;
}

async function getAddressById(id) {
  const r = await getPool().query('SELECT * FROM ipam_addresses WHERE id=$1', [id]);
  return r.rows[0] || null;
}

async function upsertAddress(data) {
  const mac = data.mac_address ? data.mac_address.toUpperCase().replace(/:/g, '-') : null;
  const r = await getPool().query(
    `INSERT INTO ipam_addresses (vlan_id, address, status, hostname, description, owner, mac_address, source, device_id, last_seen_at, lease_expires_at)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
     ON CONFLICT (vlan_id, address) DO UPDATE SET
       status=EXCLUDED.status, hostname=COALESCE(EXCLUDED.hostname, ipam_addresses.hostname),
       owner=COALESCE(EXCLUDED.owner, ipam_addresses.owner),
       mac_address=COALESCE(EXCLUDED.mac_address, ipam_addresses.mac_address),
       source=EXCLUDED.source, device_id=COALESCE(EXCLUDED.device_id, ipam_addresses.device_id),
       last_seen_at=EXCLUDED.last_seen_at, updated_at=NOW()
     RETURNING *`,
    [data.vlan_id, data.address, data.status || 'observed', data.hostname || null,
     data.description || null, data.owner || null, mac, data.source || 'snmp',
     data.device_id || null, data.last_seen_at || new Date(), data.lease_expires_at || null]
  );
  return r.rows[0];
}

async function updateAddress(id, data) {
  const mac = data.mac_address ? data.mac_address.toUpperCase().replace(/:/g, '-') : null;
  const r = await getPool().query(
    `UPDATE ipam_addresses SET vlan_id=$2, address=$3, status=$4, hostname=$5, description=$6,
     owner=$7, mac_address=$8, source=$9, updated_at=NOW() WHERE id=$1 RETURNING *`,
    [id, data.vlan_id, data.address, data.status || 'available', data.hostname || null,
     data.description || null, data.owner || null, mac, data.source || 'manual']
  );
  return r.rows[0];
}

async function deleteAddress(id) {
  await getPool().query('DELETE FROM ipam_addresses WHERE id=$1', [id]);
}

async function getConflicts() {
  const r = await getPool().query(`
    SELECT a.address, a.vlan_id, array_agg(DISTINCT a.mac_address) AS macs, COUNT(*) AS cnt
    FROM ipam_addresses a
    WHERE a.status = 'conflict'
    GROUP BY a.address, a.vlan_id
    ORDER BY a.address
  `);
  return r.rows;
}

async function detectConflicts() {
  await getPool().query(`
    UPDATE ipam_addresses SET status='conflict', updated_at=NOW()
    WHERE address IN (
      SELECT address FROM ipam_addresses
      WHERE mac_address IS NOT NULL AND status != 'conflict'
      GROUP BY address HAVING COUNT(DISTINCT mac_address) > 1
    ) AND mac_address IS NOT NULL
  `);
}

async function getIpamStats() {
  const pool = getPool();
  const [subnets, assigned, available, conflicts, devices, activeDevices] = await Promise.all([
    pool.query('SELECT COUNT(*) FROM ipam_vlans'),
    pool.query("SELECT COUNT(*) FROM ipam_addresses WHERE status='assigned'"),
    pool.query("SELECT COUNT(*) FROM ipam_addresses WHERE status='available'"),
    pool.query("SELECT COUNT(*) FROM ipam_addresses WHERE status='conflict'"),
    pool.query('SELECT COUNT(*) FROM ipam_network_devices'),
    pool.query("SELECT COUNT(*) FROM ipam_network_devices WHERE last_poll_status='success'"),
  ]);
  return {
    subnets: parseInt(subnets.rows[0].count),
    assigned: parseInt(assigned.rows[0].count),
    available: parseInt(available.rows[0].count),
    conflicts: parseInt(conflicts.rows[0].count),
    devices: parseInt(devices.rows[0].count),
    active_devices: parseInt(activeDevices.rows[0].count),
  };
}

// ─── Observations ───────────────────────────────────────────────────────────
async function insertObservation(data) {
  const mac = data.mac_address ? data.mac_address.toUpperCase().replace(/:/g, '-') : null;
  await getPool().query(
    `INSERT INTO ipam_observations (address_id, device_id, ip_address, mac_address, interface_index, interface_name, vlan_id, source, switch_device_id, switch_port_name, switch_name)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
    [data.address_id || null, data.device_id || null, data.ip_address, mac,
     data.interface_index || null, data.interface_name || null, data.vlan_id || null, data.source || 'snmp',
     data.switch_device_id || null, data.switch_port_name || null, data.switch_name || null]
  );
}

async function listObservations(filters) {
  let q = `SELECT o.*, d.name AS device_name FROM ipam_observations o
           LEFT JOIN ipam_network_devices d ON o.device_id = d.id`;
  const conds = [];
  const params = [];
  if (filters.device_id) { params.push(filters.device_id); conds.push(`o.device_id=$${params.length}`); }
  if (filters.mac_address) { params.push(filters.mac_address); conds.push(`o.mac_address=$${params.length}`); }
  if (filters.ip_address) { params.push(filters.ip_address); conds.push(`o.ip_address=$${params.length}`); }
  if (filters.source) { params.push(filters.source); conds.push(`o.source=$${params.length}`); }
  if (conds.length) q += ' WHERE ' + conds.join(' AND ');
  q += ' ORDER BY o.observed_at DESC';
  if (filters.limit) { params.push(filters.limit); q += ` LIMIT $${params.length}`; }
  const r = await getPool().query(q, params);
  return r.rows;
}

// ─── Poll Runs ──────────────────────────────────────────────────────────────
async function createPollRun(deviceId) {
  const r = await getPool().query(
    'INSERT INTO ipam_poll_runs (device_id) VALUES ($1) RETURNING *', [deviceId]
  );
  return r.rows[0];
}

async function finishPollRun(id, status, recordsFound, error) {
  await getPool().query(
    'UPDATE ipam_poll_runs SET finished_at=NOW(), status=$2, records_found=$3, error=$4 WHERE id=$1',
    [id, status, recordsFound || 0, error || null]
  );
}

async function listPollRuns(deviceId) {
  let q = 'SELECT p.*, d.name AS device_name FROM ipam_poll_runs p LEFT JOIN ipam_network_devices d ON p.device_id = d.id';
  const params = [];
  if (deviceId) { params.push(deviceId); q += ' WHERE p.device_id=$1'; }
  q += ' ORDER BY p.started_at DESC LIMIT 50';
  const r = await getPool().query(q, params);
  return r.rows;
}

module.exports = {
  listSites, createSite, updateSite, deleteSite,
  listSnmpCredentials, getSnmpCredentialById, createSnmpCredential, updateSnmpCredential, deleteSnmpCredential,
  listNetworkDevices, getNetworkDeviceById, createNetworkDevice, updateNetworkDevice,
  updateNetworkDevicePollStatus, updateNetworkDeviceInfo, deleteNetworkDevice,
  listVlans, getVlanById, createVlan, updateVlan, deleteVlan,
  listAddresses, getAddressById, upsertAddress, updateAddress, deleteAddress, getConflicts, detectConflicts, getIpamStats,
  insertObservation, listObservations,
  createPollRun, finishPollRun, listPollRuns,
};

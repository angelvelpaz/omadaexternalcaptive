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
  const securityLevel = data.snmp_version === '2c' ? 'Community' : (data.security_level || null);
  const r = await getPool().query(
    `INSERT INTO ipam_snmp_credentials (name, snmp_version, community, security_level, username, auth_protocol, auth_secret, priv_protocol, priv_secret)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING *`,
    [data.name, data.snmp_version || '3', data.community || null, securityLevel,
     data.username || null, data.auth_protocol || null, data.auth_secret || null,
     data.priv_protocol || null, data.priv_secret || null]
  );
  return r.rows[0];
}

async function updateSnmpCredential(id, data) {
  const securityLevel = data.snmp_version === '2c' ? 'Community' : (data.security_level || null);
  const cols = [
    ['name', data.name],
    ['snmp_version', data.snmp_version || '3'],
    ['community', data.community || null],
    ['security_level', securityLevel],
    ['username', data.username || null],
    ['auth_protocol', data.auth_protocol || null],
    ['priv_protocol', data.priv_protocol || null],
  ];
  if (data.auth_secret) cols.push(['auth_secret', data.auth_secret]);
  if (data.priv_secret) cols.push(['priv_secret', data.priv_secret]);
  const sets = cols.map(([col], i) => `${col}=$${i + 2}`);
  const params = [id, ...cols.map(([, val]) => val)];
  const r = await getPool().query(
    `UPDATE ipam_snmp_credentials SET ${sets.join(', ')}, updated_at=NOW() WHERE id=$1 RETURNING *`,
    params
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
  let q = `SELECT a.*, v.vlan_id AS vlan_number, v.name AS vlan_name,
                  o.interface_name AS router_interface,
                  o.vlan_id AS observed_vlan_id,
                  o.switch_name,
                  o.switch_port_name
           FROM ipam_addresses a
           LEFT JOIN ipam_vlans v ON a.vlan_id = v.id
           LEFT JOIN LATERAL (
             SELECT interface_name, vlan_id, switch_name, switch_port_name
             FROM ipam_observations
             WHERE ip_address = a.address AND source = 'arp'
             ORDER BY observed_at DESC
             LIMIT 1
           ) o ON TRUE`;
  const conds = [];
  const params = [];

  if (filters.vlan_id && /^\d+$/.test(String(filters.vlan_id))) { params.push(filters.vlan_id); conds.push(`a.vlan_id=$${params.length}`); }
  if (filters.network) {
    params.push(String(filters.network));
    conds.push(`a.address <<= $${params.length}::cidr`);
  }
  if (filters.status) { params.push(filters.status); conds.push(`a.status=$${params.length}`); }
  if (filters.source) { params.push(filters.source); conds.push(`a.source=$${params.length}`); }
  if (filters.mac_address) {
    params.push(filters.mac_address.toUpperCase().replace(/:/g, '-'));
    conds.push(`a.mac_address=$${params.length}`);
  }
  if (filters.search) {
    params.push(`%${filters.search}%`);
    const idx = params.length;
    conds.push(`(a.address::text ILIKE $${idx} OR a.hostname ILIKE $${idx} OR a.owner ILIKE $${idx} OR a.mac_address ILIKE $${idx} OR a.description ILIKE $${idx} OR o.interface_name ILIKE $${idx} OR o.switch_name ILIKE $${idx} OR o.switch_port_name ILIKE $${idx})`);
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
     ON CONFLICT (address) DO UPDATE SET
       vlan_id = COALESCE(EXCLUDED.vlan_id, ipam_addresses.vlan_id),
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

// Resuelve la VLAN/red a la que pertenece una IP (CIDR más específico gana).
async function findVlanIdByIp(ip) {
  if (!ip) return null;
  const r = await getPool().query(
    `SELECT id FROM ipam_vlans WHERE network IS NOT NULL AND $1::inet <<= network
     ORDER BY masklen(network) DESC LIMIT 1`,
    [ip]
  );
  return r.rows[0] ? r.rows[0].id : null;
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
  const pool = getPool();
  const window = "o.source = 'arp' AND o.mac_address IS NOT NULL AND o.observed_at > NOW() - INTERVAL '1 hour'";
  // IPs ARP con >=2 MACs distintas observadas recientemente = conflicto
  await pool.query(`
    UPDATE ipam_addresses a SET status='conflict', updated_at=NOW()
    WHERE a.mac_address IS NOT NULL AND a.source = 'arp' AND EXISTS (
      SELECT 1 FROM ipam_observations o
      WHERE o.ip_address = a.address AND ${window}
      GROUP BY o.ip_address HAVING COUNT(DISTINCT o.mac_address) > 1
    )
  `);
  // Revertir a 'observed' las ARP-conflict que ya no muestran duplicidad (no toca manuales)
  await pool.query(`
    UPDATE ipam_addresses a SET status='observed', updated_at=NOW()
    WHERE a.status = 'conflict' AND a.source = 'arp' AND NOT EXISTS (
      SELECT 1 FROM ipam_observations o
      WHERE o.ip_address = a.address AND ${window}
      GROUP BY o.ip_address HAVING COUNT(DISTINCT o.mac_address) > 1
    )
  `);
}

// Utilización por subred: usables / usadas / disponibles / inactivas (>24h sin ver).
async function getSubnetUtilization() {
  const r = await getPool().query(`
    SELECT v.id, v.vlan_id, v.name, v.network,
           (POWER(2::numeric, 32 - masklen(v.network))::int - 2) AS usables,
           COUNT(a.*) FILTER (WHERE a.status <> 'available') AS usadas,
           COUNT(a.*) FILTER (WHERE a.status <> 'available'
             AND (a.last_seen_at IS NULL OR a.last_seen_at < NOW() - INTERVAL '24 hours')) AS inactivas
    FROM ipam_vlans v
    LEFT JOIN ipam_addresses a ON a.address <<= v.network
    WHERE v.network IS NOT NULL
    GROUP BY v.id, v.vlan_id, v.name, v.network
    ORDER BY v.vlan_id
  `);
  return r.rows.map(row => {
    const usables = Number(row.usables);
    const usadas = Number(row.usadas);
    return { ...row, usables, usadas, disponibles: Math.max(0, usables - usadas) };
  });
}

// Purga automática: IPs descubiertas por ARP no vistas en 90 días.
// NUNCA toca filas manuales/assigned/reserved. Devuelve nº de filas borradas.
async function pruneStaleArpAddresses() {
  const r = await getPool().query(`
    DELETE FROM ipam_addresses
    WHERE source = 'arp' AND status IN ('observed', 'conflict')
      AND last_seen_at IS NOT NULL
      AND last_seen_at < NOW() - INTERVAL '90 days'`);
  return r.rowCount;
}

// IPs pendientes de hostname: sin nombre y nunca revisadas, o revisadas hace
// más del cooldown (para reintentar si algún día publican su PTR).
async function getIpsMissingHostname({ cooldownDays = 7, limit = 150 } = {}) {
  const r = await getPool().query(
    `SELECT host(address) AS ip FROM ipam_addresses
     WHERE hostname IS NULL
       AND (hostname_checked_at IS NULL
            OR hostname_checked_at < NOW() - make_interval(days => $1))
     ORDER BY (hostname_checked_at IS NULL) DESC, last_seen_at DESC NULLS LAST
     LIMIT $2`,
    [cooldownDays, limit]
  );
  return r.rows.map(x => x.ip);
}

// Persiste resultados PTR: guarda hostname si vino (nunca pisa el existente)
// y marca hostname_checked_at para todas las intentadas.
async function recordHostnameResolution(results) {
  const client = await getPool().connect();
  try {
    await client.query('BEGIN');
    for (const { ip, hostname } of results || []) {
      if (!ip) continue;
      await client.query(
        `UPDATE ipam_addresses
         SET hostname = COALESCE($2, hostname), hostname_checked_at = NOW(), updated_at = NOW()
         WHERE host(address) = $1`,
        [ip, hostname || null]
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

// Direcciones dentro de las subredes (CIDR) de las VLANs registradas.
// Enumera hosts usables y los clasifica: free | occupied | reserved(gateway).
async function getSubnetAddresses(filters = {}) {
  const params = [];
  // nets: VLANs con red, /22 o menores (masklen>=22) para no enumerar rangos gigantes
  let netsWhere = 'v.network IS NOT NULL AND masklen(v.network) >= 22';
  if (filters.vlan_id && /^\d+$/.test(String(filters.vlan_id))) {
    params.push(filters.vlan_id);
    netsWhere += ` AND v.id = $${params.length}`;
  }
  let joinedWhere = '';
  if (filters.search) {
    params.push(`%${filters.search}%`);
    const s = params.length;
    joinedWhere = `WHERE (host(h.address)::text ILIKE $${s} OR a.owner ILIKE $${s}
      OR a.hostname ILIKE $${s} OR a.mac_address ILIKE $${s})`;
  }

  const base = `
    WITH nets AS (
      SELECT v.id AS vlan_db, v.vlan_id, v.name, v.network, v.gateway, masklen(v.network) AS m
      FROM ipam_vlans v WHERE ${netsWhere}
    ),
    hosts AS (
      SELECT n.vlan_db, n.vlan_id, n.name, n.network, n.gateway,
             (set_masklen(n.network, 32)::inet + gs.i) AS address
      FROM nets n
      CROSS JOIN LATERAL generate_series(1, (power(2, 32 - n.m))::int - 2) AS gs(i)
    ),
    joined AS (
      SELECT h.address, h.vlan_db, h.vlan_id, h.name AS vlan_name, h.network,
             a.id AS address_id, a.status, a.mac_address, a.owner, a.hostname, a.source, a.last_seen_at,
             CASE
               WHEN h.gateway IS NOT NULL AND h.address = h.gateway THEN 'reserved'
               WHEN a.id IS NULL OR a.status = 'available' THEN 'free'
               ELSE 'occupied'
             END AS usage_state,
             (a.last_seen_at IS NOT NULL AND a.last_seen_at < NOW() - INTERVAL '24 hours') AS is_stale
      FROM hosts h
      LEFT JOIN ipam_addresses a ON a.address = h.address
      ${joinedWhere}
    )`;

  const pool = getPool();
  const sum = await pool.query(`
    ${base}
    SELECT COUNT(*)::int AS total,
           COUNT(*) FILTER (WHERE usage_state = 'occupied') AS ocupadas,
           COUNT(*) FILTER (WHERE usage_state = 'free') AS libres,
           COUNT(*) FILTER (WHERE usage_state = 'reserved') AS reservadas
    FROM joined`, params);
  const s = sum.rows[0];

  const usageConds = [];
  if (filters.usage === 'used') usageConds.push(`usage_state IN ('occupied','reserved')`);
  else if (filters.usage === 'free') usageConds.push(`usage_state = 'free'`);
  const whereSql = usageConds.length ? ' WHERE ' + usageConds.join(' AND ') : '';

  const limit = parseInt(filters.limit) || 50;
  const offset = parseInt(filters.offset) || 0;
  const n = params.length;
  const cnt = await pool.query(`${base} SELECT COUNT(*)::int c FROM joined${whereSql}`, params);
  const filteredTotal = Number(cnt.rows[0].c);
  const rows = await pool.query(`
    ${base}
    SELECT * FROM joined${whereSql}
    ORDER BY network::inet, host(address)::inet
    LIMIT $${n + 1} OFFSET $${n + 2}`,
    [...params, limit, offset]);

  return {
    data: rows.rows,
    total: filteredTotal,
    summary: {
      total: Number(s.total),
      ocupadas: Number(s.ocupadas),
      libres: Number(s.libres),
      reservadas: Number(s.reservadas),
    },
  };
}

async function getArpSpoofingAlerts() {
  const r = await getPool().query(`
    WITH latest AS (
      SELECT DISTINCT ON (ip_address)
        ip_address, mac_address AS current_mac, observed_at AS current_seen
      FROM ipam_observations
      WHERE source = 'arp' AND mac_address IS NOT NULL
      ORDER BY ip_address, observed_at DESC
    ),
    historical AS (
      SELECT ip_address, mac_address AS hist_mac, COUNT(*) AS freq
      FROM ipam_observations
      WHERE source = 'arp' AND mac_address IS NOT NULL
      GROUP BY ip_address, mac_address
    ),
    most_freq AS (
      SELECT DISTINCT ON (ip_address)
        ip_address, hist_mac, freq
      FROM historical
      ORDER BY ip_address, freq DESC
    ),
    suspects AS (
      SELECT l.ip_address, l.current_mac, l.current_seen,
             m.hist_mac AS expected_mac, m.freq AS expected_freq
      FROM latest l
      JOIN most_freq m ON m.ip_address = l.ip_address
      LEFT JOIN resolved_arp_alerts r ON r.ip_address = l.ip_address
      WHERE l.current_mac != m.hist_mac AND r.id IS NULL
    )
    SELECT s.ip_address, s.current_mac, s.current_seen,
           s.expected_mac, s.expected_freq,
           f.device_id, f.bridge_port, f.interface_name AS switch_port,
           d.name AS switch_name, d.management_ip AS switch_ip
    FROM suspects s
    LEFT JOIN ipam_fdb_entries f ON f.mac_address = s.current_mac
    LEFT JOIN ipam_network_devices d ON d.id = f.device_id
    ORDER BY s.current_seen DESC
  `);
  return r.rows;
}

async function resolveArpAlert(ipAddress) {
  await getPool().query(
    `INSERT INTO resolved_arp_alerts (ip_address, resolved_at) VALUES ($1, NOW())
     ON CONFLICT (ip_address) DO UPDATE SET resolved_at = NOW()`,
    [ipAddress]
  );
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

async function replaceFdbEntries(deviceId, entries, trunkIfIndexes = []) {
  const pool = getPool();
  const client = await pool.connect();
  try {
    const validEntries = (entries || []).filter(e => e.mac);

    // Safety: don't replace if new data is empty (SNMP walk likely failed)
    if (validEntries.length === 0) {
      return;
    }

    await client.query('BEGIN');

    // Reset trunk flag for this device (recomputed by upsert below)
    await client.query('UPDATE ipam_fdb_entries SET is_trunk = FALSE WHERE device_id = $1', [deviceId]);

    // Upsert new entries (COALESCE so NULL bridge_port/vlan_id dedupe correctly)
    for (const entry of validEntries) {
      await client.query(
        `INSERT INTO ipam_fdb_entries
          (device_id, mac_address, bridge_port, if_index, interface_name, vlan_id, is_trunk, last_seen_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7,NOW())
         ON CONFLICT (device_id, mac_address, COALESCE(bridge_port, 0), COALESCE(vlan_id, 0))
         DO UPDATE SET if_index = EXCLUDED.if_index, interface_name = EXCLUDED.interface_name,
           is_trunk = EXCLUDED.is_trunk, last_seen_at = NOW()`,
        [deviceId, entry.mac.toUpperCase(), entry.port || null, entry.ifIndex || null,
         entry.interfaceName || null, entry.vlanId || null,
         trunkIfIndexes.includes(entry.ifIndex)]
      );
    }

    // Remove entries not seen in more than 1 hour
    await client.query("DELETE FROM ipam_fdb_entries WHERE device_id = $1 AND last_seen_at < NOW() - INTERVAL '1 hour'", [deviceId]);

    await client.query('COMMIT');
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}

async function listFdbEntries(filters = {}) {
  const base = `FROM ipam_fdb_entries f
    JOIN ipam_network_devices d ON d.id = f.device_id
    LEFT JOIN LATERAL (
      SELECT ip_address, interface_name, switch_name, switch_port_name
      FROM ipam_observations
      WHERE mac_address = f.mac_address AND source = 'arp' AND ip_address IS NOT NULL
      ORDER BY observed_at DESC
      LIMIT 1
    ) arp ON TRUE`;

  const conds = [];
  const params = [];
  if (filters.device_id) { params.push(filters.device_id); conds.push(`f.device_id=$${params.length}`); }
  if (filters.search) {
    params.push(`%${filters.search}%`);
    const idx = params.length;
    conds.push(`(f.mac_address ILIKE $${idx} OR f.interface_name ILIKE $${idx} OR f.description ILIKE $${idx} OR d.name ILIKE $${idx} OR arp.ip_address::text ILIKE $${idx})`);
  }
  if (filters.ip_status === 'with') conds.push('arp.ip_address IS NOT NULL');
  else if (filters.ip_status === 'without') conds.push('arp.ip_address IS NULL');
  if (filters.type === 'trunk') conds.push('f.is_trunk = TRUE');
  else if (filters.type === 'access') conds.push('f.is_trunk = FALSE');

  // Respect port selection: if a switch has selected ports, show only hosts on them.
  // If a switch has no selection configured, show all (backwards compatible).
  if (filters.respect_selection !== false) {
    conds.push(`(
      NOT EXISTS (SELECT 1 FROM ipam_switch_ports s WHERE s.switch_device_id = f.device_id AND s.selected = TRUE)
      OR EXISTS (SELECT 1 FROM ipam_switch_ports s2 WHERE s2.switch_device_id = f.device_id AND s2.selected = TRUE AND s2.if_index = f.if_index)
    )`);
  }

  const whereSql = conds.length ? ' WHERE ' + conds.join(' AND ') : '';
  const pool = getPool();

  const countR = await pool.query(`SELECT COUNT(*)::int AS total ${base}${whereSql}`, params);
  const total = countR.rows[0].total;

  const limit = parseInt(filters.limit) || 10;
  const offset = parseInt(filters.offset) || 0;
  const q = `SELECT f.*, d.name AS device_name, d.management_ip,
                   arp.ip_address AS associated_ip,
                   arp.interface_name AS router_interface,
                   arp.switch_name AS correlated_switch_name,
                   arp.switch_port_name AS correlated_switch_port
            ${base}${whereSql}
            ORDER BY d.name, f.interface_name, f.mac_address
            LIMIT $${params.length + 1} OFFSET $${params.length + 2}`;
  const r = await pool.query(q, [...params, limit, offset]);
  return { data: r.rows, total, limit, offset };
}

async function updateFdbDescription(id, description) {
  const r = await getPool().query(
    'UPDATE ipam_fdb_entries SET description = $2 WHERE id = $1 RETURNING *',
    [id, description || null]
  );
  return r.rows[0] || null;
}

// B′: para un conjunto de MACs, devuelve en qué puerto de ACCESO (seleccionado y no
// troncal) de cualquier switch habilitado están aprendidas. Reemplaza related_switches.
async function listSwitchPortMapForMacs(macs) {
  if (!macs || !macs.length) return [];
  const upper = [...new Set(macs.map(m => String(m).toUpperCase()))];
  const r = await getPool().query(`
    SELECT f.mac_address, f.device_id AS switch_device_id, d.name AS switch_name,
           f.if_index, COALESCE(f.interface_name, 'if' || f.if_index) AS switch_port_name
    FROM ipam_fdb_entries f
    JOIN ipam_network_devices d ON d.id = f.device_id AND d.enabled = TRUE AND d.device_type = 'switch'
    JOIN ipam_switch_ports sp ON sp.switch_device_id = f.device_id AND sp.if_index = f.if_index AND sp.selected = TRUE
    WHERE f.mac_address = ANY($1) AND f.is_trunk = FALSE
    ORDER BY d.name, f.mac_address`,
    [upper]
  );
  return r.rows;
}

async function listSwitchPorts(deviceId) {
  const r = await getPool().query(
    `SELECT * FROM ipam_switch_ports
     WHERE switch_device_id = $1
     ORDER BY if_index`, [deviceId]
  );
  return r.rows;
}

async function getSelectedSwitchPortIndexes(deviceId) {
  const r = await getPool().query(
    'SELECT if_index FROM ipam_switch_ports WHERE switch_device_id=$1 AND selected=TRUE ORDER BY if_index',
    [deviceId]
  );
  return r.rows.map(row => row.if_index);
}

async function saveSwitchPorts(deviceId, ports) {
  const client = await getPool().connect();
  try {
    await client.query('BEGIN');
    await client.query('DELETE FROM ipam_switch_ports WHERE switch_device_id=$1', [deviceId]);
    for (const port of ports || []) {
      if (!Number.isInteger(Number(port.if_index)) || !port.interface_name) continue;
      await client.query(
        `INSERT INTO ipam_switch_ports
          (switch_device_id, if_index, interface_name, interface_alias, selected, is_trunk)
         VALUES ($1,$2,$3,$4,$5,$6)`,
        [deviceId, Number(port.if_index), port.interface_name, port.interface_alias || null,
         port.selected === true, port.is_trunk === true]
      );
    }
    await client.query('COMMIT');
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
  return listSwitchPorts(deviceId);
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
  listAddresses, getAddressById, upsertAddress, updateAddress, deleteAddress,   getConflicts, detectConflicts, getArpSpoofingAlerts, resolveArpAlert, getIpamStats,
  findVlanIdByIp, getSubnetUtilization, getSubnetAddresses, pruneStaleArpAddresses,
  getIpsMissingHostname, recordHostnameResolution,
  insertObservation, listObservations, replaceFdbEntries, listFdbEntries, updateFdbDescription, listSwitchPortMapForMacs,
  listSwitchPorts, getSelectedSwitchPortIndexes, saveSwitchPorts,
  createPollRun, finishPollRun, listPollRuns,
};

'use strict';

const express = require('express');
const router = express.Router();
const ipamDb = require('../services/db/ipam');
const { testSnmp, runDiscovery, pollDevice } = require('../services/ipamDiscoveryWorker');
const db = require('../services/database');

const ADMIN_SECRET = process.env.ADMIN_SECRET || '';

async function requireAdmin(req, res, next) {
  const auth = req.headers.authorization || '';
  let token = auth.startsWith('Bearer ') ? auth.slice(7) : (req.headers['x-admin-token'] || null);
  if (!token) return res.status(401).json({ error: 'No autorizado.' });

  try {
    if (process.env.NODE_ENV !== 'production' && token === ADMIN_SECRET) {
      req.adminUser = 'admin';
      req.adminRol = 'superadministrador';
      return next();
    }
    const session = await db.getAdminBySessionToken(token);
    if (!session) return res.status(401).json({ error: 'Sesión no válida.' });
    req.adminUser = session.username;
    req.adminRol = session.rol || 'operador';
    next();
  } catch (err) { next(err); }
}

router.use(requireAdmin);

// ─── Dashboard ──────────────────────────────────────────────────────────────
router.get('/stats', async (req, res, next) => {
  try {
    const stats = await ipamDb.getIpamStats();
    res.json(stats);
  } catch (err) { next(err); }
});

// ─── Sites ──────────────────────────────────────────────────────────────────
router.get('/sites', async (req, res, next) => {
  try { res.json(await ipamDb.listSites()); } catch (err) { next(err); }
});

router.post('/sites', async (req, res, next) => {
  try {
    const { name, description, timezone } = req.body;
    if (!name) return res.status(400).json({ error: 'Nombre requerido.' });
    res.json(await ipamDb.createSite(name, description, timezone));
  } catch (err) { next(err); }
});

router.put('/sites/:id', async (req, res, next) => {
  try {
    const { name, description, timezone } = req.body;
    res.json(await ipamDb.updateSite(req.params.id, name, description, timezone));
  } catch (err) { next(err); }
});

router.delete('/sites/:id', async (req, res, next) => {
  try { await ipamDb.deleteSite(req.params.id); res.json({ ok: true }); } catch (err) { next(err); }
});

// ─── SNMP Credentials ───────────────────────────────────────────────────────
router.get('/credentials', async (req, res, next) => {
  try { res.json(await ipamDb.listSnmpCredentials()); } catch (err) { next(err); }
});

router.post('/credentials', async (req, res, next) => {
  try {
    const { name, snmp_version, community, security_level, username, auth_protocol, auth_secret, priv_protocol, priv_secret } = req.body;
    if (!name) return res.status(400).json({ error: 'Nombre requerido.' });
    res.json(await ipamDb.createSnmpCredential({ name, snmp_version, community, security_level, username, auth_protocol, auth_secret, priv_protocol, priv_secret }));
  } catch (err) { next(err); }
});

router.put('/credentials/:id', async (req, res, next) => {
  try {
    const { name, snmp_version, community, security_level, username, auth_protocol, auth_secret, priv_protocol, priv_secret } = req.body;
    res.json(await ipamDb.updateSnmpCredential(req.params.id, { name, snmp_version, community, security_level, username, auth_protocol, auth_secret, priv_protocol, priv_secret }));
  } catch (err) { next(err); }
});

router.delete('/credentials/:id', async (req, res, next) => {
  try { await ipamDb.deleteSnmpCredential(req.params.id); res.json({ ok: true }); } catch (err) { next(err); }
});

// ─── Network Devices ────────────────────────────────────────────────────────
router.get('/devices', async (req, res, next) => {
  try { res.json(await ipamDb.listNetworkDevices()); } catch (err) { next(err); }
});

router.get('/devices/:id', async (req, res, next) => {
  try {
    const dev = await ipamDb.getNetworkDeviceById(req.params.id);
    if (!dev) return res.status(404).json({ error: 'Dispositivo no encontrado.' });
    res.json(dev);
  } catch (err) { next(err); }
});

router.post('/devices', async (req, res, next) => {
  try {
    const { name, hostname, management_ip, vendor, model, device_type, site_id, snmp_port, snmp_timeout_ms, snmp_retries, snmp_credential_id, trunk_ports } = req.body;
    if (!name || !management_ip) return res.status(400).json({ error: 'Nombre e IP de gestión requeridos.' });
    res.json(await ipamDb.createNetworkDevice({ name, hostname, management_ip, vendor, model, device_type, site_id, snmp_port, snmp_timeout_ms, snmp_retries, snmp_credential_id, trunk_ports }));
  } catch (err) { next(err); }
});

router.put('/devices/:id', async (req, res, next) => {
  try {
    const { name, hostname, management_ip, vendor, model, device_type, site_id, snmp_port, snmp_timeout_ms, snmp_retries, snmp_credential_id, enabled, trunk_ports } = req.body;
    res.json(await ipamDb.updateNetworkDevice(req.params.id, { name, hostname, management_ip, vendor, model, device_type, site_id, snmp_port, snmp_timeout_ms, snmp_retries, snmp_credential_id, enabled, trunk_ports }));
  } catch (err) { next(err); }
});

router.delete('/devices/:id', async (req, res, next) => {
  try { await ipamDb.deleteNetworkDevice(req.params.id); res.json({ ok: true }); } catch (err) { next(err); }
});

router.post('/devices/:id/test-snmp', async (req, res, next) => {
  try {
    const dev = await ipamDb.getNetworkDeviceById(req.params.id);
    if (!dev) return res.status(404).json({ error: 'Dispositivo no encontrado.' });

    const credential = dev.snmp_credential_id
      ? await ipamDb.getSnmpCredentialById(dev.snmp_credential_id)
      : {};

    const result = await testSnmp({
      host: dev.management_ip,
      port: dev.snmp_port || 161,
      timeout: dev.snmp_timeout_ms || 5000,
      retries: dev.snmp_retries || 2,
      snmp_version: credential?.snmp_version || '2c',
      community: credential?.community || 'public',
      username: credential?.username || '',
      security_level: credential?.security_level || 'authPriv',
      auth_protocol: credential?.auth_protocol || '',
      auth_secret: credential?.auth_secret || '',
      priv_protocol: credential?.priv_protocol || '',
      priv_secret: credential?.priv_secret || '',
    });

    if (result.ok) {
      await ipamDb.updateNetworkDeviceInfo(dev.id, result.sysDescr, result.sysUptime);
      await ipamDb.updateNetworkDevicePollStatus(dev.id, 'success', null);
    } else {
      await ipamDb.updateNetworkDevicePollStatus(dev.id, 'error', result.error);
    }

    res.json(result);
  } catch (err) { next(err); }
});

router.post('/devices/:id/poll', async (req, res, next) => {
  try {
    const dev = await ipamDb.getNetworkDeviceById(req.params.id);
    if (!dev) return res.status(404).json({ error: 'Dispositivo no encontrado.' });
    const result = await pollDevice(dev);
    res.json(result);
  } catch (err) { next(err); }
});

// ─── VLANs ──────────────────────────────────────────────────────────────────
router.get('/vlans', async (req, res, next) => {
  try { res.json(await ipamDb.listVlans(req.query.site_id)); } catch (err) { next(err); }
});

router.post('/vlans', async (req, res, next) => {
  try {
    const { site_id, vlan_id, name, description, network, gateway, dhcp_source } = req.body;
    if (!vlan_id) return res.status(400).json({ error: 'VLAN ID requerido.' });
    res.json(await ipamDb.createVlan({ site_id, vlan_id, name, description, network, gateway, dhcp_source }));
  } catch (err) { next(err); }
});

router.put('/vlans/:id', async (req, res, next) => {
  try {
    const { site_id, vlan_id, name, description, network, gateway, dhcp_source, enabled } = req.body;
    res.json(await ipamDb.updateVlan(req.params.id, { site_id, vlan_id, name, description, network, gateway, dhcp_source, enabled }));
  } catch (err) { next(err); }
});

router.delete('/vlans/:id', async (req, res, next) => {
  try { await ipamDb.deleteVlan(req.params.id); res.json({ ok: true }); } catch (err) { next(err); }
});

// ─── Addresses ──────────────────────────────────────────────────────────────
router.get('/addresses', async (req, res, next) => {
  try {
    const { vlan_id, status, source, mac_address, search, limit, offset } = req.query;
    res.json(await ipamDb.listAddresses({ vlan_id, status, source, mac_address, search, limit: parseInt(limit) || 200, offset: parseInt(offset) || 0 }));
  } catch (err) { next(err); }
});

router.get('/addresses/conflicts', async (req, res, next) => {
  try { res.json(await ipamDb.getConflicts()); } catch (err) { next(err); }
});

router.post('/addresses', async (req, res, next) => {
  try {
    const { vlan_id, address, status, hostname, description, owner, mac_address, source } = req.body;
    if (!address) return res.status(400).json({ error: 'Dirección IP requerida.' });
    res.json(await ipamDb.upsertAddress({ vlan_id, address, status: status || 'assigned', hostname, description, owner, mac_address, source: source || 'manual' }));
  } catch (err) { next(err); }
});

router.put('/addresses/:id', async (req, res, next) => {
  try {
    const { vlan_id, address, status, hostname, description, owner, mac_address, source } = req.body;
    res.json(await ipamDb.updateAddress(req.params.id, { vlan_id, address, status, hostname, description, owner, mac_address, source }));
  } catch (err) { next(err); }
});

router.delete('/addresses/:id', async (req, res, next) => {
  try { await ipamDb.deleteAddress(req.params.id); res.json({ ok: true }); } catch (err) { next(err); }
});

// ─── Observations ───────────────────────────────────────────────────────────
router.get('/observations', async (req, res, next) => {
  try {
    const { device_id, mac_address, ip_address, limit } = req.query;
    res.json(await ipamDb.listObservations({ device_id, mac_address, ip_address, limit: parseInt(limit) || 100 }));
  } catch (err) { next(err); }
});

// ─── Poll Runs ──────────────────────────────────────────────────────────────
router.get('/poll-runs', async (req, res, next) => {
  try { res.json(await ipamDb.listPollRuns(req.query.device_id)); } catch (err) { next(err); }
});

// ─── Discovery ──────────────────────────────────────────────────────────────
router.post('/discovery/run', async (req, res, next) => {
  try {
    runDiscovery();
    res.json({ ok: true, message: 'Descubrimiento iniciado en segundo plano.' });
  } catch (err) { next(err); }
});

module.exports = router;

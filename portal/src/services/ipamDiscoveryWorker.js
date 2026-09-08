'use strict';

const ipamDb = require('./db/ipam');
const { buildSession, getTarget, closeSession, OIDS } = require('./snmpClient');
const { poll: genericPoll } = require('./snmpAdapters/generic');
const { poll: mikrotikPoll } = require('./snmpAdapters/mikrotik');
const { poll: ciscoPoll } = require('./snmpAdapters/cisco');
const { poll: hpePoll } = require('./snmpAdapters/hpe');
const { poll: ruijiePoll } = require('./snmpAdapters/ruijie');

let running = false;
let intervalHandle = null;
const INTERVAL_MS = 5 * 60 * 1000;

function getAdapter(vendor) {
  switch ((vendor || '').toLowerCase()) {
    case 'mikrotik': return mikrotikPoll;
    case 'cisco': return ciscoPoll;
    case 'hpe':
    case 'aruba':
    case 'hp': return hpePoll;
    case 'ruijie': return ruijiePoll;
    default: return genericPoll;
  }
}

async function pollDevice(device) {
  const pollRun = await ipamDb.createPollRun(device.id);
  const credential = device.snmp_credential_id
    ? await ipamDb.getSnmpCredentialById(device.snmp_credential_id)
    : {};

  const deviceConfig = {
    host: device.management_ip,
    port: device.snmp_port || 161,
    timeout: device.snmp_timeout_ms || 5000,
    retries: device.snmp_retries || 2,
    snmp_version: credential?.snmp_version || '2c',
    community: credential?.community || 'public',
    username: credential?.username || '',
    security_level: credential?.security_level || 'authPriv',
    auth_protocol: credential?.auth_protocol || '',
    auth_secret: credential?.auth_secret || '',
    priv_protocol: credential?.priv_protocol || '',
    priv_secret: credential?.priv_secret || '',
  };

  const adapter = getAdapter(device.vendor);
  const result = await adapter(deviceConfig);

  if (result.identity) {
    await ipamDb.updateNetworkDeviceInfo(device.id, result.identity.sysDescr, result.identity.sysUptime);
  }

  let recordCount = 0;

  for (const entry of result.arp) {
    if (!entry.ip || !entry.mac) continue;
    await ipamDb.upsertAddress({
      address: entry.ip,
      mac_address: entry.mac,
      status: 'observed',
      source: 'arp',
      device_id: device.id,
      last_seen_at: new Date(),
    });
    await ipamDb.insertObservation({
      ip_address: entry.ip,
      mac_address: entry.mac,
      interface_index: entry.ifIndex,
      device_id: device.id,
      source: 'arp',
    });
    recordCount++;
  }

  for (const entry of result.macTable) {
    if (!entry.mac) continue;
    await ipamDb.insertObservation({
      mac_address: entry.mac,
      interface_index: entry.ifIndex,
      device_id: device.id,
      source: 'fdb',
    });
    recordCount++;
  }

  if (result.errors.length === 0) {
    await ipamDb.updateNetworkDevicePollStatus(device.id, 'success', null);
    await ipamDb.finishPollRun(pollRun.id, 'success', recordCount, null);
  } else {
    await ipamDb.updateNetworkDevicePollStatus(device.id, 'warning', result.errors.join('; '));
    await ipamDb.finishPollRun(pollRun.id, 'warning', recordCount, result.errors.join('; '));
  }

  return { deviceId: device.id, records: recordCount, errors: result.errors };
}

async function runDiscovery() {
  if (running) return;
  running = true;
  console.log('[IPAM-WORKER] Iniciando descubrimiento SNMP...');

  try {
    const devices = await ipamDb.listNetworkDevices();
    const enabled = devices.filter(d => d.enabled);

    for (const device of enabled) {
      try {
        const result = await pollDevice(device);
        console.log(`[IPAM-WORKER] ${device.name}: ${result.records} registros, ${result.errors.length} errores`);
      } catch (err) {
        console.error(`[IPAM-WORKER] Error en ${device.name}:`, err.message);
        await ipamDb.updateNetworkDevicePollStatus(device.id, 'error', err.message);
      }
    }

    await ipamDb.detectConflicts();
    console.log('[IPAM-WORKER] Descubrimiento completado.');
  } catch (err) {
    console.error('[IPAM-WORKER] Error general:', err.message);
  }

  running = false;
}

function startIpamWorker() {
  if (intervalHandle) return;
  console.log('[IPAM-WORKER] Worker iniciado (intervalo: 5 min)');
  setTimeout(runDiscovery, 30000);
  intervalHandle = setInterval(runDiscovery, INTERVAL_MS);
}

function stopIpamWorker() {
  if (intervalHandle) {
    clearInterval(intervalHandle);
    intervalHandle = null;
  }
}

async function testSnmp(deviceConfig) {
  const session = buildSession(deviceConfig);
  try {
    const sysName = await getTarget(session, OIDS.sysName);
    const sysDescr = await getTarget(session, OIDS.sysDescr);
    const sysUpTime = await getTarget(session, OIDS.sysUpTime);
    return {
      ok: true,
      sysName: String(sysName || ''),
      sysDescr: String(sysDescr || ''),
      sysUptime: Number(sysUpTime || 0),
    };
  } catch (err) {
    return { ok: false, error: err.message };
  } finally {
    closeSession(session);
  }
}

module.exports = { runDiscovery, startIpamWorker, stopIpamWorker, pollDevice, testSnmp };

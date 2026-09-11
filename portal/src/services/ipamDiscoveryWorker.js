'use strict';

const ipamDb = require('./db/ipam');
const { resolveHostnames } = require('./reverseDns');
const { buildSession, getTarget, closeSession, OIDS } = require('./snmpClient');
const { poll: genericPoll, pollArpOnly: genericArpOnly, pollFdbOnly: genericFdbOnly, getInterfaces: genericGetInterfaces, getInterfacesPhysical: genericGetInterfacesPhysical } = require('./snmpAdapters/generic');
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
    trunk_ports: device.trunk_ports || [],
    include_trunks: device.device_type === 'switch',
  };

  const adapter = getAdapter(device.vendor);
  const result = await adapter(deviceConfig);

  if (result.identity) {
    await ipamDb.updateNetworkDeviceInfo(device.id, result.identity.sysDescr, result.identity.sysUptime);
  }

  // Build interface index -> name map
  const ifMap = {};
  for (const iface of (result.interfaces || [])) {
    ifMap[iface.ifIndex] = iface.descr || iface.alias || ('if' + iface.ifIndex);
  }

  const trunkIfIndexes = (result.interfaces || [])
    .filter(i => (device.trunk_ports || []).includes(i.descr) || (device.trunk_ports || []).includes(String(i.ifIndex)))
    .map(i => i.ifIndex);

  if (device.device_type === 'switch' && result.macTable) {
    const fdbEntries = result.macTable.map(entry => ({
      ...entry,
      interfaceName: ifMap[entry.ifIndex] || null,
    }));
    await ipamDb.replaceFdbEntries(device.id, fdbEntries, trunkIfIndexes);
  }

  // B′: mapear MAC → puerto de acceso considerando TODOS los switches habilitados,
  // usando su FDB almacenada (solo puertos de acceso seleccionados y no troncales).
  // Reemplaza la lógica por related_switches y ya no descarta hosts por no estar en la FDB.
  const macToSwitchPort = {};
  if (device.device_type === 'router') {
    const arpMacs = (result.arp || []).map(a => a.mac).filter(Boolean);
    if (arpMacs.length > 0) {
      try {
        const rows = await ipamDb.listSwitchPortMapForMacs(arpMacs);
        for (const row of rows) {
          if (!macToSwitchPort[row.mac_address]) {
            macToSwitchPort[row.mac_address] = {
              switchId: row.switch_device_id,
              switchName: row.switch_name,
              ifIndex: row.if_index,
              portName: row.switch_port_name,
            };
          }
        }
      } catch (err) {
        console.error('[IPAM-WORKER] Error mapeando MACs a puertos de switch:', err.message);
      }
    }
  }

  let recordCount = 0;

  for (const entry of result.arp) {
    if (!entry.ip || !entry.mac) continue;

    const vlanId = await ipamDb.findVlanIdByIp(entry.ip);

    await ipamDb.upsertAddress({
      address: entry.ip,
      vlan_id: vlanId,
      mac_address: entry.mac,
      status: 'observed',
      source: 'arp',
      device_id: device.id,
      last_seen_at: new Date(),
    });

    // Look up switch port for this MAC (B′: todos los switches, solo puertos de acceso)
    const swPort = macToSwitchPort[String(entry.mac).toUpperCase()] || null;

    await ipamDb.insertObservation({
      ip_address: entry.ip,
      mac_address: entry.mac,
      vlan_id: vlanId,
      interface_index: entry.ifIndex,
      interface_name: ifMap[entry.ifIndex] || null,
      device_id: device.id,
      switch_device_id: swPort ? swPort.switchId : null,
      switch_port_name: swPort ? swPort.portName : null,
      switch_name: swPort ? swPort.switchName : null,
      source: 'arp',
    });
    recordCount++;
  }

  for (const entry of result.macTable) {
    if (!entry.mac) continue;
    await ipamDb.insertObservation({
      mac_address: entry.mac,
      interface_index: entry.ifIndex,
      interface_name: ifMap[entry.ifIndex] || null,
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

// Enriquecimiento incremental de hostnames vía reverse DNS (PTR).
// Solo toca IPs sin hostname (nunca resueltas o con reintento tras cooldown);
// no pisa nombres manuales. Se llama al final de cada descubrimiento.
async function enrichHostnames({ cap = 150, cooldownDays = 7 } = {}) {
  try {
    const ips = await ipamDb.getIpsMissingHostname({ cooldownDays, limit: cap });
    if (!ips.length) return 0;
    const map = await resolveHostnames(ips, { concurrency: 10, timeoutMs: 2000 });
    const results = [...map.entries()].map(([ip, hostname]) => ({ ip, hostname }));
    await ipamDb.recordHostnameResolution(results);
    const named = results.filter(r => r.hostname).length;
    console.log(`[IPAM-WORKER] Hostnames PTR: ${named}/${results.length} resueltos (pendientes consultados: ${ips.length}).`);
    return named;
  } catch (err) {
    console.error('[IPAM-WORKER] Error resolviendo hostnames PTR:', err.message);
    return 0;
  }
}

async function runDiscovery() {
  if (running) return;
  running = true;
  console.log('[IPAM-WORKER] Iniciando descubrimiento SNMP...');

  try {
    const devices = await ipamDb.listNetworkDevices();
    // Import FDB de switches antes de consultar routers para que el mapeo
    // ARP -> puerto físico esté disponible cuanto antes.
    const enabled = devices
      .filter(d => d.enabled)
      .sort((a, b) => {
        const aIsSwitch = a.device_type === 'switch' ? 0 : 1;
        const bIsSwitch = b.device_type === 'switch' ? 0 : 1;
        return aIsSwitch - bIsSwitch;
      });

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
    const purged = await ipamDb.pruneStaleArpAddresses();
    if (purged) console.log(`[IPAM-WORKER] Purga ARP: ${purged} IPs sin actividad >90d eliminadas.`);
    await enrichHostnames();
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

function buildDeviceConfig(device, credential) {
  return {
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
    trunk_ports: device.trunk_ports || [],
  };
}

async function queryArpFromDevice(deviceId) {
  const device = await ipamDb.getNetworkDeviceById(deviceId);
  if (!device) throw new Error('Dispositivo no encontrado');

  const credential = device.snmp_credential_id
    ? await ipamDb.getSnmpCredentialById(device.snmp_credential_id)
    : {};

  const deviceConfig = buildDeviceConfig(device, credential);
  return await genericArpOnly(deviceConfig);
}

async function queryFdbFromDevice(deviceId) {
  const device = await ipamDb.getNetworkDeviceById(deviceId);
  if (!device) throw new Error('Dispositivo no encontrado');

  const credential = device.snmp_credential_id
    ? await ipamDb.getSnmpCredentialById(device.snmp_credential_id)
    : {};

  const deviceConfig = buildDeviceConfig(device, credential);
  return await genericFdbOnly(deviceConfig);
}

async function crossReferenceArpFdb(routerId, switchIds) {
  const routerResult = await queryArpFromDevice(routerId);

  const switchResults = [];
  for (const switchId of switchIds) {
    try {
      const result = await queryFdbFromDevice(switchId);
      switchResults.push({ deviceId: switchId, ...result });
    } catch (err) {
      switchResults.push({ deviceId: switchId, identity: null, interfaces: [], macTable: [], errors: [err.message] });
    }
  }

  const arpEntries = routerResult.arp || [];
  const mapping = [];

  for (const arp of arpEntries) {
    if (!arp.ip || !arp.mac) continue;

    const entry = {
      ip: arp.ip,
      mac: arp.mac,
      routerIfIndex: arp.ifIndex,
      ports: [],
    };

    for (const sw of switchResults) {
      if (!sw.macTable) continue;

      const fdbMatch = sw.macTable.find(f => f.mac === arp.mac);
      if (fdbMatch) {
        const iface = (sw.interfaces || []).find(i => i.ifIndex === fdbMatch.ifIndex);
        entry.ports.push({
          deviceId: sw.deviceId,
          deviceName: sw.identity?.sysName || '',
          ifIndex: fdbMatch.ifIndex,
          portName: iface?.descr || '',
          portAlias: iface?.alias || '',
        });
      }
    }

    if (entry.ports.length > 0) mapping.push(entry);
  }

  return {
    router: routerResult.identity,
    switches: switchResults.map(s => ({ deviceId: s.deviceId, identity: s.identity, errors: s.errors })),
    arpCount: arpEntries.length,
    mappedCount: mapping.filter(m => m.ports.length > 0).length,
    mapping,
  };
}

async function queryInterfacesFromDevice(deviceId) {
  const device = await ipamDb.getNetworkDeviceById(deviceId);
  if (!device) throw new Error('Dispositivo no encontrado');
  const credential = device.snmp_credential_id
    ? await ipamDb.getSnmpCredentialById(device.snmp_credential_id)
    : {};
  const session = buildSession(buildDeviceConfig(device, credential));
  try {
    return await genericGetInterfacesPhysical(session);
  } finally {
    closeSession(session);
  }
}

module.exports = { runDiscovery, startIpamWorker, stopIpamWorker, pollDevice, testSnmp, queryArpFromDevice, queryFdbFromDevice, crossReferenceArpFdb, queryInterfacesFromDevice };

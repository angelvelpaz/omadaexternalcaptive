'use strict';

const { OIDS, buildSession, getTarget, walkTarget, closeSession } = require('../snmpClient');

function formatMac(buf) {
  if (!Buffer.isBuffer(buf) || buf.length !== 6) return null;
  return Array.from(buf).map(b => b.toString(16).padStart(2, '0')).join('-').toLowerCase();
}

function macFromOidSuffix(oid, baseOid) {
  const suffix = oid.replace(baseOid + '.', '');
  const parts = suffix.split('.').map(Number);
  if (parts.length !== 6) return null;
  return parts.map(b => b.toString(16).padStart(2, '0')).join('-').toLowerCase();
}

async function getIdentity(session) {
  const [sysName, sysDescr, sysUpTime] = await Promise.all([
    getTarget(session, OIDS.sysName).catch(() => ''),
    getTarget(session, OIDS.sysDescr).catch(() => ''),
    getTarget(session, OIDS.sysUpTime).catch(() => 0),
  ]);
  return {
    sysName: String(sysName || ''),
    sysDescr: String(sysDescr || ''),
    sysUptime: Number(sysUpTime || 0),
  };
}

async function getInterfaces(session) {
  const [indexes, descrs, aliases, adminStatuses, operStatuses, speeds, physAddrs, highSpeeds] = await Promise.all([
    walkTarget(session, OIDS.ifIndex).catch(() => []),
    walkTarget(session, OIDS.ifDescr).catch(() => []),
    walkTarget(session, OIDS.ifAlias).catch(() => []),
    walkTarget(session, OIDS.ifAdminStatus).catch(() => []),
    walkTarget(session, OIDS.ifOperStatus).catch(() => []),
    walkTarget(session, OIDS.ifSpeed).catch(() => []),
    walkTarget(session, OIDS.ifPhysAddress).catch(() => []),
    walkTarget(session, OIDS.ifHighSpeed).catch(() => []),
  ]);

  const map = {};
  for (const v of indexes) {
    const idx = v.oid.split('.').pop();
    map[idx] = { ifIndex: parseInt(idx) };
  }
  for (const v of descrs) { const idx = v.oid.split('.').pop(); if (map[idx]) map[idx].descr = String(v.value); }
  for (const v of aliases) { const idx = v.oid.split('.').pop(); if (map[idx]) map[idx].alias = String(v.value); }
  for (const v of adminStatuses) { const idx = v.oid.split('.').pop(); if (map[idx]) map[idx].adminStatus = Number(v.value); }
  for (const v of operStatuses) { const idx = v.oid.split('.').pop(); if (map[idx]) map[idx].operStatus = Number(v.value); }
  for (const v of speeds) { const idx = v.oid.split('.').pop(); if (map[idx]) map[idx].speed = Number(v.value); }
  for (const v of physAddrs) { const idx = v.oid.split('.').pop(); if (map[idx]) map[idx].physAddress = formatMac(v.value); }
  for (const v of highSpeeds) { const idx = v.oid.split('.').pop(); if (map[idx]) map[idx].highSpeed = Number(v.value); }

  return Object.values(map);
}

async function getArpTable(session) {
  const [macs, ips, types] = await Promise.all([
    walkTarget(session, OIDS.ipNetToMediaPhysAddress).catch(() => []),
    walkTarget(session, OIDS.ipNetToMediaNetAddress).catch(() => []),
    walkTarget(session, OIDS.ipNetToMediaType).catch(() => []),
  ]);

  const map = {};
  for (const v of ips) {
    const suffix = v.oid.replace(OIDS.ipNetToMediaNetAddress + '.', '');
    const parts = suffix.split('.');
    const ifIndex = parts[0];
    const ip = parts.slice(1).join('.');
    const key = `${ifIndex}-${ip}`;
    map[key] = { ip, ifIndex: parseInt(ifIndex) };
  }
  for (const v of macs) {
    const suffix = v.oid.replace(OIDS.ipNetToMediaPhysAddress + '.', '');
    const parts = suffix.split('.');
    const ifIndex = parts[0];
    const ip = parts.slice(1).join('.');
    const key = `${ifIndex}-${ip}`;
    if (map[key]) map[key].mac = formatMac(v.value);
  }
  for (const v of types) {
    const suffix = v.oid.replace(OIDS.ipNetToMediaType + '.', '');
    const parts = suffix.split('.');
    const ifIndex = parts[0];
    const ip = parts.slice(1).join('.');
    const key = `${ifIndex}-${ip}`;
    if (map[key]) map[key].type = Number(v.value);
  }

  return Object.values(map);
}

async function getMacTable(session, trunkIfIndexes = [], includeTrunks = false, selectedIfIndexes) {
  const [macs, ports, statuses] = await Promise.all([
    walkTarget(session, OIDS.dot1dTpFdbAddress).catch(() => []),
    walkTarget(session, OIDS.dot1dTpFdbPort).catch(() => []),
    walkTarget(session, OIDS.dot1dTpFdbStatus).catch(() => []),
  ]);

  const portToIf = {};
  try {
    const portIfs = await walkTarget(session, OIDS.dot1dBasePortIfIndex);
    for (const v of portIfs) {
      const portIdx = v.oid.split('.').pop();
      portToIf[portIdx] = Number(v.value);
    }
  } catch {}

  const map = {};
  for (const v of macs) {
    const suffix = v.oid.replace(OIDS.dot1dTpFdbAddress + '.', '');
    map[suffix] = { mac: formatMac(v.value), port: null, ifIndex: null, status: null };
  }
  for (const v of ports) {
    const suffix = v.oid.replace(OIDS.dot1dTpFdbPort + '.', '');
    if (map[suffix]) {
      const portIdx = String(Number(v.value));
      map[suffix].port = Number(v.value);
      map[suffix].ifIndex = portToIf[portIdx] || null;
    }
  }
  for (const v of statuses) {
    const suffix = v.oid.replace(OIDS.dot1dTpFdbStatus + '.', '');
    if (map[suffix]) map[suffix].status = Number(v.value);
  }

  return Object.values(map).filter(e => {
    if (!e.mac || e.status !== 3) return false;
    if (Array.isArray(selectedIfIndexes) && !selectedIfIndexes.includes(e.ifIndex)) return false;
    if (!includeTrunks && trunkIfIndexes.length > 0 && trunkIfIndexes.includes(e.ifIndex)) return false;
    return true;
  });
}

async function poll(deviceConfig) {
  const session = buildSession(deviceConfig);
  const trunkPorts = deviceConfig.trunk_ports || [];
  const pollRun = { identity: null, interfaces: [], arp: [], macTable: [], errors: [] };

  try {
    pollRun.identity = await getIdentity(session);
  } catch (err) {
    pollRun.errors.push(`identity: ${err.message}`);
  }

  try {
    pollRun.interfaces = await getInterfaces(session);
  } catch (err) {
    pollRun.errors.push(`interfaces: ${err.message}`);
  }

  try {
    pollRun.arp = await getArpTable(session);
  } catch (err) {
    pollRun.errors.push(`arp: ${err.message}`);
  }

  try {
    let trunkIfIndexes = [];
    if (trunkPorts.length > 0 && pollRun.interfaces.length > 0) {
      trunkIfIndexes = pollRun.interfaces
        .filter(i => trunkPorts.includes(i.descr) || trunkPorts.includes(String(i.ifIndex)))
        .map(i => i.ifIndex);
    }
    pollRun.macTable = await getMacTable(session, trunkIfIndexes, Boolean(deviceConfig.include_trunks), deviceConfig.selected_if_indexes);
  } catch (err) {
    pollRun.errors.push(`macTable: ${err.message}`);
  }

  closeSession(session);
  return pollRun;
}

async function pollArpOnly(deviceConfig) {
  const session = buildSession(deviceConfig);
  const result = { identity: null, arp: [], errors: [] };

  try {
    result.identity = await getIdentity(session);
  } catch (err) {
    result.errors.push('identity: ' + err.message);
  }

  try {
    result.arp = await getArpTable(session);
  } catch (err) {
    result.errors.push('arp: ' + err.message);
  }

  closeSession(session);
  return result;
}

async function pollFdbOnly(deviceConfig) {
  const session = buildSession(deviceConfig);
  const trunkPorts = deviceConfig.trunk_ports || [];
  const result = { identity: null, interfaces: [], macTable: [], errors: [] };

  try {
    result.identity = await getIdentity(session);
  } catch (err) {
    result.errors.push('identity: ' + err.message);
  }

  try {
    result.interfaces = await getInterfaces(session);
  } catch (err) {
    result.errors.push('interfaces: ' + err.message);
  }

  try {
    let trunkIfIndexes = [];
    if (trunkPorts.length > 0 && result.interfaces.length > 0) {
      trunkIfIndexes = result.interfaces
        .filter(i => trunkPorts.includes(i.descr) || trunkPorts.includes(String(i.ifIndex)))
        .map(i => i.ifIndex);
    }
    result.macTable = await getMacTable(session, trunkIfIndexes, Boolean(deviceConfig.include_trunks), deviceConfig.selected_if_indexes);
  } catch (err) {
    result.errors.push('macTable: ' + err.message);
  }

  closeSession(session);
  return result;
}

module.exports = { poll, pollArpOnly, pollFdbOnly, getIdentity, getInterfaces, getArpTable, getMacTable, formatMac };

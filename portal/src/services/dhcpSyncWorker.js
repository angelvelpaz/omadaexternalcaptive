'use strict';

const mikrotikSvc = require('./mikrotik');
const db = require('./database');

let intervalId = null;
let isRunning = false;

async function syncDhcpLeasesToMacBypass() {
  if (isRunning) return { synced: 0, error: null };
  isRunning = true;

  try {
    const mikrotikResult = await mikrotikSvc.listDhcpLeases();
    if (!mikrotikResult.ok) {
      console.error('[DHCP-SYNC] MikroTik error:', mikrotikResult.error);
      return { synced: 0, error: mikrotikResult.error };
    }

    const mikrotikLeaseMap = new Map();
    for (const lease of mikrotikResult.leases) {
      const mac = lease['mac-address'].toUpperCase().replace(/:/g, '-');
      mikrotikLeaseMap.set(mac, lease.address);
    }

    if (mikrotikLeaseMap.size === 0) {
      return { synced: 0, error: null };
    }

    const bypassEntries = await db.getMacBypassesByMacs([...mikrotikLeaseMap.keys()]);

    let updated = 0;
    for (const entry of bypassEntries) {
      const mikrotikIp = mikrotikLeaseMap.get(entry.mac_address);
      if (mikrotikIp && !entry.ip_address) {
        await db.updateMacBypassIp(entry.id, mikrotikIp);
        updated++;
        console.log(`[DHCP-SYNC] Auto-detected IP ${mikrotikIp} for MAC ${entry.mac_address}`);
      }
    }

    if (updated > 0) {
      console.log(`[DHCP-SYNC] Updated ${updated} MAC bypass entries with MikroTik DHCP IPs.`);
    }

    return { synced: updated, error: null };
  } catch (err) {
    console.error('[DHCP-SYNC] Error during sync:', err.message);
    return { synced: 0, error: err.message };
  } finally {
    isRunning = false;
  }
}

function startDhcpSyncWorker(intervalMs = 300000) {
  if (intervalId) return;
  console.log(`[DHCP-SYNC] Starting DHCP sync worker (interval: ${intervalMs}ms)...`);
  setTimeout(syncDhcpLeasesToMacBypass, 15000);
  intervalId = setInterval(syncDhcpLeasesToMacBypass, intervalMs);
}

function stopDhcpSyncWorker() {
  if (intervalId) {
    clearInterval(intervalId);
    intervalId = null;
  }
}

module.exports = { startDhcpSyncWorker, stopDhcpSyncWorker, syncDhcpLeasesToMacBypass };

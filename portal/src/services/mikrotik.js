'use strict';

const axios = require('axios');
const https = require('https');
const db = require('./database');

function buildClient(url, user, pass) {
  let cleanUrl = url.trim();
  if (!cleanUrl.startsWith('http://') && !cleanUrl.startsWith('https://')) {
    cleanUrl = 'https://' + cleanUrl;
  }
  return axios.create({
    baseURL: cleanUrl,
    httpsAgent: new https.Agent({ rejectUnauthorized: false }),
    timeout: 10000,
    auth: { username: user, password: pass }
  });
}

async function getMikrotikConfig() {
  const cfg = await db.getControllerConfig('mikrotik');
  return {
    url: cfg?.url || process.env.MIKROTIK_URL || '',
    user: cfg?.user || process.env.MIKROTIK_USER || '',
    pass: cfg?.pass || process.env.MIKROTIK_PASS || ''
  };
}

/**
 * Lista las DHCP static leases en MikroTik
 */
async function listDhcpLeases() {
  const cfg = await getMikrotikConfig();
  if (!cfg.url || !cfg.user || !cfg.pass) {
    return { ok: false, error: 'Configuración MikroTik incompleta.' };
  }
  const client = buildClient(cfg.url, cfg.user, cfg.pass);
  try {
    const res = await client.get('/rest/ip/dhcp-server/lease', {
      params: { '.proplist': '.id,address,mac-address,server,dynamic,comment', 'dynamic': 'false' }
    });
    return { ok: true, leases: res.data || [] };
  } catch (err) {
    return { ok: false, error: `Error al listar leases: ${err.message}` };
  }
}

/**
 * Obtiene los nombres de los servidores DHCP configurados en MikroTik
 */
async function getDhcpServerNames() {
  const cfg = await getMikrotikConfig();
  if (!cfg.url || !cfg.user || !cfg.pass) return [];
  const client = buildClient(cfg.url, cfg.user, cfg.pass);
  try {
    const res = await client.get('/rest/ip/dhcp-server', {
      params: { '.proplist': 'name' }
    });
    return (res.data || []).map(s => s.name).filter(Boolean);
  } catch {
    return [];
  }
}

/**
 * Crea o actualiza una DHCP static lease en MikroTik
 */
async function setDhcpLease({ macAddress, ipAddress, server, comment }) {
  const cfg = await getMikrotikConfig();
  if (!cfg.url || !cfg.user || !cfg.pass) {
    return { ok: false, error: 'Configuración MikroTik incompleta.' };
  }
  const client = buildClient(cfg.url, cfg.user, cfg.pass);
  const normalizedMac = macAddress.toUpperCase().replace(/-/g, ':');

  try {
    // Buscar lease existente para esta MAC (where filter de MikroTik no funciona, buscar por query param)
    const existing = await client.get('/rest/ip/dhcp-server/lease', {
      params: { '.proplist': '.id,address,mac-address,server', 'mac-address': normalizedMac }
    });
    const leases = (existing.data || []).filter(l =>
      l['mac-address']?.toUpperCase() === normalizedMac
    );
    
    // Detectar server DHCP: usar el del lease existente, o el primer servidor disponible
    let dhcpServer = server || 'all';
    if (leases.length > 0 && leases[0].server) {
      dhcpServer = leases[0].server;
    } else if (dhcpServer === 'all') {
      const servers = await getDhcpServerNames();
      if (servers.length > 0) dhcpServer = servers[0];
    }

    // 'dynamic' es solo lectura en MikroTik, no enviarlo en PUT/POST
    const payload = {
      'address': ipAddress,
      'mac-address': normalizedMac,
      'server': dhcpServer,
      'comment': comment || ''
    };

    if (leases.length > 0) {
      // Actualizar lease existente
      await client.put(`/rest/ip/dhcp-server/lease/${leases[0]['.id']}`, payload);
      return { ok: true, action: 'updated', leaseId: leases[0]['.id'] };
    } else {
      // Crear nuevo lease
      const res = await client.post('/rest/ip/dhcp-server/lease', payload);
      return { ok: true, action: 'created', leaseId: res.data?.['.id'] };
    }
  } catch (err) {
    return { ok: false, error: `Error al gestionar DHCP lease: ${err.message}` };
  }
}

/**
 * Elimina una DHCP static lease de MikroTik
 */
async function removeDhcpLease(macAddress) {
  const cfg = await getMikrotikConfig();
  if (!cfg.url || !cfg.user || !cfg.pass) {
    return { ok: false, error: 'Configuración MikroTik incompleta.' };
  }
  const client = buildClient(cfg.url, cfg.user, cfg.pass);
  const normalizedMac = macAddress.toUpperCase().replace(/-/g, ':');

  try {
    const existing = await client.get('/rest/ip/dhcp-server/lease', {
      params: { '.proplist': '.id,mac-address', 'mac-address': normalizedMac }
    });
    const leases = (existing.data || []).filter(l =>
      l['mac-address']?.toUpperCase() === normalizedMac
    );

    if (leases.length === 0) {
      return { ok: true, message: 'No se encontró lease para esta MAC.' };
    }

    for (const lease of leases) {
      await client.delete(`/rest/ip/dhcp-server/lease/${lease['.id']}`);
    }
    return { ok: true, deleted: leases.length };
  } catch (err) {
    return { ok: false, error: `Error al eliminar DHCP lease: ${err.message}` };
  }
}

/**
 * Verifica si existe un DHCP static lease para una MAC en MikroTik
 */
async function checkDhcpLease(macAddress) {
  const cfg = await getMikrotikConfig();
  if (!cfg.url || !cfg.user || !cfg.pass) {
    return { exists: false, error: 'Configuración MikroTik incompleta.' };
  }
  const client = buildClient(cfg.url, cfg.user, cfg.pass);
  const normalizedMac = macAddress.toUpperCase().replace(/-/g, ':');

  try {
    const res = await client.get('/rest/ip/dhcp-server/lease', {
      params: { '.proplist': '.id,address,mac-address', 'mac-address': normalizedMac }
    });
    const leases = (res.data || []).filter(l =>
      l['mac-address']?.toUpperCase() === normalizedMac
    );
    return { exists: leases.length > 0, lease: leases[0] || null };
  } catch (err) {
    return { exists: false, error: `Error al verificar DHCP lease: ${err.message}` };
  }
}

module.exports = {
  getMikrotikConfig,
  listDhcpLeases,
  setDhcpLease,
  removeDhcpLease,
  checkDhcpLease
};

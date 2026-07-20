'use strict';

const axios = require('axios');
const https = require('https');

const db = require('./database');

const SESSION_MINUTES = parseInt(process.env.SESSION_DURATION_MINUTES || '480');

let cachedToken = null;
let tokenExpiresAt = 0;

async function getOmadaConfig() {
  try {
    const dbConfig = await db.getControllerConfig('omada');
    const url = dbConfig?.url || process.env.OMADA_CONTROLLER_URL || '';
    const clientId = dbConfig?.clientId || process.env.OMADA_CLIENT_ID || '';
    const secret = dbConfig?.secret || process.env.OMADA_CLIENT_SECRET || '';
    const siteId = dbConfig?.siteId || process.env.OMADA_SITE_ID || '';
    return { url, clientId, secret, siteId };
  } catch (err) {
    return {
      url: process.env.OMADA_CONTROLLER_URL || '',
      clientId: process.env.OMADA_CLIENT_ID || '',
      secret: process.env.OMADA_CLIENT_SECRET || '',
      siteId: process.env.OMADA_SITE_ID || ''
    };
  }
}

function buildClient(baseUrl) {
  const client = axios.create({
    baseURL: baseUrl,
    httpsAgent: new https.Agent({ rejectUnauthorized: false }),
    timeout: 10000,
  });

  client.interceptors.response.use(
    (response) => {
      const body = response.data;
      if (body && (body.errorCode === 10003 || body.errorCode === 10004)) {
        console.warn(`[OMADA] Token inválido o expirado detectado (${body.errorCode}). Limpiando caché de token.`);
        cachedToken = null;
        tokenExpiresAt = 0;
      }
      return response;
    },
    (error) => {
      return Promise.reject(error);
    }
  );

  return client;
}

/**
 * Obtiene un access token del controlador Omada vía OAuth2 client credentials.
 * @returns {{ accessToken: string, omadacId: string }}
 */
async function getToken(client, cfg) {
  const now = Date.now();
  if (cachedToken && tokenExpiresAt > now + 300000) {
    return cachedToken;
  }

  const omadaConfig = cfg || await getOmadaConfig();

  const resp = await client.post(
    '/openapi/authorize/token?grant_type=client_credentials',
    {
      omadacId:      omadaConfig.siteId,
      client_id:     omadaConfig.clientId,
      client_secret: omadaConfig.secret,
    },
    {
      headers: { 'Content-Type': 'application/json' },
    }
  );

  const body = resp.data;
  if (body?.errorCode !== 0) {
    throw new Error(`Omada auth error ${body?.errorCode}: ${body?.msg || JSON.stringify(body)}`);
  }

  const result = body.result ?? body.data;
  if (!result?.accessToken) {
    throw new Error('No se obtuvo access token de Omada: ' + JSON.stringify(body));
  }

  const expiresIn = result.expiresIn ? parseInt(result.expiresIn) : 3600;

  cachedToken = {
    accessToken: result.accessToken,
    omadacId:    omadaConfig.siteId,
  };
  tokenExpiresAt = now + (expiresIn * 1000);

  return cachedToken;
}

/**
 * Autoriza un cliente en el portal externo de Omada usando la OpenAPI v1.
 *
 * @param {Object} params
 * @param {string} params.clientMac - MAC del cliente
 * @param {string} params.siteId    - ID del sitio
 * @param {number} params.timeLimit - Límite de tiempo en minutos
 */
async function authorizeClient({ clientMac, siteId, timeLimit }) {
  const cfg = await getOmadaConfig();
  if (!cfg.url) {
    throw new Error('OMADA_CONTROLLER_URL no configurado');
  }

  const client = buildClient(cfg.url);
  const { accessToken, omadacId } = await getToken(client, cfg);

  const targetSiteId = siteId || cfg.siteId || 'default';
  const minutes = timeLimit || SESSION_MINUTES;

  console.log(`[OMADA] Token obtenido, autorizando MAC: ${clientMac} en sitio: ${targetSiteId}`);

  const resp = await client.post(
    `/openapi/v1/${omadacId}/sites/${targetSiteId}/hotspot/clients/${clientMac.toUpperCase()}/auth`,
    {
      timeLimit: parseInt(minutes),
    },
    {
      headers: {
        Authorization: `AccessToken=${accessToken}`,
        'Content-Type': 'application/json',
      },
    }
  );

  if (resp.data?.errorCode !== 0) {
    throw new Error('Autorización Omada fallida: ' + JSON.stringify(resp.data));
  }

  console.log(`[OMADA] Cliente ${clientMac} autorizado por ${minutes} minutos`);
  return true;
}

/**
 * Desautoriza un cliente de Omada en todos los sitios disponibles.
 *
 * @param {Object} params
 * @param {string} params.clientMac - MAC del cliente
 */
async function unauthorizeClient({ clientMac }) {
  const cfg = await getOmadaConfig();
  if (!cfg.url) {
    console.warn('[OMADA] Controlador Omada no configurado.');
    return false;
  }

  const client = buildClient(cfg.url);
  const { accessToken, omadacId } = await getToken(client, cfg);

  // 1. Obtener lista de sitios
  const sitesResp = await client.get(`/openapi/v1/${omadacId}/sites?page=1&pageSize=100`, {
    headers: { Authorization: `AccessToken=${accessToken}` },
  });

  const sitesBody = sitesResp.data;
  if (sitesBody?.errorCode !== 0) {
    throw new Error('No se pudo obtener la lista de sitios de Omada: ' + JSON.stringify(sitesBody));
  }

  const list = sitesBody.result?.data ?? sitesBody.data?.data ?? [];
  const siteIds = Array.isArray(list) ? list.map(s => s.siteId || s.id) : ['default'];

  console.log(`[OMADA] Desautorizando MAC: ${clientMac} en sitios:`, siteIds);

  let successCount = 0;
  let errors = [];

  // 2. Intentar desautorizar (Hotspot) y desconectar (AP) en cada sitio
  for (const siteId of siteIds) {
    let actionOk = false;

    // 2.1 Desautorizar en el portal Hotspot
    try {
      const resp1 = await client.post(
        `/openapi/v1/${omadacId}/sites/${siteId}/hotspot/clients/${clientMac.toUpperCase()}/unauth`,
        {},
        {
          headers: {
            Authorization: `AccessToken=${accessToken}`,
            'Content-Type': 'application/json',
          },
        }
      );
      if (resp1.data?.errorCode === 0) {
        actionOk = true;
      } else {
        errors.push(`Sitio ${siteId} (unauth): ${resp1.data?.msg}`);
      }
    } catch (err) {
      errors.push(`Sitio ${siteId} (unauth): ${err.response?.data?.msg || err.message}`);
    }

    // 2.2 Desconectar físicamente del AP (reconnect)
    try {
      const resp2 = await client.post(
        `/openapi/v1/${omadacId}/sites/${siteId}/clients/${clientMac.toUpperCase()}/reconnect`,
        {},
        {
          headers: {
            Authorization: `AccessToken=${accessToken}`,
            'Content-Type': 'application/json',
          },
        }
      );
      if (resp2.data?.errorCode === 0) {
        actionOk = true;
      } else {
        errors.push(`Sitio ${siteId} (reconnect): ${resp2.data?.msg}`);
      }
    } catch (err) {
      errors.push(`Sitio ${siteId} (reconnect): ${err.response?.data?.msg || err.message}`);
    }

    if (actionOk) {
      successCount++;
      console.log(`[OMADA] Cliente ${clientMac} desautorizado/desconectado en sitio ${siteId}`);
    }
  }

  if (successCount === 0) {
    console.log(`[OMADA] No se encontró sesión activa para desconectar al cliente ${clientMac} (Detalles: ${errors.join('; ')})`);
  } else {
    console.log(`[OMADA] Cliente ${clientMac} desautorizado/desconectado en ${successCount} sitio(s)`);
  }

  return true;
}

/**
 * Bloquea un cliente de Omada en todos los sitios disponibles.
 *
 * @param {Object} params
 * @param {string} params.clientMac - MAC del cliente
 */
async function blockClient({ clientMac }) {
  const cfg = await getOmadaConfig();
  if (!cfg.url) {
    throw new Error('OMADA_CONTROLLER_URL no configurado');
  }

  const client = buildClient(cfg.url);
  const { accessToken, omadacId } = await getToken(client, cfg);

  const sitesResp = await client.get(`/openapi/v1/${omadacId}/sites?page=1&pageSize=100`, {
    headers: { Authorization: `AccessToken=${accessToken}` },
  });

  const sitesBody = sitesResp.data;
  if (sitesBody?.errorCode !== 0) {
    throw new Error('No se pudo obtener la lista de sitios de Omada: ' + JSON.stringify(sitesBody));
  }

  const list = sitesBody.result?.data ?? sitesBody.data?.data ?? [];
  const siteIds = Array.isArray(list) ? list.map(s => s.siteId || s.id) : ['default'];

  console.log(`[OMADA] Bloqueando MAC: ${clientMac} en sitios:`, siteIds);

  let successCount = 0;
  let errors = [];

  for (const siteId of siteIds) {
    try {
      const resp = await client.post(
        `/openapi/v1/${omadacId}/sites/${siteId}/clients/${clientMac.toUpperCase()}/block`,
        {},
        {
          headers: {
            Authorization: `AccessToken=${accessToken}`,
            'Content-Type': 'application/json',
          },
        }
      );
      if (resp.data?.errorCode === 0) {
        successCount++;
        console.log(`[OMADA] Cliente ${clientMac} bloqueado en sitio ${siteId}`);
      } else {
        errors.push(`Sitio ${siteId}: ${resp.data?.msg}`);
      }
    } catch (err) {
      errors.push(`Sitio ${siteId}: ${err.response?.data?.msg || err.message}`);
    }
  }

  if (successCount === 0) {
    console.log(`[OMADA] No se pudo bloquear al cliente ${clientMac} en ningún sitio (Detalles: ${errors.join('; ')})`);
  }

  return true;
}

/**
 * Desbloquea un cliente de Omada en todos los sitios disponibles.
 *
 * @param {Object} params
 * @param {string} params.clientMac - MAC del cliente
 */
async function unblockClient({ clientMac }) {
  const cfg = await getOmadaConfig();
  if (!cfg.url) {
    throw new Error('OMADA_CONTROLLER_URL no configurado');
  }

  const client = buildClient(cfg.url);
  const { accessToken, omadacId } = await getToken(client, cfg);

  const sitesResp = await client.get(`/openapi/v1/${omadacId}/sites?page=1&pageSize=100`, {
    headers: { Authorization: `AccessToken=${accessToken}` },
  });

  const sitesBody = sitesResp.data;
  if (sitesBody?.errorCode !== 0) {
    throw new Error('No se pudo obtener la lista de sitios de Omada: ' + JSON.stringify(sitesBody));
  }

  const list = sitesBody.result?.data ?? sitesBody.data?.data ?? [];
  const siteIds = Array.isArray(list) ? list.map(s => s.siteId || s.id) : ['default'];

  console.log(`[OMADA] Desbloqueando MAC: ${clientMac} en sitios:`, siteIds);

  let successCount = 0;
  let errors = [];

  for (const siteId of siteIds) {
    try {
      const resp = await client.post(
        `/openapi/v1/${omadacId}/sites/${siteId}/clients/${clientMac.toUpperCase()}/unblock`,
        {},
        {
          headers: {
            Authorization: `AccessToken=${accessToken}`,
            'Content-Type': 'application/json',
          },
        }
      );
      if (resp.data?.errorCode === 0) {
        successCount++;
        console.log(`[OMADA] Cliente ${clientMac} desbloqueado en sitio ${siteId}`);
      } else {
        errors.push(`Sitio ${siteId}: ${resp.data?.msg}`);
      }
    } catch (err) {
      errors.push(`Sitio ${siteId}: ${err.response?.data?.msg || err.message}`);
    }
  }

  if (successCount === 0) {
    console.log(`[OMADA] No se pudo desbloquear al cliente ${clientMac} en ningún sitio (Detalles: ${errors.join('; ')})`);
  }

  return true;
}

/**
 * Desconecta (kick) un cliente de Omada para forzar su reasociación.
 *
 * @param {Object} params
 * @param {string} params.clientMac - MAC del cliente
 * @param {string} params.siteId    - ID del sitio
 */
async function kickClient({ clientMac, siteId }) {
  const cfg = await getOmadaConfig();
  if (!cfg.url) {
    throw new Error('OMADA_CONTROLLER_URL no configurado');
  }

  const client = buildClient(cfg.url);
  const { accessToken, omadacId } = await getToken(client, cfg);

  const targetSiteId = siteId || 'default';
  const formattedMac = clientMac.toUpperCase().replace(/:/g, '-');

  console.log(`[OMADA] Enviando comando de desconexión (kick) para MAC: ${formattedMac} en sitio: ${targetSiteId}`);

  try {
    const resp = await client.delete(
      `/openapi/v1/${omadacId}/sites/${targetSiteId}/clients/${formattedMac}`,
      {
        headers: {
          Authorization: `AccessToken=${accessToken}`,
          'Content-Type': 'application/json',
        },
      }
    );

    if (resp.data?.errorCode !== 0) {
      console.warn(`[OMADA] No se pudo desconectar el cliente (errorCode: ${resp.data?.errorCode}): ${JSON.stringify(resp.data)}`);
      return false;
    }

    console.log(`[OMADA] Cliente ${formattedMac} desconectado (kick) exitosamente.`);
    return true;
  } catch (err) {
    console.error(`[OMADA] Error al desconectar cliente ${formattedMac}:`, err.message);
    return false;
  }
}

/**
 * Obtiene la lista de clientes activos en todos los sitios de Omada.
 */
async function getActiveClients() {
  const cfg = await getOmadaConfig();
  if (!cfg.url) return [];

  try {
    const client = buildClient(cfg.url);
    const { accessToken, omadacId } = await getToken(client, cfg);

    // 1. Obtener lista de sitios
    const sitesResp = await client.get(`/openapi/v1/${omadacId}/sites?page=1&pageSize=100`, {
      headers: { Authorization: `AccessToken=${accessToken}` },
    });

    const sitesBody = sitesResp.data;
    if (sitesBody?.errorCode !== 0 || !sitesBody?.result?.data) {
      return [];
    }

    const sites = sitesBody.result.data;
    const allClients = [];

    for (const site of sites) {
      const siteId = site.siteId || site.id;
      try {
        const clientsResp = await client.get(
          `/openapi/v1/${omadacId}/sites/${siteId}/clients?page=1&pageSize=1000`,
          {
            headers: { Authorization: `AccessToken=${accessToken}` },
          }
        );

        const body = clientsResp.data;
        if (body?.errorCode === 0 && body?.result?.data) {
          for (const c of body.result.data) {
            allClients.push({
              macAddress: c.mac,
              ipAddress:  c.ip,
              uptime:     c.uptime || 0,
              upload:     c.up || c.trafficUp || 0,
              download:   c.down || c.trafficDown || 0,
              ssid:       c.ssid || null,
              apMac:      c.apMac || null,
              apName:     c.apName || null,
              name:       c.name || c.hostName || null,
              signalLevel: c.signalLevel || c.rssi || null,
              siteId:     siteId,
              siteName:   site.name || siteId,
              vendor:     'omada'
            });
          }
        }
      } catch (siteErr) {
        console.error(`[OMADA] Error al obtener clientes de sitio ${siteId}:`, siteErr.message);
      }
    }

    return allClients;
  } catch (err) {
    console.error('[OMADA] Error al obtener clientes activos:', err.message);
    return [];
  }
}

async function getDeviceLiveStatus(macAddress) {
  const normMac = String(macAddress).toUpperCase().replace(/[:\-]/g, '');
  const activeClients = await getActiveClients();
  const found = activeClients.find(c => String(c.macAddress).toUpperCase().replace(/[:\-]/g, '') === normMac);

  if (!found) {
    return {
      online: false,
      mac: macAddress,
      message: 'Dispositivo fuera de línea o no conectado en Omada.'
    };
  }

  return {
    online: true,
    mac: found.macAddress,
    ip: found.ipAddress || '—',
    name: found.name || '—',
    siteId: found.siteId,
    siteName: found.siteName || 'Omada Site',
    apMac: found.apMac || '—',
    apName: found.apName || 'AP Omada',
    ssid: found.ssid || '—',
    signalLevel: found.signalLevel,
    uptime: found.uptime,
    upload: found.upload,
    download: found.download,
    vendor: 'omada'
  };
}

module.exports = { authorizeClient, unauthorizeClient, blockClient, unblockClient, kickClient, getActiveClients, getDeviceLiveStatus };

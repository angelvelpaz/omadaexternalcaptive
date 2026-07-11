'use strict';

const axios = require('axios');
const https = require('https');

const CONTROLLER_URL = process.env.UNIFI_CONTROLLER_URL || '';
const UNIFI_USER     = process.env.UNIFI_USER || '';
const UNIFI_PASS     = process.env.UNIFI_PASS || '';
const UNIFI_SITE     = process.env.UNIFI_SITE || 'default';
const VERIFY_SSL     = process.env.UNIFI_VERIFY_SSL !== 'false';
const SESSION_MINUTES = parseInt(process.env.SESSION_DURATION_MINUTES || '480');

// Instancia axios con soporte de cookies
function buildClient() {
  const httpsAgent = new https.Agent({ rejectUnauthorized: VERIFY_SSL });
  return axios.create({
    baseURL: CONTROLLER_URL,
    httpsAgent,
    withCredentials: true,
    timeout: 10000,
  });
}

/**
 * Autoriza al cliente en el controlador UniFi.
 * Flujo: login al controlador → POST authorize-guest con el MAC del cliente.
 *
 * @param {string} clientMac  - MAC del cliente (viene del param ?id= de UniFi)
 * @param {string} apMac      - MAC del AP (param ?ap=)
 */
async function authorizeGuest(clientMac, apMac) {
  if (!CONTROLLER_URL) {
    throw new Error('UNIFI_CONTROLLER_URL no configurado');
  }

  const client = buildClient();
  let cookieHeader = '';

  // 1. Login al controlador
  const loginResp = await client.post('/api/login', {
    username: UNIFI_USER,
    password: UNIFI_PASS,
  });

  // Extraer cookie de sesión
  const setCookie = loginResp.headers['set-cookie'];
  if (setCookie) {
    cookieHeader = setCookie.map(c => c.split(';')[0]).join('; ');
  }

  if (loginResp.data?.meta?.rc !== 'ok') {
    throw new Error('Login al controlador UniFi fallido');
  }

  console.log(`[UNIFI] Login exitoso, autorizando MAC: ${clientMac}`);

  // 2. Autorizar cliente como guest
  const authResp = await client.post(
    `/api/s/${UNIFI_SITE}/cmd/stamgr`,
    {
      cmd: 'authorize-guest',
      mac: clientMac.toLowerCase(),
      minutes: SESSION_MINUTES,
    },
    {
      headers: { Cookie: cookieHeader },
    }
  );

  if (authResp.data?.meta?.rc !== 'ok') {
    throw new Error('Autorización de guest en UniFi fallida: ' + JSON.stringify(authResp.data));
  }

  console.log(`[UNIFI] Cliente ${clientMac} autorizado por ${SESSION_MINUTES} minutos`);
  return true;
}

/**
 * Desautoriza/desconecta al cliente en el controlador UniFi.
 *
 * @param {string} clientMac  - MAC del cliente
 */
async function unauthorizeGuest(clientMac) {
  if (!CONTROLLER_URL) {
    throw new Error('UNIFI_CONTROLLER_URL no configurado');
  }

  const client = buildClient();
  let cookieHeader = '';

  // 1. Login al controlador
  const loginResp = await client.post('/api/login', {
    username: UNIFI_USER,
    password: UNIFI_PASS,
  });

  // Extraer cookie de sesión
  const setCookie = loginResp.headers['set-cookie'];
  if (setCookie) {
    cookieHeader = setCookie.map(c => c.split(';')[0]).join('; ');
  }

  if (loginResp.data?.meta?.rc !== 'ok') {
    throw new Error('Login al controlador UniFi fallido');
  }

  console.log(`[UNIFI] Login exitoso, desautorizando MAC: ${clientMac}`);

  // 2. Desautorizar cliente
  const authResp = await client.post(
    `/api/s/${UNIFI_SITE}/cmd/stamgr`,
    {
      cmd: 'unauthorize-guest',
      mac: clientMac.toLowerCase(),
    },
    {
      headers: { Cookie: cookieHeader },
    }
  );

  if (authResp.data?.meta?.rc !== 'ok') {
    throw new Error('Desautorización de guest en UniFi fallida: ' + JSON.stringify(authResp.data));
  }

  console.log(`[UNIFI] Cliente ${clientMac} desautorizado exitosamente`);
  return true;
}

/**
 * Obtiene la lista de clientes activos en UniFi.
 */
async function getActiveClients() {
  if (!CONTROLLER_URL) return [];

  try {
    const client = buildClient();

    // 1. Login al controlador
    const loginResp = await client.post('/api/login', {
      username: UNIFI_USER,
      password: UNIFI_PASS,
    });

    let cookieHeader = '';
    const setCookie = loginResp.headers['set-cookie'];
    if (setCookie) {
      cookieHeader = setCookie.map(c => c.split(';')[0]).join('; ');
    }

    if (loginResp.data?.meta?.rc !== 'ok') {
      return [];
    }

    // 2. Obtener clientes activos (sta)
    const resp = await client.get(`/api/s/${UNIFI_SITE}/stat/sta`, {
      headers: { Cookie: cookieHeader },
    });

    if (resp.data?.meta?.rc !== 'ok' || !resp.data?.data) {
      return [];
    }

    return resp.data.data.map(c => ({
      macAddress: c.mac,
      ipAddress:  c.ip,
      uptime:     c.uptime || 0,
      upload:     c.tx_bytes || 0,
      download:   c.rx_bytes || 0,
      vendor:     'unifi'
    }));
  } catch (err) {
    console.error('[UNIFI] Error al obtener clientes activos:', err.message);
    return [];
  }
}

module.exports = { authorizeGuest, unauthorizeGuest, getActiveClients };

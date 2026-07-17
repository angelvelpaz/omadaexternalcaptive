'use strict';

const axios  = require('axios');
const https  = require('https');
const dgram  = require('dgram');
const radius = require('radius');

// ─── Helpers ──────────────────────────────────────────────────────────────────

function httpsAgent(verify) {
  return new https.Agent({ rejectUnauthorized: verify === 'true' || verify === true });
}

function masked(str) {
  if (!str) return null;
  return str.slice(0, 3) + '***' + str.slice(-2);
}

// ─── FreeRADIUS (Status-Server) ───────────────────────────────────────────────

/**
 * Prueba FreeRADIUS enviando un Status-Server UDP.
 * @param {Object} cfg  { host, port, secret, timeout }
 */
function testFreeRadius(cfg = {}) {
  const host    = cfg.host    || 'freeradius';
  const port    = parseInt(cfg.port    || '1812');
  const secret  = cfg.secret  || '';
  const timeout = parseInt(cfg.timeout || '4000');

  return new Promise((resolve) => {
    const socket = dgram.createSocket('udp4');
    let done = false;
    const t = setTimeout(() => {
      if (done) return; done = true;
      socket.close();
      resolve({ ok: false, message: 'Timeout: FreeRADIUS no respondió.' });
    }, timeout);

    socket.on('error', (err) => {
      if (done) return; done = true;
      clearTimeout(t); socket.close();
      resolve({ ok: false, message: err.message });
    });

    socket.on('message', (msg) => {
      if (done) return; done = true;
      clearTimeout(t); socket.close();
      try {
        const resp = radius.decode({ packet: msg, secret });
        resolve({ ok: true, message: `FreeRADIUS respondió: ${resp.code}` });
      } catch (e) {
        resolve({ ok: false, message: 'Respuesta inválida: ' + e.message });
      }
    });

    try {
      const pkt = radius.encode({
        code: 'Status-Server',
        secret,
        attributes: [['NAS-IP-Address', '127.0.0.1']],
      });
      socket.send(pkt, 0, pkt.length, port, host);
    } catch (e) {
      done = true; clearTimeout(t); socket.close();
      resolve({ ok: false, message: 'Error construyendo paquete: ' + e.message });
    }
  });
}

// ─── UniFi ────────────────────────────────────────────────────────────────────

/**
 * @param {Object} cfg  { url, user, pass, site, verifySSL }
 */
async function testUnifi(cfg = {}) {
  const url  = cfg.url;
  const user = cfg.user;
  const pass = cfg.pass;
  const site = cfg.site || 'default';

  if (!url || !user || !pass) {
    return { ok: false, message: 'URL, usuario y contraseña son requeridos.' };
  }

  const client = axios.create({
    baseURL: url,
    httpsAgent: httpsAgent(cfg.verifySSL),
    timeout: 8000,
  });

  try {
    const loginResp = await client.post('/api/login', { username: user, password: pass });
    if (loginResp.data?.meta?.rc !== 'ok') {
      return { ok: false, message: 'Login fallido: ' + JSON.stringify(loginResp.data?.meta) };
    }

    const cookie = (loginResp.headers['set-cookie'] || []).map(c => c.split(';')[0]).join('; ');
    const siteResp = await client.get(`/api/s/${site}/stat/sysinfo`, {
      headers: { Cookie: cookie },
    });

    const info = siteResp.data?.data?.[0];
    return {
      ok: true,
      message: `Conectado. Versión: ${info?.version || 'desconocida'}, uptime: ${info?.uptime ? Math.round(info.uptime / 3600) + 'h' : '—'}`,
      details: { version: info?.version, uptime: info?.uptime, site },
    };
  } catch (err) {
    const status = err.response?.status;
    const msg    = err.response?.data?.meta?.msg || err.message;
    return { ok: false, message: `${status ? 'HTTP ' + status + ': ' : ''}${msg}` };
  }
}

// ─── Omada ────────────────────────────────────────────────────────────────────

/**
 * @param {Object} cfg  { url, clientId, secret, siteId }
 */
async function testOmada(cfg = {}) {
  const url      = cfg.url;
  const clientId = cfg.clientId;
  const secret   = cfg.secret;

  if (!url || !clientId || !secret) {
    return { ok: false, message: 'URL, Client ID y Client Secret son requeridos.' };
  }

  const client = axios.create({
    baseURL: url,
    httpsAgent: httpsAgent(false),
    timeout: 8000,
  });

  try {
    const tokenResp = await client.post(
      '/openapi/authorize/token?grant_type=client_credentials',
      {
        omadacId:      cfg.siteId,
        client_id:     clientId,
        client_secret: secret,
      },
      {
        headers: { 'Content-Type': 'application/json' },
      }
    );

    const body = tokenResp.data;

    // Omada devuelve HTTP 200 con errorCode != 0 para credenciales inválidas
    if (body?.errorCode !== 0) {
      return {
        ok: false,
        message: `Error ${body?.errorCode}: ${body?.msg || JSON.stringify(body)}`,
      };
    }

    // Omada 5+ usa body.result; versiones antiguas usaban body.data
    const result   = body.result ?? body.data;
    const token    = result?.accessToken;
    const omadacId = cfg.siteId;

    if (!token) {
      return { ok: false, message: 'No se obtuvo access_token: ' + JSON.stringify(body) };
    }

    try {
      const sitesResp = await client.get(`/openapi/v1/${omadacId}/sites`, {
        headers: { Authorization: `AccessToken=${token}` },
      });
      const sitesBody = sitesResp.data;
      if (sitesBody?.errorCode === 0) {
        // Omada 5: lista en result.data; fallback a data.data
        const list  = sitesBody.result?.data ?? sitesBody.data?.data ?? [];
        const count = Array.isArray(list) ? list.length : (sitesBody.result?.totalRows ?? 0);
        return {
          ok: true,
          message: `Conectado. ${count} sitio${count !== 1 ? 's' : ''} disponible${count !== 1 ? 's' : ''}.`,
          details: { omadacId, siteCount: count },
        };
      }
      return { ok: true, message: 'Token obtenido correctamente.', details: { omadacId } };
    } catch {
      return { ok: true, message: 'Token obtenido correctamente.', details: { omadacId } };
    }
  } catch (err) {
    const body   = err.response?.data;
    const status = err.response?.status;
    // Omada puede devolver el mensaje de error en body.msg
    const msg = body?.msg || body?.message || err.message;
    return { ok: false, message: `${status ? 'HTTP ' + status + ': ' : ''}${msg}` };
  }
}

/**
 * Prueba la conectividad con la API REST de MikroTik RouterOS v7+
 */
async function testMikrotik(cfg = {}) {
  const url = cfg.url;
  const user = cfg.user;
  const pass = cfg.pass;

  if (!url || !user || !pass) {
    return { ok: false, message: 'URL del router, usuario y contraseña de API son requeridos.' };
  }

  let cleanUrl = url.trim();
  if (!cleanUrl.startsWith('http://') && !cleanUrl.startsWith('https://')) {
    cleanUrl = 'https://' + cleanUrl;
  }

  const client = axios.create({
    baseURL: cleanUrl,
    httpsAgent: httpsAgent(false),
    timeout: 5000,
    auth: {
      username: user,
      password: pass
    }
  });

  try {
    const res = await client.get('/rest/system/identity');
    if (res.data && res.data.name !== undefined) {
      return { ok: true, message: `Conectado con éxito a MikroTik RouterOS. Identidad: ${res.data.name}` };
    }
    return { ok: true, message: 'Conectado a la API REST de MikroTik RouterOS.' };
  } catch (err) {
    const status = err.response?.status;
    const details = err.response?.data?.message || err.message;
    return { ok: false, message: `Error al conectar con MikroTik: ${status ? 'HTTP ' + status + ' - ' : ''}${details}` };
  }
}

module.exports = { testFreeRadius, testUnifi, testOmada, testMikrotik, masked };

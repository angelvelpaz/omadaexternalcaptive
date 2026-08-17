'use strict';

const axios = require('axios');

function agentConfig() {
  return {
    baseURL: (process.env.WINBIND_AGENT_URL || 'http://freeradius:8765').replace(/\/+$/, ''),
    token: process.env.WINBIND_MANAGER_TOKEN || '',
  };
}

class WinbindManagerError extends Error {
  constructor(message, status = 503) {
    super(message);
    this.name = 'WinbindManagerError';
    this.status = status;
  }
}

async function request(method, path, data) {
  const { baseURL, token } = agentConfig();
  if (!token) {
    throw new WinbindManagerError('El agente Winbind no está configurado en el portal.');
  }

  try {
    const response = await axios.request({
      method,
      url: `${baseURL}${path}`,
      data,
      timeout: 10000,
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json',
      },
      validateStatus: () => true,
    });
    if (response.status >= 400) {
      throw new WinbindManagerError(
        response.data && response.data.error
          ? String(response.data.error)
          : (response.data && response.data.message
            ? String(response.data.message)
            : 'El agente Winbind rechazó la operación.'),
        response.status === 401 ? 502 : response.status
      );
    }
    return response.data;
  } catch (error) {
    if (error instanceof WinbindManagerError) throw error;
    throw new WinbindManagerError('No se pudo contactar al agente Winbind dentro del contenedor.');
  }
}

function getStatus() {
  return request('GET', '/v1/status');
}

function testCredentials({ username, password }) {
  return request('POST', '/v1/ntlm-auth', { username, password });
}

function configureDomain(config) {
  return request('POST', '/v1/domain/configure', config);
}

function joinDomain(credentials) {
  return request('POST', '/v1/domain/join', credentials);
}

module.exports = {
  getStatus,
  testCredentials,
  configureDomain,
  joinDomain,
  WinbindManagerError,
};

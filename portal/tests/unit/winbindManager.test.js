'use strict';

jest.mock('axios', () => ({ request: jest.fn() }));

const axios = require('axios');
const manager = require('../../src/services/winbindManager');

describe('services/winbindManager', () => {
  beforeEach(() => {
    process.env.WINBIND_MANAGER_TOKEN = 'unit-test-token';
    process.env.WINBIND_AGENT_URL = 'http://freeradius:8765';
    jest.clearAllMocks();
  });

  test('consulta el agente con token y timeout', async () => {
    axios.request.mockResolvedValueOnce({ status: 200, data: { available: true } });
    await expect(manager.getStatus()).resolves.toEqual({ available: true });
    expect(axios.request).toHaveBeenCalledWith(expect.objectContaining({
      method: 'GET',
      url: 'http://freeradius:8765/v1/status',
      timeout: 10000,
      headers: expect.objectContaining({ Authorization: 'Bearer unit-test-token' }),
    }));
  });

  test('no expone errores de transporte ni credenciales', async () => {
    axios.request.mockRejectedValueOnce(new Error('transport error temporary-secret'));
    await expect(manager.testCredentials({ username: 'user', password: 'temporary-secret' }))
      .rejects.toThrow('No se pudo contactar al agente Winbind');
  });
});

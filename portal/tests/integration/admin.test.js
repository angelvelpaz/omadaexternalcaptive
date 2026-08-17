'use strict';

const request = require('supertest');
jest.mock('../../src/services/winbindManager', () => ({
  getStatus: jest.fn(),
  testCredentials: jest.fn(),
  configureDomain: jest.fn(),
  joinDomain: jest.fn(),
}));
const app = require('../../src/app');
const db = require('../../src/services/database');
const winbindManager = require('../../src/services/winbindManager');

describe('Integration: Admin Endpoints', () => {
  beforeAll(async () => {
    await db.connect();
  });

  test('GET /admin/api/stats sin token retorna 401', async () => {
    const res = await request(app)
      .get('/admin/api/stats')
      .expect('Content-Type', /json/)
      .expect(401);

    expect(res.body.error).toContain('No autorizado');
  });

  test('GET /admin/api/stats con ADMIN_SECRET retorna 200', async () => {
    const adminSecret = process.env.ADMIN_SECRET || 'admin_secret_cambia_esto';
    const res = await request(app)
      .get('/admin/api/stats')
      .set('Authorization', `Bearer ${adminSecret}`)
      .expect('Content-Type', /json/)
      .expect(200);

    expect(res.body).toHaveProperty('total_users');
    expect(res.body).toHaveProperty('active_users');
  });

  test('GET /admin/api/users con token válido retorna lista paginada', async () => {
    const adminSecret = process.env.ADMIN_SECRET || 'admin_secret_cambia_esto';
    const res = await request(app)
      .get('/admin/api/users?limit=10&offset=0')
      .set('Authorization', `Bearer ${adminSecret}`)
      .expect('Content-Type', /json/)
      .expect(200);

    expect(Array.isArray(res.body.users)).toBe(true);
    expect(typeof res.body.total).toBe('number');
  });

  test('un operador no puede modificar la configuración LDAP', async () => {
    const username = 'operator-rbac-test';
    try {
      await db.deleteAdmin(username);
    } catch (e) {}

    await db.createAdmin({
      username,
      password: 'operator-password',
      nombres: 'Operator Test',
      rol: 'operador'
    });
    const session = await db.createAdminSession(username);

    try {
      await request(app)
        .put('/admin/api/controllers/ldap')
        .set('Authorization', `Bearer ${session.token}`)
        .send({ ldapAllowedGroup: 'CN=Wifi' })
        .expect(403);
    } finally {
      await db.deleteAdmin(username);
    }
  });

  test('Winbind devuelve estado al superadministrador', async () => {
    winbindManager.getStatus.mockResolvedValueOnce({
      available: true,
      configured: true,
      config: { realm: 'EMPRESA.LOCAL', netbios_domain: 'EMPRESA', dc: 'dc01.empresa.local' },
      join: { ok: true, message: 'OK' },
      trust: { ok: true, message: 'OK' },
      domain_info: { realm: 'EMPRESA.LOCAL' },
    });
    const adminSecret = process.env.ADMIN_SECRET || 'admin_secret_cambia_esto';
    const res = await request(app)
      .get('/admin/api/winbind/status')
      .set('Authorization', `Bearer ${adminSecret}`)
      .expect(200);

    expect(res.body.config.realm).toBe('EMPRESA.LOCAL');
    expect(winbindManager.getStatus).toHaveBeenCalled();
  });

  test('Winbind exige superadministrador y no devuelve la contraseña', async () => {
    const username = 'winbind-operator-test';
    try { await db.deleteAdmin(username); } catch (e) {}
    await db.createAdmin({ username, password: 'operator-password', nombres: 'Winbind Operator', rol: 'operador' });
    const session = await db.createAdminSession(username);
    try {
      await request(app)
        .post('/admin/api/winbind/test')
        .set('Authorization', `Bearer ${session.token}`)
        .send({ username: 'ad-user', password: 'temporary-secret' })
        .expect(403);
    } finally {
      await db.deleteAdmin(username);
    }
  });

  test('Winbind reenvía solo el resultado seguro de la prueba', async () => {
    winbindManager.testCredentials.mockResolvedValueOnce({
      ok: true,
      authenticated: true,
      message: 'Credenciales aceptadas.',
    });
    const adminSecret = process.env.ADMIN_SECRET || 'admin_secret_cambia_esto';
    const res = await request(app)
      .post('/admin/api/winbind/test')
      .set('Authorization', `Bearer ${adminSecret}`)
      .send({ username: 'ad-user', password: 'temporary-secret' })
      .expect(200);

    expect(res.body).toEqual({ ok: true, authenticated: true, message: 'Credenciales aceptadas.' });
    expect(JSON.stringify(res.body)).not.toContain('temporary-secret');
    expect(winbindManager.testCredentials).toHaveBeenCalledWith({ username: 'ad-user', password: 'temporary-secret' });
  });
});

'use strict';

const request = require('supertest');
const app = require('../../src/app');

describe('Integration: Admin Endpoints', () => {
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
});

'use strict';

const request = require('supertest');
const app = require('../../src/app');

describe('Integration: Auth Endpoints', () => {
  test('GET /auth/config retorna configuración del portal', async () => {
    const res = await request(app)
      .get('/auth/config')
      .expect('Content-Type', /json/)
      .expect(200);

    expect(res.body).toHaveProperty('name');
    expect(res.body).toHaveProperty('logo');
    expect(res.body).toHaveProperty('sessionMinutes');
  });

  test('POST /auth/check con cédula inválida retorna valid=false', async () => {
    const res = await request(app)
      .post('/auth/check')
      .send({ cedula: '1234567890' })
      .expect('Content-Type', /json/)
      .expect(200);

    expect(res.body.valid).toBe(false);
    expect(res.body.exists).toBe(false);
    expect(res.body.error).toContain('no válido');
  });

  test('POST /auth/check con cédula de seed retorna valid=true, exists=true', async () => {
    const res = await request(app)
      .post('/auth/check')
      .send({ cedula: '1713175071' })
      .expect('Content-Type', /json/)
      .expect(200);

    expect(res.body.valid).toBe(true);
    expect(res.body.exists).toBe(true);
  });

  test('POST /auth/check con cédula inexistente retorna valid=true, exists=false', async () => {
    const res = await request(app)
      .post('/auth/check')
      .send({ cedula: '0101010101' })
      .expect('Content-Type', /json/)
      .expect(200);

    expect(res.body.valid).toBe(true);
    expect(res.body.exists).toBe(false);
  });

  test('POST /auth/login sin body retorna 400', async () => {
    const res = await request(app)
      .post('/auth/login')
      .send({})
      .expect(400);

    expect(res.body.error).toBeDefined();
  });

  test('POST /auth/register sin body retorna 400', async () => {
    const res = await request(app)
      .post('/auth/register')
      .send({})
      .expect(400);

    expect(res.body.error).toBeDefined();
  });

  test('GET /health retorna status ok', async () => {
    const res = await request(app)
      .get('/health')
      .expect('Content-Type', /json/)
      .expect(200);

    expect(res.body.status).toBe('ok');
    expect(res.body.checks).toHaveProperty('postgres');
    expect(res.body.checks).toHaveProperty('freeradius');
    expect(res.body.timestamp).toBeDefined();
  });
});

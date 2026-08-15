'use strict';

const request = require('supertest');
const app = require('../../src/app');
const db = require('../../src/services/database');

describe('Integration: Auth Endpoints', () => {
  beforeAll(async () => {
    // Asegurar conexión a BD
    await db.connect();
    // Eliminar test user si ya existe para evitar colisión de claves únicas
    try {
      await db.deleteUser('1713175071', true);
    } catch (e) {}
    // Crear el usuario de prueba para el test de verificación
    await db.createUser({
      cedula: '1713175071',
      nombres: 'Test',
      apellidos: 'User',
      email: 'test@user.com',
      terminosAceptados: 'Aceptado por Test',
      tipo_usuario: 'externo'
    });
  });

  afterAll(async () => {
    try {
      await db.deleteUser('1713175071', true);
    } catch (e) {}
  });

  test('GET /auth/config retorna configuración del portal', async () => {
    const res = await request(app)
      .get('/auth/config')
      .expect('Content-Type', /json/)
      .expect(200);

    expect(res.body).toHaveProperty('name');
    expect(res.body).toHaveProperty('logo');
    expect(res.body).toHaveProperty('sessionMinutes');
  });

  test('GET /auth/config no activa LDAP del portal por defecto', async () => {
    await db.saveSsidConfig('test-ldap-disabled', 'ldap', {});

    try {
      const res = await request(app)
        .get('/auth/config?ssid=test-ldap-disabled')
        .expect('Content-Type', /json/)
        .expect(200);

      expect(res.body.authType).toBe('cedula');
      expect(res.body.ldapEnabled).toBe(false);
    } finally {
      await db.deleteSsidConfig('test-ldap-disabled');
    }
  });

  test('POST /auth/ldap se bloquea si LDAP del portal está desactivado', async () => {
    const res = await request(app)
      .post('/auth/ldap')
      .send({ username: 'usuario', password: 'password', mac: 'AA-BB-CC-DD-EE-FF' })
      .expect(403);

    expect(res.body.error).toContain('LDAP del portal cautivo está desactivada');
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
      .send({ cedula: '1713175089' })
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

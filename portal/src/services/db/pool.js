'use strict';

const { Pool } = require('pg');

let pool;

function getPool() {
  return pool;
}

async function connect() {
  pool = new Pool({
    host:     process.env.POSTGRES_HOST || 'postgres',
    port:     parseInt(process.env.POSTGRES_PORT || '5432'),
    database: process.env.POSTGRES_DB,
    user:     process.env.POSTGRES_USER,
    password: process.env.POSTGRES_PASSWORD,
    max: parseInt(process.env.DB_POOL_MAX || '40'),
    idleTimeoutMillis: parseInt(process.env.DB_POOL_IDLE_TIMEOUT || '10000'),
    connectionTimeoutMillis: parseInt(process.env.DB_POOL_CONN_TIMEOUT || '3000'),
  });

  // Verificar conexión e inicializar esquema adicional
  const client = await pool.connect();
  await client.query('SELECT 1');
  await client.query(`
    CREATE TABLE IF NOT EXISTS controller_config (
      vendor      TEXT PRIMARY KEY,
      config      JSONB NOT NULL DEFAULT '{}',
      updated_at  TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  await client.query(`
    CREATE TABLE IF NOT EXISTS ssid_config (
      id          SERIAL PRIMARY KEY,
      ssid_name   VARCHAR(64) UNIQUE NOT NULL,
      auth_type   VARCHAR(20) NOT NULL,
      config      JSONB NOT NULL DEFAULT '{}',
      updated_at  TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  // Crear tablas para administración multiusuario y auditoría
  await client.query(`
    CREATE TABLE IF NOT EXISTS administradores (
      id             SERIAL PRIMARY KEY,
      username       VARCHAR(50) UNIQUE NOT NULL,
      password_hash  VARCHAR(255) NOT NULL,
      nombres        VARCHAR(100) NOT NULL,
      activo         BOOLEAN DEFAULT TRUE,
      rol            VARCHAR(30) DEFAULT 'operador',
      created_at     TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  await client.query(`
    CREATE TABLE IF NOT EXISTS admin_sessions (
      token       VARCHAR(255) PRIMARY KEY,
      username    VARCHAR(50) NOT NULL REFERENCES administradores(username) ON DELETE CASCADE,
      created_at  TIMESTAMPTZ DEFAULT NOW(),
      expires_at  TIMESTAMPTZ NOT NULL
    )
  `);

  await client.query(`
    CREATE TABLE IF NOT EXISTS auditoria_admin (
      id          SERIAL PRIMARY KEY,
      username    VARCHAR(50) NOT NULL,
      ip_address  VARCHAR(45) NOT NULL,
      accion      VARCHAR(100) NOT NULL,
      detalles    TEXT NOT NULL,
      created_at  TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  // Crear tablas para módulo de Hoteles y Restaurantes
  await client.query(`
    CREATE TABLE IF NOT EXISTS restaurant_pins (
      id                  SERIAL PRIMARY KEY,
      pin                 VARCHAR(10) UNIQUE NOT NULL,
      duracion_minutos    INTEGER DEFAULT 60,
      limite_dispositivos INTEGER DEFAULT 2,
      dispositivos_usados INTEGER DEFAULT 0,
      activo              BOOLEAN DEFAULT TRUE,
      creado_el           TIMESTAMPTZ DEFAULT NOW(),
      expira_el           TIMESTAMPTZ
    )
  `);

  await client.query(`
    CREATE TABLE IF NOT EXISTS hotel_guests (
      id                SERIAL PRIMARY KEY,
      habitacion        VARCHAR(10) NOT NULL,
      apellido          VARCHAR(100) NOT NULL,
      nombre            VARCHAR(100),
      fecha_checkin     TIMESTAMPTZ DEFAULT NOW(),
      fecha_checkout    TIMESTAMPTZ NOT NULL,
      activo            BOOLEAN DEFAULT TRUE,
      perfil_velocidad  VARCHAR(50) DEFAULT 'ldap',
      UNIQUE(habitacion, apellido)
    )
  `);

  // Insertar administrador inicial por defecto si la tabla está vacía
  const adminCheck = await client.query('SELECT 1 FROM administradores LIMIT 1');
  if (adminCheck.rowCount === 0) {
    const adminSecret = process.env.ADMIN_SECRET || 'admin_secret_cambia_esto';
    const crypto = require('crypto');
    const salt = crypto.randomBytes(16).toString('hex');
    const hash = crypto.pbkdf2Sync(adminSecret, salt, 1000, 64, 'sha512').toString('hex');
    const dbHash = `${salt}:${hash}`;
    
    await client.query(
      `INSERT INTO administradores (username, password_hash, nombres, activo, rol)
       VALUES ('admin', $1, 'Administrador Principal', TRUE, 'superadministrador')`,
      [dbHash]
    );
    console.log('[DB] Administrador principal ("admin") creado por defecto.');
  }

  // Asegurar que las columnas terminos_aceptados y tipo_usuario existan en usuarios_portal
  try {
    await client.query(`
      ALTER TABLE usuarios_portal 
      ADD COLUMN IF NOT EXISTS terminos_aceptados TEXT;
    `);
    await client.query(`
      ALTER TABLE usuarios_portal 
      ADD COLUMN IF NOT EXISTS tipo_usuario VARCHAR(20) DEFAULT 'externo';
    `);
    await client.query(`
      ALTER TABLE administradores 
      ADD COLUMN IF NOT EXISTS rol VARCHAR(30) DEFAULT 'operador';
    `);
    await client.query(`
      UPDATE administradores 
      SET rol = 'superadministrador' 
      WHERE username = 'admin' AND (rol = 'operador' OR rol IS NULL);
    `);
  } catch (colErr) {
    console.error('[DB] Advertencia al validar columnas adicionales:', colErr.message);
  }

  // Inicializar grupos RADIUS por defecto si no existen
  try {
    await client.query(`
      INSERT INTO radgroupreply (groupname, attribute, op, value)
      SELECT groupname, attribute, op, value FROM (
        VALUES
          ('captive-portal-users-institucional', 'Session-Timeout', ':=', '43200'),
          ('captive-portal-users-institucional', 'Idle-Timeout', ':=', '3600'),
          ('captive-portal-users-institucional', 'WISPr-Bandwidth-Max-Up', ':=', '10240000'),
          ('captive-portal-users-institucional', 'WISPr-Bandwidth-Max-Down', ':=', '20480000'),
          ('captive-portal-users-externo', 'Session-Timeout', ':=', '7200'),
          ('captive-portal-users-externo', 'Idle-Timeout', ':=', '900'),
          ('captive-portal-users-externo', 'WISPr-Bandwidth-Max-Up', ':=', '3145728'),
          ('captive-portal-users-externo', 'WISPr-Bandwidth-Max-Down', ':=', '5242880')
      ) AS t(groupname, attribute, op, value)
      WHERE NOT EXISTS (
        SELECT 1 FROM radgroupreply r 
        WHERE r.groupname = t.groupname AND r.attribute = t.attribute
      );
    `);
  } catch (grpErr) {
    console.error('[DB] Advertencia al sembrar grupos RADIUS:', grpErr.message);
  }

  client.release();
  console.log('[DB] Conexión a PostgreSQL establecida');
}

module.exports = { connect, getPool };

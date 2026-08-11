'use strict';

/**
 * Configuración inicial para tests de integración.
 * NOTA: Los tests de integración requieren un servidor PostgreSQL real.
 * Se asume que las variables de entorno apuntan a la DB de test o se usan mocks.
 */

beforeAll(async () => {
  // Asegurar que dotenv cargue variables de test si existen
  require('dotenv').config();
});

afterAll(async () => {
  // Cerrar pools de conexión si están abiertos
  try {
    const db = require('../src/services/database');
    const pool = db.getPool && db.getPool();
    if (pool && pool.end) {
      await pool.end();
    }
  } catch (e) {
    // Ignorar si no hay pool activo
  }
});

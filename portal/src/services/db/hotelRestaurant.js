'use strict';

const { getPool } = require('./pool');

// ── Métodos para Hoteles y Restaurantes ──────────────────────────────────────

async function getHotelGuest(habitacion, apellido) {
  const result = await getPool().query(
    'SELECT * FROM hotel_guests WHERE LOWER(habitacion) = LOWER($1) AND LOWER(apellido) = LOWER($2) AND activo = TRUE LIMIT 1',
    [habitacion.trim(), apellido.trim()]
  );
  return result.rows[0];
}

async function createHotelGuest({ habitacion, apellido, nombre, fecha_checkin, fecha_checkout, perfil_velocidad }) {
  const checkinVal = fecha_checkin ? new Date(fecha_checkin) : new Date();
  const checkoutVal = new Date(fecha_checkout);
  const result = await getPool().query(
    `INSERT INTO hotel_guests (habitacion, apellido, nombre, fecha_checkin, fecha_checkout, perfil_velocidad, activo)
     VALUES ($1, $2, $3, $4, $5, $6, TRUE)
     ON CONFLICT (habitacion, apellido) 
     DO UPDATE SET nombre = EXCLUDED.nombre, fecha_checkin = EXCLUDED.fecha_checkin, fecha_checkout = EXCLUDED.fecha_checkout, perfil_velocidad = EXCLUDED.perfil_velocidad, activo = TRUE
     RETURNING *`,
    [habitacion.trim(), apellido.trim(), nombre ? nombre.trim() : null, checkinVal, checkoutVal, perfil_velocidad || 'ldap']
  );
  return result.rows[0];
}

async function listHotelGuests() {
  const result = await getPool().query('SELECT * FROM hotel_guests ORDER BY fecha_checkout DESC');
  return result.rows;
}

async function deleteHotelGuest(id) {
  const result = await getPool().query('DELETE FROM hotel_guests WHERE id = $1 RETURNING *', [id]);
  return result.rows[0];
}

async function getRestaurantPin(pin) {
  const result = await getPool().query(
    'SELECT * FROM restaurant_pins WHERE pin = $1 AND activo = TRUE LIMIT 1',
    [pin.trim()]
  );
  return result.rows[0];
}

async function createRestaurantPin({ pin, duracion_minutos, limite_dispositivos, expira_el }) {
  const limitDisp = limite_dispositivos ? parseInt(limite_dispositivos) : 2;
  const durMin = duracion_minutos ? parseInt(duracion_minutos) : 60;
  const expVal = expira_el ? new Date(expira_el) : null;
  const result = await getPool().query(
    `INSERT INTO restaurant_pins (pin, duracion_minutos, limite_dispositivos, expira_el, activo)
     VALUES ($1, $2, $3, $4, TRUE)
     ON CONFLICT (pin) DO UPDATE SET duracion_minutos = EXCLUDED.duracion_minutos, limite_dispositivos = EXCLUDED.limite_dispositivos, expira_el = EXCLUDED.expira_el, activo = TRUE
     RETURNING *`,
    [pin.trim(), durMin, limitDisp, expVal]
  );
  return result.rows[0];
}

async function incrementPinUsage(pin) {
  const result = await getPool().query(
    `UPDATE restaurant_pins 
     SET dispositivos_usados = dispositivos_usados + 1,
         activo = CASE WHEN (dispositivos_usados + 1) >= limite_dispositivos THEN FALSE ELSE TRUE END
     WHERE pin = $1 RETURNING *`,
    [pin.trim()]
  );
  return result.rows[0];
}

async function listRestaurantPins() {
  const result = await getPool().query('SELECT * FROM restaurant_pins ORDER BY creado_el DESC');
  return result.rows;
}

async function deleteRestaurantPin(id) {
  const result = await getPool().query('DELETE FROM restaurant_pins WHERE id = $1 RETURNING *', [id]);
  return result.rows[0];
}

module.exports = {
  getHotelGuest,
  createHotelGuest,
  listHotelGuests,
  deleteHotelGuest,
  getRestaurantPin,
  createRestaurantPin,
  incrementPinUsage,
  listRestaurantPins,
  deleteRestaurantPin,
};

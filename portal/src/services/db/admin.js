'use strict';

const crypto = require('crypto');
const { getPool } = require('./pool');

// ─── Gestión de administradores y auditoría ────────────────────────────────────

function hashAdminPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.pbkdf2Sync(password, salt, 1000, 64, 'sha512').toString('hex');
  return `${salt}:${hash}`;
}

function verifyAdminPassword(password, storedHash) {
  const [salt, hash] = storedHash.split(':');
  const checkHash = crypto.pbkdf2Sync(password, salt, 1000, 64, 'sha512').toString('hex');
  return hash === checkHash;
}

async function verifyAdminLogin(username, password) {
  const res = await getPool().query(
    'SELECT username, password_hash, nombres, activo, rol FROM administradores WHERE username = $1 LIMIT 1',
    [username.trim().toLowerCase()]
  );
  const admin = res.rows[0];
  if (!admin || !admin.activo) return null;
  if (verifyAdminPassword(password, admin.password_hash)) {
    return { username: admin.username, nombres: admin.nombres, rol: admin.rol || 'operador' };
  }
  return null;
}

async function createAdminSession(username) {
  const token = crypto.randomBytes(32).toString('hex');
  const expiresAt = new Date(Date.now() + 2 * 60 * 60 * 1000); // 2 horas
  await getPool().query(
    `INSERT INTO admin_sessions (token, username, expires_at)
     VALUES ($1, $2, $3)`,
    [token, username, expiresAt]
  );
  return { token, expiresAt };
}

async function getAdminBySessionToken(token) {
  const res = await getPool().query(
    `SELECT s.username, a.rol, a.nombres
     FROM admin_sessions s
     JOIN administradores a ON a.username = s.username
     WHERE s.token = $1 AND s.expires_at > NOW() LIMIT 1`,
    [token]
  );
  const session = res.rows[0];
  if (!session) return null;
  
  // Renovar expiración por 2 horas más
  const newExpiresAt = new Date(Date.now() + 2 * 60 * 60 * 1000);
  await getPool().query(
    'UPDATE admin_sessions SET expires_at = $1 WHERE token = $2',
    [newExpiresAt, token]
  );
  
  return { username: session.username, rol: session.rol || 'operador', nombres: session.nombres };
}

async function deleteAdminSession(token) {
  await getPool().query('DELETE FROM admin_sessions WHERE token = $1', [token]);
}

async function listAdmins() {
  const res = await getPool().query(
    'SELECT id, username, nombres, activo, rol, created_at FROM administradores ORDER BY username ASC'
  );
  return res.rows;
}

async function createAdmin({ username, password, nombres, rol = 'operador' }) {
  const validRoles = ['operador', 'administrador', 'superadministrador'];
  const rolFinal = validRoles.includes(rol) ? rol : 'operador';
  const hash = hashAdminPassword(password);
  const res = await getPool().query(
    `INSERT INTO administradores (username, password_hash, nombres, activo, rol)
     VALUES ($1, $2, $3, TRUE, $4)
     RETURNING id, username, nombres, rol`,
    [username.trim().toLowerCase(), hash, nombres.trim(), rolFinal]
  );
  return res.rows[0];
}

async function updateAdminRol(username, rol) {
  const validRoles = ['operador', 'administrador', 'superadministrador'];
  if (!validRoles.includes(rol)) throw new Error('Rol no válido.');
  if (username.trim().toLowerCase() === 'admin') throw new Error('No se puede cambiar el rol del administrador principal.');
  await getPool().query(
    'UPDATE administradores SET rol = $1 WHERE username = $2',
    [rol, username.trim().toLowerCase()]
  );
}

async function updateAdminStatus(username, activo) {
  if (username.trim().toLowerCase() === 'admin') {
    throw new Error('No se puede desactivar al administrador principal "admin".');
  }
  await getPool().query(
    'UPDATE administradores SET activo = $1 WHERE username = $2',
    [activo, username.trim().toLowerCase()]
  );
}

async function updateAdminPassword(username, newPassword) {
  const hash = hashAdminPassword(newPassword);
  await getPool().query(
    'UPDATE administradores SET password_hash = $1 WHERE username = $2',
    [hash, username.trim().toLowerCase()]
  );
}

async function deleteAdmin(username) {
  const userLower = username.trim().toLowerCase();
  if (userLower === 'admin') {
    throw new Error('No se puede eliminar al administrador principal "admin".');
  }
  await getPool().query('DELETE FROM administradores WHERE username = $1', [userLower]);
}

module.exports = {
  verifyAdminLogin,
  createAdminSession,
  getAdminBySessionToken,
  deleteAdminSession,
  listAdmins,
  createAdmin,
  updateAdminRol,
  updateAdminStatus,
  updateAdminPassword,
  deleteAdmin,
};

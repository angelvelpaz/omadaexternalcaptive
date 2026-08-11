'use strict';

/**
 * Extrae la IP real del cliente desde los headers de proxy.
 */
function getClientIp(req) {
  let clientIp = req.headers['x-real-ip'] || req.headers['x-forwarded-for'] || req.ip || req.connection?.remoteAddress || '';
  if (clientIp.startsWith('::ffff:')) {
    clientIp = clientIp.substring(7);
  }
  return clientIp;
}

/**
 * Valida una imagen base64 subida: tamaño máximo y tipos MIME permitidos.
 * @returns {{valid: boolean, ext?: string, buffer?: Buffer, error?: string}}
 */
function validateBase64Image(base64String, { maxBytes = 2 * 1024 * 1024, allowedTypes = ['png', 'jpg', 'jpeg', 'svg', 'svg+xml'] } = {}) {
  if (!base64String || !base64String.startsWith('data:image/')) {
    return { valid: false, error: 'Formato de imagen inválido.' };
  }
  const matches = base64String.match(/^data:image\/([a-zA-Z0-9+.-]+);base64,(.+)$/);
  if (!matches || matches.length !== 3) {
    return { valid: false, error: 'Formato base64 inválido.' };
  }
  let ext = matches[1];
  if (ext === 'svg+xml') ext = 'svg';
  if (ext === 'jpeg') ext = 'jpg';
  if (!allowedTypes.includes(matches[1]) && !allowedTypes.includes(ext)) {
    return { valid: false, error: `Tipo de imagen no permitido: ${matches[1]}.` };
  }
  const buffer = Buffer.from(matches[2], 'base64');
  if (buffer.length > maxBytes) {
    return { valid: false, error: `Imagen demasiado grande (máx ${maxBytes / 1024 / 1024}MB).` };
  }
  return { valid: true, ext, buffer };
}

module.exports = { getClientIp, validateBase64Image };

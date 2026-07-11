'use strict';

const dgram = require('dgram');
const radius = require('radius');

const RADIUS_HOST    = process.env.RADIUS_HOST    || 'freeradius';
const RADIUS_PORT    = parseInt(process.env.RADIUS_PORT || '1812');
const RADIUS_SECRET  = process.env.RADIUS_SECRET  || '';
const RADIUS_TIMEOUT = parseInt(process.env.RADIUS_TIMEOUT || '5000');

/**
 * Autentica un usuario contra FreeRADIUS usando PAP (Access-Request).
 *
 * Crea un socket UDP por solicitud para evitar problemas de concurrencia.
 * El shared secret debe coincidir exactamente con clients.conf en FreeRADIUS.
 *
 * @param {string} username - Número de cédula
 * @param {string} password - radius_password almacenado en DB
 * @returns {Promise<boolean>} true si Access-Accept, false si Access-Reject
 */
function authenticate(username, password) {
  return new Promise((resolve, reject) => {
    const socket = dgram.createSocket('udp4');
    let settled = false;
    let timer;

    function finish(fn, value) {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.close();
      fn(value);
    }

    socket.on('error', (err) => {
      console.error('[RADIUS] Socket error:', err.message);
      finish(reject, new Error('Error de comunicación con RADIUS: ' + err.message));
    });

    socket.on('message', (msg) => {
      try {
        const response = radius.decode({ packet: msg, secret: RADIUS_SECRET });
        console.log(`[RADIUS] Respuesta para ${username}: ${response.code}`);

        if (response.code === 'Access-Accept') {
          finish(resolve, true);
        } else if (response.code === 'Access-Reject') {
          finish(resolve, false);
        } else {
          finish(reject, new Error('Respuesta RADIUS inesperada: ' + response.code));
        }
      } catch (err) {
        finish(reject, new Error('Error decodificando respuesta RADIUS: ' + err.message));
      }
    });

    // Construir paquete Access-Request
    const packet = radius.encode({
      code: 'Access-Request',
      secret: RADIUS_SECRET,
      attributes: [
        ['User-Name', username],
        ['User-Password', password],
        ['NAS-IP-Address', '127.0.0.1'],
        ['NAS-Port', 0],
        ['Service-Type', 'Login-User'],
      ],
    });

    timer = setTimeout(() => {
      console.error(`[RADIUS] Timeout para usuario ${username}`);
      finish(reject, new Error('Timeout: FreeRADIUS no respondió en ' + RADIUS_TIMEOUT + 'ms'));
    }, RADIUS_TIMEOUT);

    socket.send(packet, 0, packet.length, RADIUS_PORT, RADIUS_HOST, (err) => {
      if (err) {
        finish(reject, new Error('Error enviando paquete RADIUS: ' + err.message));
      }
    });
  });
}

module.exports = { authenticate };

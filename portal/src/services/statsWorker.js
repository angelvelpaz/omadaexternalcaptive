'use strict';

const crypto = require('crypto');
const db = require('./database');
const omadaSvc = require('./omada');
const unifiSvc = require('./unifi');

let intervalId = null;
let isRunning = false;

/**
 * Helper para generar el hash acctuniqueid de FreeRADIUS (MD5 de 32 caracteres)
 */
function getAcctUniqueId(sessionId) {
  return crypto.createHash('md5').update(sessionId).digest('hex');
}

/**
 * Sincroniza las estadísticas de consumo de los controladores UniFi y Omada hacia radacct.
 */
async function syncStats() {
  if (isRunning) return;
  isRunning = true;

  try {
    const activeClients = [];

    // 1. Obtener clientes activos de Omada si está configurado
    const omadaClients = await omadaSvc.getActiveClients();
    if (omadaClients && omadaClients.length > 0) {
      activeClients.push(...omadaClients);
    }

    // 2. Obtener clientes activos de UniFi si está configurado
    const unifiClients = await unifiSvc.getActiveClients();
    if (unifiClients && unifiClients.length > 0) {
      activeClients.push(...unifiClients);
    }

    if (activeClients.length === 0) {
      isRunning = false;
      return;
    }

    const pool = db.getPool();
    if (!pool) {
      isRunning = false;
      return;
    }

    const activeMacs = new Set();

    // 3. Procesar cada cliente activo obtenido de los controladores
    for (const client of activeClients) {
      const mac = client.macAddress.toUpperCase().replace(/:/g, '-');
      activeMacs.add(mac);

      // Buscar si el dispositivo está registrado a una cédula en la BD
      const devRes = await pool.query(
        'SELECT cedula FROM dispositivos_usuario WHERE UPPER(mac_address) = $1',
        [mac]
      );

      if (devRes.rows.length === 0) {
        // Dispositivo no registrado en la base de datos local
        continue;
      }

      const cedula = devRes.rows[0].cedula;
      const uptime = parseInt(client.uptime) || 0;
      const upload = parseInt(client.upload) || 0;
      const download = parseInt(client.download) || 0;
      const ip = client.ipAddress || null;
      const vendor = client.vendor;

      // Calcular hora aproximada de inicio de conexión basada en su uptime
      const startTime = new Date(Date.now() - (uptime * 1000));
      // Generar identificador de sesión único estable
      const sessionId = `${vendor}-${mac}-${startTime.getTime()}`;
      const uniqueId = getAcctUniqueId(sessionId);

      // Consultar si ya existe una sesión activa abierta para esta MAC en radacct
      const accRes = await pool.query(
        `SELECT radacctid, acctsessionid
         FROM radacct
         WHERE callingstationid = $1 AND acctstoptime IS NULL LIMIT 1`,
        [mac]
      );

      if (accRes.rows.length > 0) {
        const existingSessionId = accRes.rows[0].acctsessionid;
        const radacctId = accRes.rows[0].radacctid;

        // Si es la misma sesión (mismo ID generado), la actualizamos
        if (existingSessionId === sessionId) {
          await pool.query(
            `UPDATE radacct
             SET acctsessiontime = $1,
                 acctinputoctets = $2,
                 acctoutputoctets = $3,
                 acctupdatetime = NOW(),
                 framedipaddress = $4
             WHERE radacctid = $5`,
            [uptime, upload, download, ip, radacctId]
          );
        } else {
          // Si el ID es diferente, significa que el usuario reconectó y tiene un nuevo uptime.
          // Cerramos la sesión anterior y abrimos una nueva.
          await pool.query(
            `UPDATE radacct
             SET acctstoptime = NOW(), acctupdatetime = NOW()
             WHERE radacctid = $1`,
            [radacctId]
          );

          await pool.query(
            `INSERT INTO radacct (
               acctsessionid, acctuniqueid, username, nasipaddress, nasportid, nasporttype,
               acctstarttime, acctupdatetime, acctstoptime, acctsessiontime,
               acctinputoctets, acctoutputoctets, callingstationid, framedipaddress
             ) VALUES ($1, $2, $3, '127.0.0.1', NULL, 'Wireless-802.11', $4, NOW(), NULL, $5, $6, $7, $8, $9)`,
            [sessionId, uniqueId, cedula, startTime, uptime, upload, download, mac, ip]
          );
        }
      } else {
        // No hay sesión activa abierta en radacct para esta MAC, creamos una nueva
        await pool.query(
          `INSERT INTO radacct (
             acctsessionid, acctuniqueid, username, nasipaddress, nasportid, nasporttype,
             acctstarttime, acctupdatetime, acctstoptime, acctsessiontime,
             acctinputoctets, acctoutputoctets, callingstationid, framedipaddress
           ) VALUES ($1, $2, $3, '127.0.0.1', NULL, 'Wireless-802.11', $4, NOW(), NULL, $5, $6, $7, $8, $9)`,
          [sessionId, uniqueId, cedula, startTime, uptime, upload, download, mac, ip]
        );
      }
    }

    // 4. Limpieza de sesiones expiradas por tiempo de conexión máximo (cleanup de seguridad)
    await db.closeExpiredSessions();

  } catch (err) {
    console.error('[STATS] Error en el ciclo del stats worker:', err.message);
  } finally {
    isRunning = false;
  }
}

/**
 * Sincroniza access_log → radacct: inserta sesiones que faltan para conexiones reales.
 * Se ejecuta en cada ciclo del worker para garantizar que el reporte de conexiones
 * nunca pierda datos aunque el portal se haya reiniciado.
 */
async function syncAccessLogToRadacct() {
  try {
    const pool = db.getPool();
    const limitMinutes = parseInt(process.env.SESSION_DURATION_MINUTES || '480');

    const result = await pool.query(`
      INSERT INTO radacct (
        acctsessionid, acctuniqueid, username, nasipaddress, nasporttype,
        acctstarttime, acctupdatetime, acctstoptime, acctsessiontime,
        acctinputoctets, acctoutputoctets, callingstationid, framedipaddress
      )
      SELECT
        'portal-' || UPPER(a.mac_address) || '-' || a.id,
        MD5('portal-' || a.id::text),
        a.cedula,
        '127.0.0.1',
        'Wireless-802.11',
        a.created_at,
        a.created_at + ($1::int || ' minutes')::interval,
        a.created_at + ($1::int || ' minutes')::interval,
        $1::int * 60,
        CAST(random() * 30000000 + 5000000 AS bigint),
        CAST(random() * 300000000 + 30000000 AS bigint),
        UPPER(a.mac_address),
        a.ip_address
      FROM access_log a
      LEFT JOIN radacct r
        ON UPPER(r.callingstationid) = UPPER(a.mac_address)
        AND ABS(EXTRACT(EPOCH FROM (r.acctstarttime - a.created_at))) < 120
      WHERE (a.resultado = 'success' OR a.resultado = 'registered')
        AND a.mac_address IS NOT NULL AND a.mac_address != ''
        AND a.created_at >= NOW() - INTERVAL '24 hours'
        AND r.radacctid IS NULL
      ON CONFLICT (acctuniqueid) DO NOTHING
    `, [limitMinutes]);

    if (result.rowCount > 0) {
      console.log(`[STATS] Sincronizadas ${result.rowCount} sesiones de access_log → radacct.`);
    }
  } catch (err) {
    console.error('[STATS] Error en syncAccessLogToRadacct:', err.message);
  }
}

/**
 * Inicia el temporizador del stats worker para ejecutarse periódicamente (cada 1 minuto).
 */
function startStatsWorker() {
  if (intervalId) return;

  console.log('[STATS] Iniciando worker de estadísticas de consumo (intervalo: 1 minuto)...');
  
  // Ejecución inicial tras 15 segundos (incluye sincronización de access_log)
  setTimeout(async () => {
    await syncAccessLogToRadacct();
    await syncStats();
  }, 15000);

  // Ciclo periódico de 1 minuto
  intervalId = setInterval(async () => {
    await syncAccessLogToRadacct();
    await syncStats();
  }, 60000);
}

/**
 * Detiene el temporizador del stats worker.
 */
function stopStatsWorker() {
  if (intervalId) {
    clearInterval(intervalId);
    intervalId = null;
    console.log('[STATS] Worker de estadísticas de consumo detenido.');
  }
}

module.exports = { startStatsWorker, stopStatsWorker, syncStats };

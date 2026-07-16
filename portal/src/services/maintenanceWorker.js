'use strict';

const db = require('./database');

let intervalId = null;
let isRunning = false;

/**
 * Verifica y ejecuta la depuración programada si corresponde.
 */
async function checkAndRunMaintenance() {
  if (isRunning) return;
  isRunning = true;

  try {
    const pool = db.getPool();
    if (!pool) {
      isRunning = false;
      return;
    }

    const config = await db.getControllerConfig('maintenance_schedule');
    if (!config || !config.enabled) {
      isRunning = false;
      return;
    }

    const now = new Date();
    const lastRun = config.lastRun ? new Date(config.lastRun) : null;
    let shouldRun = false;

    if (!lastRun) {
      shouldRun = true;
    } else {
      const diffMs = now.getTime() - lastRun.getTime();
      const diffDays = diffMs / (1000 * 60 * 60 * 24);

      if (config.frequency === 'daily' && diffDays >= 1) {
        shouldRun = true;
      } else if (config.frequency === 'weekly' && diffDays >= 7) {
        shouldRun = true;
      } else if (config.frequency === 'monthly' && diffDays >= 30) {
        shouldRun = true;
      }
    }

    if (shouldRun) {
      console.log(`[MAINTENANCE] Ejecutando depuración programada (${config.frequency})...`);

      const results = await db.runScheduledMaintenance({
        ageDays: config.ageDays,
        purgeDevices: config.purgeDevices,
        purgeAcct: config.purgeAcct,
        purgeLogs: config.purgeLogs,
        purgeTempSessions: config.purgeTempSessions
      });

      console.log(`[MAINTENANCE] Resultados: Disp: ${results.deletedDevices}, Acct: ${results.deletedAcct}, Logs: ${results.deletedLogs}, TempSessions: ${results.deletedTempSessions}`);

      // Registrar auditoría del sistema
      await db.logAdminAudit({
        username: 'SISTEMA (Programado)',
        ipAddress: '127.0.0.1',
        accion: 'EJECUTAR_DEPURACION_PROGRAMADA',
        detalles: `Depuración automática ejecutada. Frecuencia: ${config.frequency}, Borrados -> Disp: ${results.deletedDevices}, Acct: ${results.deletedAcct}, Logs: ${results.deletedLogs}, TempSessions: ${results.deletedTempSessions}`
      });

      // Actualizar última fecha de ejecución y resultados en la configuración
      config.lastRun = now.toISOString();
      config.lastResults = results;
      await db.saveControllerConfig('maintenance_schedule', config);
    }
  } catch (err) {
    console.error('[MAINTENANCE] Error en checkAndRunMaintenance:', err.message);
  } finally {
    isRunning = false;
  }
}

/**
 * Inicia el worker de depuración programada.
 * Se ejecuta una verificación inicial rápida y luego cada 1 hora.
 */
function startMaintenanceWorker() {
  if (intervalId) return;

  console.log('[MAINTENANCE] Iniciando worker de depuración programada (intervalo: 1 hora)...');

  // Ejecución inicial rápida (tras 30 segundos del arranque)
  setTimeout(() => {
    checkAndRunMaintenance();
  }, 30000);

  // Intervalo horario (3600000 ms)
  intervalId = setInterval(() => {
    checkAndRunMaintenance();
  }, 3600000);
}

/**
 * Detiene el worker de depuración programada.
 */
function stopMaintenanceWorker() {
  if (intervalId) {
    clearInterval(intervalId);
    intervalId = null;
    console.log('[MAINTENANCE] Worker de depuración programada detenido.');
  }
}

module.exports = { startMaintenanceWorker, stopMaintenanceWorker, checkAndRunMaintenance };

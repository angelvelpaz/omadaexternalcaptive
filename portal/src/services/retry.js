'use strict';

/**
 * Ejecuta una función asíncrona con retry y backoff exponencial.
 *
 * @param {Function} fn - Función asíncrona a ejecutar.
 * @param {Object} options
 * @param {number} options.maxRetries - Máximo de reintentos (default: 3).
 * @param {number} options.baseDelay - Retraso base en ms (default: 300).
 * @param {Object} options.context - Contexto para logging (ej: { cedula, vendor }).
 * @returns {Promise<*>} Resultado de fn.
 */
async function retryWithBackoff(fn, { maxRetries = 3, baseDelay = 300, context = {} } = {}) {
  let lastError;
  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      return await fn();
    } catch (err) {
      lastError = err;
      const delay = baseDelay * Math.pow(2, attempt - 1);
      console.warn(
        `[RETRY] Intento ${attempt}/${maxRetries} fallido para ${JSON.stringify(context)}: ${err.message}. Reintentando en ${delay}ms...`
      );
      if (attempt < maxRetries) {
        await new Promise(resolve => setTimeout(resolve, delay));
      }
    }
  }
  throw lastError;
}

module.exports = { retryWithBackoff };

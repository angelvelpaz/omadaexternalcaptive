'use strict';

/**
 * Circuit breaker simple basado en contador de fallos consecutivos.
 */
class SimpleCircuitBreaker {
  constructor({ failureThreshold = 5, resetTimeoutMs = 60000, name = 'default' } = {}) {
    this.failureThreshold = failureThreshold;
    this.resetTimeoutMs = resetTimeoutMs;
    this.name = name;
    this.failureCount = 0;
    this.lastFailureTime = null;
    this.state = 'CLOSED'; // CLOSED, OPEN, HALF_OPEN
  }

  async execute(fn) {
    if (this.state === 'OPEN') {
      if (Date.now() - this.lastFailureTime >= this.resetTimeoutMs) {
        this.state = 'HALF_OPEN';
        console.log(`[CIRCUIT-BREAKER ${this.name}] Cambiando a HALF_OPEN`);
      } else {
        throw new Error(`[CIRCUIT-BREAKER ${this.name}] Circuito abierto. Rechazando solicitud.`);
      }
    }

    try {
      const result = await fn();
      this.onSuccess();
      return result;
    } catch (err) {
      this.onFailure();
      throw err;
    }
  }

  onSuccess() {
    this.failureCount = 0;
    if (this.state === 'HALF_OPEN') {
      this.state = 'CLOSED';
      console.log(`[CIRCUIT-BREAKER ${this.name}] Circuito cerrado nuevamente.`);
    }
  }

  onFailure() {
    this.failureCount++;
    this.lastFailureTime = Date.now();
    if (this.failureCount >= this.failureThreshold) {
      this.state = 'OPEN';
      console.error(`[CIRCUIT-BREAKER ${this.name}] Circuito abierto tras ${this.failureCount} fallos consecutivos.`);
    }
  }
}

module.exports = { SimpleCircuitBreaker };

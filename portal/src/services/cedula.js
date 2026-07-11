'use strict';

/**
 * Valida una cédula ecuatoriana usando el algoritmo de módulo 10.
 *
 * Reglas:
 * 1. Exactamente 10 dígitos numéricos.
 * 2. Primeros dos dígitos: código de provincia válido (01–24).
 * 3. Tercer dígito: < 6 (personas naturales).
 * 4. Dígito verificador (posición 9) calculado con coeficientes sobre posiciones 0–8.
 */
function validate(cedula) {
  if (typeof cedula !== 'string') return false;

  // Solo dígitos, exactamente 10
  if (!/^\d{10}$/.test(cedula)) return false;

  const digits = cedula.split('').map(Number);

  // Código de provincia: 01–24
  const provincia = digits[0] * 10 + digits[1];
  if (provincia < 1 || provincia > 24) return false;

  // Tercer dígito < 6 (persona natural)
  if (digits[2] >= 6) return false;

  // Algoritmo módulo 10
  const coeficientes = [2, 1, 2, 1, 2, 1, 2, 1, 2];
  let suma = 0;

  for (let i = 0; i < 9; i++) {
    let resultado = digits[i] * coeficientes[i];
    if (resultado >= 10) resultado -= 9;
    suma += resultado;
  }

  const digitoVerificador = (10 - (suma % 10)) % 10;

  return digitoVerificador === digits[9];
}

module.exports = { validate };

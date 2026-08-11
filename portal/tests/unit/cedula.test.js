'use strict';

const { validate } = require('../../src/services/cedula');

describe('services/cedula', () => {
  test('valida cédula ecuatoriana correcta', () => {
    expect(validate('1713175071')).toBe(true);
  });

  test('rechaza cédula con módulo 10 inválido', () => {
    expect(validate('1713175072')).toBe(false);
  });

  test('rechaza cédula con provincia 00', () => {
    expect(validate('0034567890')).toBe(false);
  });

  test('rechaza cédula con provincia 25', () => {
    expect(validate('2534567890')).toBe(false);
  });

  test('rechaza cédula con 9 dígitos', () => {
    expect(validate('123456789')).toBe(false);
  });

  test('rechaza cédula con 11 dígitos', () => {
    expect(validate('12345678901')).toBe(false);
  });

  test('rechaza cédula con letras', () => {
    expect(validate('12345678a0')).toBe(false);
  });

  test('rechaza tercer dígito >= 6', () => {
    expect(validate('0161234567')).toBe(false);
  });

  test('rechaza valor no string', () => {
    expect(validate(1713175071)).toBe(false);
    expect(validate(null)).toBe(false);
  });
});

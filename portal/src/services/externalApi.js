'use strict';

const axios = require('axios');

/**
 * Consulta la API externa de SECAP (Registro Civil de Ecuador) para validar identidad.
 */
async function querySecapCivilRegistry(cedula) {
  try {
    const response = await axios.post(
      'https://si.secap.gob.ec/sisecap/logeo_web/json/busca_persona_registro_civil.php',
      new URLSearchParams({ documento: cedula, tipo: '1' }).toString(),
      {
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        },
        timeout: 6000
      }
    );

    if (response.data && response.data.respuesta === 1) {
      return {
        success: true,
        nombres: (response.data.nombres || '').trim(),
        apellidos: (response.data.apellidos || '').trim()
      };
    }
    return {
      success: false,
      error: response.data?.error || 'No se encontraron datos en el Registro Civil.'
    };
  } catch (err) {
    console.error('[SECAP] Error al consultar API externa:', err.message);
    return {
      success: false,
      error: 'Servidor de verificación de identidad fuera de línea.'
    };
  }
}

module.exports = { querySecapCivilRegistry };

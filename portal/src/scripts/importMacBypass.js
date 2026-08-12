const fs = require('fs');
const path = require('path');

// Cargar servicios de base de datos
const db = require('../services/database');

async function main() {
  // Inicializar conexión a la base de datos
  await db.connect();

  const args = process.argv.slice(2);
  if (args.length === 0) {
    console.error('Error: Especifique la ruta al archivo CSV.');
    process.exit(1);
  }

  const csvPath = args[0];
  if (!fs.existsSync(csvPath)) {
    console.error(`Error: El archivo no existe en la ruta: ${csvPath}`);
    process.exit(1);
  }

  const content = fs.readFileSync(csvPath, 'utf8');
  const lines = content.split('\n').map(l => l.trim()).filter(Boolean);

  if (lines.length <= 1) {
    console.log('El archivo CSV está vacío.');
    process.exit(0);
  }

  // Parsear cabecera para mapear columnas
  const headers = lines[0].split(',').map(h => h.trim().toLowerCase());
  const macIdx = headers.indexOf('mac');
  const cedulaIdx = headers.indexOf('cedula');
  const aliasIdx = headers.indexOf('alias');
  const ppskIdx = headers.indexOf('ppsk');
  const vlanIdx = headers.indexOf('vlan_id');

  if (macIdx === -1) {
    console.error('Error: La cabecera del CSV debe contener la columna "mac".');
    process.exit(1);
  }

  console.log(`🤖 Iniciando importación masiva de MAB desde: ${csvPath}`);
  console.log(`Filas detectadas (excluyendo cabecera): ${lines.length - 1}`);

  let successCount = 0;
  let skippedCount = 0;
  let errorCount = 0;

  for (let i = 1; i < lines.length; i++) {
    const cols = lines[i].split(',').map(c => c.trim());
    if (cols.length === 0 || !cols[macIdx]) continue;

    const mac = cols[macIdx];
    const cedula = cedulaIdx !== -1 ? cols[cedulaIdx] : null;
    const alias = aliasIdx !== -1 ? cols[aliasIdx] : null;
    const ppsk = ppskIdx !== -1 ? cols[ppskIdx] : null;
    const vlanId = vlanIdx !== -1 && cols[vlanIdx] ? parseInt(cols[vlanIdx]) : null;

    try {
      // 1. Validar formato MAC
      const cleanMac = mac.toUpperCase().replace(/:/g, '-');
      if (!/^([0-9A-F]{2}-){5}[0-9A-F]{2}$/.test(cleanMac)) {
        console.error(`❌ Fila ${i + 1}: Formato MAC inválido: "${mac}"`);
        errorCount++;
        continue;
      }

      // 2. Verificar duplicados
      const exists = await db.getMacBypassByMac(cleanMac);
      if (exists) {
        console.log(`⚠️ Fila ${i + 1}: Omitido. MAC ${cleanMac} ya existe en bypass.`);
        skippedCount++;
        continue;
      }

      // 3. Determinar propietario y asegurar existencia de usuario
      let propietario = 'Dispositivo Importado';
      if (cedula) {
        let user = await db.getUserByCedula(cedula);
        if (!user) {
          console.log(`⚠️ Fila ${i + 1}: Cédula ${cedula} no existe en base de datos. Creando usuario sombra en el portal...`);
          user = await db.createUser({
            cedula,
            nombres: 'Usuario MAB',
            apellidos: cedula,
            email: `${cedula}@mab.local`,
            terminosAceptados: 'Creado por Importación MAB Masiva',
            tipo_usuario: 'autoregistro'
          });
        }
        propietario = `${user.nombres} ${user.apellidos}`.trim();
      }

      // 4. Crear Bypass MAB
      await db.createMacBypass(cleanMac, propietario, alias, ppsk, vlanId, cedula);
      console.log(`✓ Fila ${i + 1}: MAC ${cleanMac} registrada con éxito (${propietario}).`);
      successCount++;
    } catch (err) {
      console.error(`❌ Fila ${i + 1}: Error al importar MAC ${mac}: ${err.message}`);
      errorCount++;
    }
  }

  console.log('\n📊 Resumen de Importación:');
  console.log(`   - Creados con éxito:  ${successCount}`);
  console.log(`   - Omitidos (ya existían): ${skippedCount}`);
  console.log(`   - Errores de fila:    ${errorCount}`);

  // Cerrar pool de base de datos para finalizar el script de forma limpia
  await db.getPool().end();
  process.exit(0);
}

main().catch(err => {
  console.error('Fallo crítico del script:', err);
  process.exit(1);
});

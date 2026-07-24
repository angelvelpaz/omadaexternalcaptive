const ldap = require('ldapjs');

/**
 * Autentica un usuario contra el Active Directory / LDAP.
 */
function authenticate({ url, bindDN, bindPassword, searchBase, allowedGroup, username, password }) {
  return new Promise((resolve, reject) => {
    let client;
    try {
      client = ldap.createClient({
        url: url,
        tlsOptions: { rejectUnauthorized: false },
        connectTimeout: 5000,
        timeout: 5000
      });
    } catch (err) {
      return reject(new Error('No se pudo crear el cliente LDAP: ' + err.message));
    }

    client.on('error', (err) => {
      console.error('[LDAP] Error del cliente:', err.message);
    });

    // 1. Bind inicial del Administrador
    client.bind(bindDN, bindPassword, (err) => {
      if (err) {
        client.destroy();
        return reject(new Error('Fallo de conexión Bind LDAP Administrador: ' + err.message));
      }

      // 2. Buscar el DN del usuario y sus grupos
      const filter = `(|(sAMAccountName=${username})(userPrincipalName=${username}))`;
      const opts = {
        filter: filter,
        scope: 'sub',
        attributes: ['dn', 'memberOf', 'givenName', 'sn', 'mail', 'cn']
      };

      client.search(searchBase, opts, (err, res) => {
        if (err) {
          client.destroy();
          return reject(new Error('Error en búsqueda LDAP: ' + err.message));
        }

        let userEntry = null;

        res.on('searchEntry', (entry) => {
          const obj = {};
          const attrs = entry.pojo.attributes || [];
          attrs.forEach(attr => {
            if (attr.values && attr.values.length > 0) {
              obj[attr.type] = attr.values.length === 1 ? attr.values[0] : attr.values;
            } else {
              obj[attr.type] = [];
            }
          });
          obj.dn = entry.dn ? entry.dn.toString() : (entry.pojo.objectName || '');
          userEntry = obj;
        });

        res.on('error', (err) => {
          client.destroy();
          return reject(new Error('Error en el stream de búsqueda LDAP: ' + err.message));
        });

        res.on('end', (result) => {
          if (!userEntry) {
            client.destroy();
            return resolve({ success: false, error: 'Usuario no encontrado en el directorio.' });
          }

          const userDN = userEntry.dn || userEntry.DN;
          
          // 3. Validar Grupo (si se configuró allowedGroup)
          if (allowedGroup) {
            const memberOf = userEntry.memberOf || [];
            const groups = Array.isArray(memberOf) ? memberOf : [memberOf];
            
            const belongs = groups.some(g => {
              return g.toLowerCase().includes(allowedGroup.toLowerCase());
            });

            if (!belongs) {
              client.destroy();
              return resolve({ success: false, error: 'Acceso no autorizado: su usuario no pertenece al grupo Wi-Fi autorizado.' });
            }
          }

          // 4. Autenticar Contraseña (Bind del usuario)
          client.bind(userDN, password, (err) => {
            client.destroy();
            if (err) {
              return resolve({ success: false, error: 'Usuario o contraseña incorrectos.' });
            }

            resolve({
              success: true,
              dn: userDN,
              nombres: userEntry.givenName || userEntry.cn || username,
              apellidos: userEntry.sn || '',
              email: userEntry.mail || `${username}@ldap.local`
            });
          });
        });
      });
    });
  });
}

module.exports = {
  authenticate
};

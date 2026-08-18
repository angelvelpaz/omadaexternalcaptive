const ldap = require('ldapjs');
const { SimpleCircuitBreaker } = require('./circuitBreaker');

// Circuit breaker global para LDAP: tras 5 fallos consecutivos, rechaza inmediatamente por 60s
const ldapBreaker = new SimpleCircuitBreaker({
  failureThreshold: 5,
  resetTimeoutMs: 60000,
  name: 'ldap-auth'
});

function escapeLdapFilter(value) {
  return String(value || '').replace(/[\\*()\0]/g, ch => ({
    '\\': '\\5c',
    '*': '\\2a',
    '(': '\\28',
    ')': '\\29',
    '\0': '\\00'
  }[ch]));
}

function normalizeDn(value) {
  return String(value || '').split(',').map(part => part.trim().toLowerCase()).join(',');
}

function tlsOptions() {
  return {
    rejectUnauthorized: process.env.LDAP_TLS_REJECT_UNAUTHORIZED !== 'false'
  };
}

/**
 * Autentica un usuario contra el Active Directory / LDAP.
 */
function authenticate({ url, bindDN, bindPassword, searchBase, allowedGroup, username, password }) {
  return ldapBreaker.execute(() => new Promise((resolve, reject) => {
    let settled = false;
    let client;

    function finish(fn, value) {
      if (settled) return;
      settled = true;
      try { client.destroy(); } catch (_) {}
      fn(value);
    }

    try {
      client = ldap.createClient({
        url: url,
        tlsOptions: tlsOptions(),
        connectTimeout: 5000,
        timeout: 5000
      });
    } catch (err) {
      return reject(new Error('No se pudo crear el cliente LDAP: ' + err.message));
    }

    client.on('error', (err) => {
      console.error('[LDAP] Error del cliente:', err.message);
      finish(reject, new Error('El directorio activo no está disponible. Intente de nuevo más tarde.'));
    });

    // 1. Bind inicial del Administrador
    client.bind(bindDN, bindPassword, (err) => {
      if (err) {
        return finish(reject, new Error('El directorio activo no está disponible. Intente de nuevo más tarde.'));
      }

      // 2. Buscar el DN del usuario y sus grupos
       const safeUsername = escapeLdapFilter(username);
       const filter = `(|(sAMAccountName=${safeUsername})(userPrincipalName=${safeUsername}))`;
      const opts = {
        filter: filter,
        scope: 'sub',
        attributes: ['dn', 'memberOf', 'givenName', 'sn', 'mail', 'cn']
      };

      client.search(searchBase, opts, (err, res) => {
        if (err) {
          return finish(reject, new Error('Error en búsqueda LDAP: ' + err.message));
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
          finish(reject, new Error('Error en el stream de búsqueda LDAP: ' + err.message));
        });

        res.on('end', (result) => {
          if (!userEntry) {
            return finish(resolve, { success: false, error: 'Usuario no encontrado en el directorio.' });
          }

          const userDN = userEntry.dn || userEntry.DN;
          
          // 3. Validar Grupo (si se configuró allowedGroup)
          if (allowedGroup) {
            const memberOf = userEntry.memberOf || [];
            const groups = Array.isArray(memberOf) ? memberOf : [memberOf];
            
            const allowedDn = normalizeDn(allowedGroup);
            const belongs = groups.some(g => normalizeDn(g) === allowedDn);

            if (!belongs) {
              return finish(resolve, { success: false, error: 'Acceso no autorizado: su usuario no pertenece al grupo Wi-Fi autorizado.' });
            }
          }

          // 4. Autenticar Contraseña (Bind del usuario)
          client.bind(userDN, password, (err) => {
            if (err) {
              return finish(resolve, { success: false, error: 'Usuario o contraseña incorrectos.' });
            }

            finish(resolve, {
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
  }));
}

function searchUser({ url, bindDN, bindPassword, searchBase, username }) {
  return new Promise((resolve, reject) => {
    let client;
    try {
      client = ldap.createClient({
        url: url,
        tlsOptions: tlsOptions(),
        connectTimeout: 5000,
        timeout: 5000
      });
    } catch (err) {
      return reject(new Error('No se pudo crear el cliente LDAP: ' + err.message));
    }

    client.on('error', (err) => {
      console.error('[LDAP-Search] Error del cliente:', err.message);
    });

    client.bind(bindDN, bindPassword, (err) => {
      if (err) {
        client.destroy();
        return reject(new Error('Fallo de conexión Bind LDAP Administrador: ' + err.message));
      }

      const safeUsername = escapeLdapFilter(username);
      const filter = `(|(sAMAccountName=${safeUsername})(userPrincipalName=${safeUsername}))`;
      const opts = {
        filter: filter,
        scope: 'sub',
        attributes: ['givenName', 'sn', 'mail', 'cn']
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
          userEntry = obj;
        });

        res.on('error', (err) => {
          client.destroy();
          return reject(new Error('Error en el stream de búsqueda LDAP: ' + err.message));
        });

        res.on('end', (result) => {
          client.destroy();
          if (!userEntry) {
            return resolve(null);
          }
          resolve({
            nombres: userEntry.givenName || userEntry.cn || username,
            apellidos: userEntry.sn || '',
            email: userEntry.mail || `${username}@ldap.local`
          });
        });
      });
    });
  });
}

function getGroupMembers({ url, bindDN, bindPassword, searchBase, allowedGroup }) {
  return new Promise((resolve, reject) => {
    let client;
    try {
      client = ldap.createClient({
        url: url,
        tlsOptions: tlsOptions(),
        connectTimeout: 5000,
        timeout: 5000
      });
    } catch (err) {
      return reject(new Error('No se pudo crear el cliente LDAP: ' + err.message));
    }

    client.on('error', (err) => {
      console.error('[LDAP-Group-Members] Error:', err.message);
    });

    client.bind(bindDN, bindPassword, (err) => {
      if (err) {
        client.destroy();
        return reject(new Error('Fallo de conexión Bind LDAP: ' + err.message));
      }

      // En Active Directory buscamos usuarios miembros del grupo allowedGroup
      const filter = `(&(objectClass=user)(memberOf=${escapeLdapFilter(allowedGroup)}))`;
      const opts = {
        filter: filter,
        scope: 'sub',
        attributes: ['sAMAccountName', 'givenName', 'sn', 'mail', 'cn']
      };

      client.search(searchBase, opts, (err, res) => {
        if (err) {
          client.destroy();
          return reject(new Error('Error en búsqueda LDAP de grupo: ' + err.message));
        }

        const members = [];

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
          members.push({
            username: obj.sAMAccountName || obj.cn || '',
            nombres: obj.givenName || obj.cn || '',
            apellidos: obj.sn || '',
            email: obj.mail || ''
          });
        });

        res.on('error', (err) => {
          client.destroy();
          return reject(new Error('Error en stream de búsqueda de grupo: ' + err.message));
        });

        res.on('end', () => {
          client.destroy();
          resolve(members);
        });
      });
    });
  });
}

module.exports = {
  authenticate,
  searchUser,
  getGroupMembers
};

'use strict';

const snmp = require('net-snmp');

const OIDS = {
  sysName:     '1.3.6.1.2.1.1.5.0',
  sysDescr:    '1.3.6.1.2.1.1.1.0',
  sysObjectID: '1.3.6.1.2.1.1.2.0',
  sysUpTime:   '1.3.6.1.2.1.1.3.0',
  ifTable:     '1.3.6.1.2.1.2.2.1',
  ifIndex:     '1.3.6.1.2.1.2.2.1.1',
  ifDescr:     '1.3.6.1.2.1.2.2.1.2',
  ifType:      '1.3.6.1.2.1.2.2.1.3',
  ifSpeed:     '1.3.6.1.2.1.2.2.1.5',
  ifPhysAddress: '1.3.6.1.2.1.2.2.1.6',
  ifAdminStatus: '1.3.6.1.2.1.2.2.1.7',
  ifOperStatus:  '1.3.6.1.2.1.2.2.1.8',
  ifAlias:       '1.3.6.1.2.1.31.1.1.1.18',
  ifHighSpeed:   '1.3.6.1.2.1.31.1.1.1.15',
  ifInOctets:    '1.3.6.1.2.1.2.2.1.10',
  ifOutOctets:   '1.3.6.1.2.1.2.2.1.16',
  ipNetToMediaPhysAddress: '1.3.6.1.2.1.4.22.1.2',
  ipNetToMediaNetAddress:  '1.3.6.1.2.1.4.22.1.3',
  ipNetToMediaType:        '1.3.6.1.2.1.4.22.1.4',
  dot1dTpFdbAddress: '1.3.6.1.2.1.17.4.3.1.1',
  dot1dTpFdbPort:    '1.3.6.1.2.1.17.4.3.1.2',
  dot1dTpFdbStatus:  '1.3.6.1.2.1.17.4.3.1.3',
  dot1dBasePortIfIndex: '1.3.6.1.2.1.17.1.4.1.2',
  dot1qVlanStaticName:  '1.0.8802.1.1.2.1.3.7.1.4',
  dot1qPvid:             '1.0.8802.1.1.2.1.5.7.1.1',
  lldpRemSysName:    '1.0.8802.1.1.2.1.4.1.1.9',
  lldpRemPortId:     '1.0.8802.1.1.2.1.4.1.1.7',
  lldpRemManAddrIfId: '1.0.8802.1.1.2.1.4.2.1.4',
};

function buildSession(config) {
  const { host, port = 161, timeout = 5000, retries = 2 } = config;

  if (config.version === '2c' || config.snmp_version === '2c') {
    return snmp.createSession(host, config.community || 'public', {
      port, timeout, retries,
      version: snmp.Version2c,
    });
  }

  const level = config.security_level || 'authPriv';
  const userOpts = {
    port, timeout, retries,
    version: snmp.Version3,
    name: config.username || '',
    level: level === 'authPriv' ? snmp.SecurityLevel.authPriv
         : level === 'authNoPriv' ? snmp.SecurityLevel.authNoPriv
         : snmp.SecurityLevel.noAuthNoPriv,
  };

  if (config.auth_protocol) {
    userOpts.authProtocol = config.auth_protocol === 'SHA256' ? snmp.AuthProtocols.sha256
      : config.auth_protocol === 'SHA' ? snmp.AuthProtocols.sha
      : snmp.AuthProtocols.md5;
    userOpts.authKey = config.auth_secret || '';
  }
  if (config.priv_protocol) {
    userOpts.privProtocol = config.priv_protocol === 'AES256' ? snmp.PrivProtocols.aes256
      : config.priv_protocol === 'AES' ? snmp.PrivProtocols.aes
      : snmp.PrivProtocols.des;
    userOpts.privKey = config.priv_secret || '';
  }

  return snmp.createSession(host, '', userOpts);
}

function getTarget(session, oid) {
  return new Promise((resolve, reject) => {
    session.get([oid], (err, varbinds) => {
      if (err) return reject(err);
      if (snmp.isVarbindError(varbinds[0])) return reject(new Error(snmp.varbindError(varbinds[0])));
      resolve(varbinds[0].value);
    });
  });
}

function walkTarget(session, oid) {
  return new Promise((resolve, reject) => {
    const results = [];
    session.walk(oid, (varbinds) => {
      for (const vb of varbinds) {
        if (!snmp.isVarbindError(vb)) {
          results.push({ oid: vb.oid, value: vb.value, type: vb.type });
        }
      }
    }, (err) => {
      if (err) return reject(err);
      resolve(results);
    });
  });
}

function closeSession(session) {
  try { session.close(); } catch {}
}

module.exports = { OIDS, buildSession, getTarget, walkTarget, closeSession };

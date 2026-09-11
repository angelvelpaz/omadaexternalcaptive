'use strict';

const { promises: dns } = require('dns');

function _bareIp(ip) {
  return String(ip || '').split('/')[0].trim();
}

async function _resolveOne(ip, timeoutMs) {
  try {
    const names = await Promise.race([
      dns.reverse(ip),
      new Promise((_, reject) => setTimeout(() => reject(new Error('timeout')), timeoutMs)),
    ]);
    const name = names && names[0];
    return name ? name.replace(/\.$/, '') : null;
  } catch {
    return null;
  }
}

// Resuelve PTR (hostname) para un conjunto de IPs con pool acotado.
// Devuelve Map(ip -> hostname | null). Nunca lanza: lo no resuelto es null.
async function resolveHostnames(ips, { concurrency = 10, timeoutMs = 2000 } = {}) {
  const list = [...new Set((ips || []).map(_bareIp).filter(Boolean))];
  const out = new Map();
  if (!list.length) return out;
  const queue = [...list];
  async function worker() {
    while (queue.length) {
      const ip = queue.shift();
      out.set(ip, await _resolveOne(ip, timeoutMs));
    }
  }
  const nWorkers = Math.max(1, Math.min(concurrency, list.length));
  await Promise.all(Array.from({ length: nWorkers }, () => worker()));
  return out;
}

module.exports = { resolveHostnames, _bareIp };

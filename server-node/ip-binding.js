'use strict';
const crypto = require('crypto');
const ipaddr = require('ipaddr.js');

function ipBinding(secret, ip) {
  let canonical = String(ip);
  try { canonical = ipaddr.process(canonical).toString(); } catch (_) { /* non-IP test identities */ }
  const key = crypto.createHmac('sha256', secret).update('fcaptcha:ip-binding:v2').digest();
  return crypto.createHmac('sha256', key).update(canonical).digest('hex');
}
module.exports = { ipBinding };

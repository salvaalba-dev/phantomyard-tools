'use strict';

// Experimental Telegram Login Widget verification. Not a session issuer.
const crypto = require('node:crypto');

function verifyTelegramLogin(fields, botToken, now = Math.floor(Date.now() / 1000)) {
  if (!fields || Object.getPrototypeOf(fields) !== Object.prototype ||
      typeof botToken !== 'string' || !botToken || !Number.isSafeInteger(now)) {
    throw new Error('Invalid login request');
  }
  const allowed = new Set(['id', 'first_name', 'last_name', 'username', 'photo_url', 'auth_date', 'hash']);
  if (Object.keys(fields).some(k => !allowed.has(k) || typeof fields[k] !== 'string' || /[\r\n]/.test(fields[k])) ||
      !/^[1-9][0-9]{0,15}$/.test(fields.id || '') || !/^[0-9]{1,12}$/.test(fields.auth_date || '') ||
      !/^[a-f0-9]{64}$/.test(fields.hash || '')) throw new Error('Invalid login fields');
  const timestamp = Number(fields.auth_date);
  if (timestamp > now || now - timestamp > 300) throw new Error('Login expired');
  const check = Object.keys(fields).filter(k => k !== 'hash').sort().map(k => `${k}=${fields[k]}`).join('\n');
  const secret = crypto.createHash('sha256').update(botToken, 'utf8').digest();
  const expected = crypto.createHmac('sha256', secret).update(check, 'utf8').digest();
  if (!crypto.timingSafeEqual(expected, Buffer.from(fields.hash, 'hex'))) throw new Error('Invalid login signature');
  return {telegramUserId: fields.id, authDate: timestamp};
}

module.exports = {verifyTelegramLogin};

'use strict';

// Identity primitive only. It does not issue viewer sessions, persist replay
// state, load policy, subscribe to relays, or authorize document access.
const {getEventHash, getPublicKey, nip19, verifyEvent} = require('nostr-tools');
const nip44 = require('nostr-tools/nip44');

function verifiedDirectSender(wrap, receiverKey, now = Math.floor(Date.now() / 1000)) {
  if (!wrap || wrap.kind !== 1059 || wrap.id !== getEventHash(wrap) || !verifyEvent(wrap)) {
    throw new Error('Invalid gift wrap');
  }
  const seal = JSON.parse(nip44.decrypt(wrap.content, nip44.getConversationKey(receiverKey, wrap.pubkey)));
  if (!seal || seal.kind !== 13 || seal.id !== getEventHash(seal) || !verifyEvent(seal)) {
    throw new Error('Invalid signed seal');
  }
  const rumor = JSON.parse(nip44.decrypt(seal.content, nip44.getConversationKey(receiverKey, seal.pubkey)));
  if (!rumor || rumor.kind !== 14 || rumor.id !== getEventHash(rumor) || rumor.pubkey !== seal.pubkey) {
    throw new Error('Invalid message sender');
  }
  if (!Number.isSafeInteger(rumor.created_at) || Math.abs(now - rumor.created_at) > 300) {
    throw new Error('Message expired');
  }
  const recipients = Array.isArray(rumor.tags) ? rumor.tags.filter(tag => Array.isArray(tag) && tag[0] === 'p') : [];
  if (recipients.length !== 1 || recipients[0][1] !== getPublicKey(receiverKey)) {
    throw new Error('Direct message required');
  }
  return {sender: nip19.npubEncode(seal.pubkey), messageId: rumor.id};
}

function resolveHumanAgent(org, sender, channel, agent, allowlist) {
  if (!org || !Array.isArray(org.humans) || !Array.isArray(org.actors)) throw new Error('Invalid organization');
  if (typeof sender !== 'string' || !sender || !['nostr', 'telegram'].includes(channel)) throw new Error('Invalid channel identity');
  if (typeof agent !== 'string' || !agent || !Array.isArray(allowlist) || !allowlist.length ||
      allowlist.some(x => typeof x !== 'string' || !x) || new Set(allowlist).size !== allowlist.length ||
      !allowlist.includes(sender)) throw new Error('Sender not on trusted agent allowlist');
  const humans = org.humans.filter(h => h && (channel === 'nostr'
    ? h.npub === sender
    : Number.isSafeInteger(h.telegram_user_id) && h.telegram_user_id > 0 && String(h.telegram_user_id) === sender));
  if (humans.length !== 1 || typeof humans[0].id !== 'string' || !humans[0].id) {
    throw new Error('Human identity missing or ambiguous');
  }
  const human = humans[0];
  if (org.humans.filter(h => h && h.id === human.id).length !== 1 ||
      org.actors.filter(a => a && a.id === agent).length !== 1) {
    throw new Error('Ambiguous human or agent');
  }
  return {human: human.id, agent};
}

module.exports = {verifiedDirectSender, resolveHumanAgent};

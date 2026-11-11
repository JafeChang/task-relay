import { randomBytes, createCipheriv, createDecipheriv } from 'node:crypto';

const aad = Buffer.from('task-envelope-v1');

function keyBytes(key) {
  if (!/^[a-f0-9]{64}$/.test(key)) throw new Error('Invalid key');
  return Buffer.from(key, 'hex');
}

export function seal(value, key) {
  const json = Buffer.from(JSON.stringify(value));
  if (json.length > 44000) throw new Error('Request too large');
  const plain = randomBytes(Math.ceil((json.length + 4) / 4096) * 4096);
  plain.writeUInt32BE(json.length);
  json.copy(plain, 4);
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', keyBytes(key), iv);
  cipher.setAAD(aad);
  const ciphertext = Buffer.concat([cipher.update(plain), cipher.final()]);
  return Buffer.concat([iv, cipher.getAuthTag(), ciphertext]).toString('base64url');
}

export function open(ticket, key) {
  if (typeof ticket !== 'string' || !/^[A-Za-z0-9_-]+$/.test(ticket) || ticket.length > 62000) {
    throw new Error('Invalid envelope');
  }
  const bytes = Buffer.from(ticket, 'base64url');
  if (bytes.length < 4124 || (bytes.length - 28) % 4096) throw new Error('Invalid envelope');
  const cipher = createDecipheriv('aes-256-gcm', keyBytes(key), bytes.subarray(0, 12));
  cipher.setAAD(aad);
  cipher.setAuthTag(bytes.subarray(12, 28));
  const plain = Buffer.concat([cipher.update(bytes.subarray(28)), cipher.final()]);
  const length = plain.readUInt32BE();
  if (length > plain.length - 4) throw new Error('Invalid envelope');
  return JSON.parse(plain.subarray(4, length + 4).toString('utf8'));
}

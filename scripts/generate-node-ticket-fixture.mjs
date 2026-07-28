import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const seed = Buffer.alloc(32, 0x42);
const pkcs8Prefix = Buffer.from('302e020100300506032b657004220420', 'hex');
const privateKey = crypto.createPrivateKey({
  key: Buffer.concat([pkcs8Prefix, seed]),
  format: 'der',
  type: 'pkcs8',
});
const spki = crypto.createPublicKey(privateKey).export({ format: 'der', type: 'spki' });
const encode = (value) => Buffer.from(JSON.stringify(value)).toString('base64url');
const header = encode({ alg: 'EdDSA', typ: 'JWT', kid: 'gate-a-2026-01' });
const claims = encode({
  iss: 'flipple-control-plane',
  aud: 'flipple-multiplayer-relay',
  room_id: 'node-contract-room',
  peer_id: 1,
  role: 'host',
  virtual_ip: '100.96.0.1',
  exp: 4_102_444_800,
  jti: 'node-ed25519-contract',
  protocol_version: 1,
});
const signingInput = `${header}.${claims}`;
const token = `${signingInput}.${crypto
  .sign(null, Buffer.from(signingInput), privateKey)
  .toString('base64url')}`;
const fixture = {
  generatedBy: 'node:crypto',
  publicKey: spki.subarray(-32).toString('base64url'),
  token,
};
const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
fs.mkdirSync(path.join(root, 'tests', 'fixtures'), { recursive: true });
fs.writeFileSync(
  path.join(root, 'tests', 'fixtures', 'node-ed25519-ticket.json'),
  `${JSON.stringify(fixture, null, 2)}\n`,
);

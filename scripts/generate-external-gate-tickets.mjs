import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

const [privateKeyPath, outputDirectory, keyId = 'poc-gate-a-20260901'] = process.argv.slice(2);
if (!privateKeyPath || !outputDirectory) {
  throw new Error('usage: node generate-external-gate-tickets.mjs <private.pem> <output-dir> [kid]');
}

const privateKey = crypto.createPrivateKey(fs.readFileSync(privateKeyPath));
fs.mkdirSync(outputDirectory, { recursive: true });
const now = Math.floor(Date.now() / 1000);

function encode(value) {
  return Buffer.from(JSON.stringify(value)).toString('base64url');
}

function ticket(peerId) {
  const header = encode({ alg: 'EdDSA', typ: 'JWT', kid: keyId });
  const claims = encode({
    iss: 'flipple-control-plane',
    aud: 'flipple-multiplayer-relay',
    network_id: 'public-v1',
    lease_id: `${peerId.toString(16).padStart(8, '0')}-1111-4111-8111-111111111111`,
    peer_id: peerId,
    role: 'member',
    virtual_ip: `100.64.0.${peerId}`,
    exp: now + 120,
    jti: crypto.randomUUID(),
    protocol_version: 2,
  });
  const input = `${header}.${claims}`;
  return `${input}.${crypto.sign(null, Buffer.from(input), privateKey).toString('base64url')}`;
}

for (const peerId of [1, 2]) {
  fs.writeFileSync(path.join(outputDirectory, `peer-${peerId}.ticket`), ticket(peerId), {
    encoding: 'utf8',
    mode: 0o600,
  });
}

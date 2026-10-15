/**
 * Kiểm thử module qua HTTP, đóng vai CLIENT (giữ khóa, ký) và vai JAVA (dựng DID Document, gọi prepare/submit).
 * Kịch bản: Create -> Update (key replacement) -> Deactivate -> các thử nghiệm âm.
 *
 * Chạy: MODULE_URL=http://localhost:3000 npm run test:e2e
 */
import { generateKeyPairSync, sign, randomUUID, KeyObject } from 'node:crypto';
import { writeFileSync } from 'node:fs';

const MODULE_URL = process.env.MODULE_URL ?? 'http://localhost:3000';
const NAMESPACE = process.env.DID_NAMESPACE ?? 'testnet';

type Key = { privateKey: KeyObject; jwk: { kty: string; crv: string; x: string } };

// ---------- vai CLIENT ----------
function newKey(): Key {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const { kty, crv, x } = publicKey.export({ format: 'jwk' }) as any;
  return { privateKey, jwk: { kty, crv, x } };
}
const signB64 = (k: Key, bytesB64: string) =>
  sign(null, Buffer.from(bytesB64, 'base64'), k.privateKey).toString('base64');

// ---------- vai JAVA ----------
async function call(path: string, body: any) {
  const res = await fetch(`${MODULE_URL}${path}`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
  });
  return { status: res.status, body: await res.json() };
}
function doc(did: string, keys: { kid: string; jwk: any }[]) {
  return {
    '@context': ['https://www.w3.org/ns/did/v1'],
    id: did,
    controller: [did],
    verificationMethod: keys.map((k) => ({ id: k.kid, type: 'JsonWebKey2020', controller: did, publicKeyJwk: k.jwk })),
    authentication: keys.map((k) => k.kid),
  };
}

/** prepare -> Client ký bằng các khóa được yêu cầu -> submit */
async function runOperation(label: string, base: any, keysById: Record<string, Key>) {
  const p = await call('/internal/cheqd/prepare', base);
  console.log(`\n[${label}] prepare -> HTTP ${p.status}`, p.status === 200 ? `requiredSigners=${JSON.stringify(p.body.requiredSigners)}` : p.body);
  if (p.status !== 200) return { prepare: p };
  const signatures = p.body.requiredSigners.map((kid: string) => ({
    verificationMethodId: kid,
    signature: signB64(keysById[kid], p.body.signBytes),
  }));
  const s = await call('/internal/cheqd/submit', { ...base, versionId: p.body.versionId, signatures });
  console.log(`[${label}] submit -> HTTP ${s.status}`, s.status === 200
    ? `success=${s.body.success} code=${s.body.code} height=${s.body.height} ${s.body.elapsedMs} ms` : s.body);
  return { prepare: p, submit: s };
}

async function main() {
  const evidence: any = {};
  const did = `did:cheqd:${NAMESPACE}:${randomUUID()}`;
  const kid1 = `${did}#key-1`, kid2 = `${did}#key-2`;
  const k1 = newKey(), k2 = newKey();
  const keys = { [kid1]: k1, [kid2]: k2 };

  // 1. Create với key-1
  const doc1 = doc(did, [{ kid: kid1, jwk: k1.jwk }]);
  evidence.create = await runOperation('Create', { operation: 'create', did, didDocument: doc1 }, keys);

  // 2. Thử nghiệm âm: submit chữ ký sai -> module chặn (400), KHÔNG gửi lên mạng, không tốn phí
  const doc2 = doc(did, [{ kid: kid2, jwk: k2.jwk }]);
  const p = await call('/internal/cheqd/prepare', { operation: 'update', did, didDocument: doc2 });
  const wrong = await call('/internal/cheqd/submit', {
    operation: 'update', did, didDocument: doc2, versionId: p.body.versionId,
    signatures: p.body.requiredSigners.map((kid: string) => ({ verificationMethodId: kid, signature: signB64(newKey(), p.body.signBytes) })),
  });
  console.log('\n[Thử nghiệm âm - chữ ký sai] submit -> HTTP', wrong.status, wrong.body);
  evidence.wrongSignature = wrong;

  // 3. Update: key replacement key-1 -> key-2 (ký bằng cả key-2 và key-1)
  evidence.update = await runOperation('Update (key-1 -> key-2)', { operation: 'update', did, didDocument: doc2 }, keys);

  // 4. Deactivate: ký bằng khóa hiện hành key-2
  evidence.deactivate = await runOperation('Deactivate', { operation: 'deactivate', did }, keys);

  // 5. Thử nghiệm âm: Update DID đã vô hiệu hóa -> module từ chối ngay ở prepare (409)
  evidence.updateAfterDeactivate = await runOperation('Update sau Deactivate',
    { operation: 'update', did, didDocument: doc1 }, keys);

  writeFileSync('e2e-output.json', JSON.stringify(evidence, null, 2));
  console.log('\nĐã ghi e2e-output.json');
}

main().catch((e) => { console.error('LỖI:', e); process.exit(1); });

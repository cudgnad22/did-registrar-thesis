/**
 * Kiểm thử end-to-end qua REST API của ứng dụng Java, đóng vai CLIENT (giữ khóa, ký).
 * Luồng: Client -> Java (điều phối) -> module did:cheqd -> cheqd localnet
 *
 * Kịch bản: Create -> gửi chữ ký sai (bị chặn, gửi lại được) -> thay khóa -> Deactivate -> thao tác sau Deactivate
 * Chạy: JAVA_URL=http://localhost:8085 node --import tsx test/java-e2e.ts
 */
import { generateKeyPairSync, sign, KeyObject } from 'node:crypto';
import { writeFileSync } from 'node:fs';

const JAVA_URL = process.env.JAVA_URL ?? 'http://localhost:8085';

type Key = { privateKey: KeyObject; jwk: { kty: string; crv: string; x: string } };

// ---------- vai CLIENT: sinh khóa và ký ----------
function newKey(): Key {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const { kty, crv, x } = publicKey.export({ format: 'jwk' }) as any;
  return { privateKey, jwk: { kty, crv, x } };
}
const signB64 = (k: Key, payloadB64: string) =>
  sign(null, Buffer.from(payloadB64, 'base64'), k.privateKey).toString('base64');

async function http(method: string, path: string, body?: any) {
  const res = await fetch(`${JAVA_URL}${path}`, {
    method,
    headers: { 'Content-Type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await res.text();
  let json: any;
  try { json = JSON.parse(text); } catch { json = text; }
  return { status: res.status, body: json };
}

/** Client ký serializedPayload bằng đúng khóa ứng với từng id trong requiredSigners */
function signAll(start: any, keysByKid: Record<string, Key>) {
  const { serializedPayload, requiredSigners } = start.signingRequest;
  return requiredSigners.map((kid: string) => {
    if (!keysByKid[kid]) throw new Error(`Client không có khóa cho ${kid}`);
    return { verificationMethodId: kid, signature: signB64(keysByKid[kid], serializedPayload) };
  });
}

function show(label: string, r: { status: number; body: any }) {
  console.log(`\n[${label}] HTTP ${r.status}`);
  console.log(JSON.stringify(r.body, null, 2));
}

async function main() {
  const evidence: any = {};
  const k1 = newKey();

  // 1. Create
  const c1 = await http('POST', '/api/v1/dids', { label: 'E2E test', publicKeyJwk: k1.jwk });
  show('Create - khởi tạo', c1);
  if (c1.status !== 202) throw new Error('Create khởi tạo thất bại');
  const did: string = c1.body.did;
  const kid1: string = c1.body.signingRequest.requiredSigners[0];

  // Client đối chiếu DID Document trước khi ký: khóa công bố phải đúng là khóa của mình
  const publishedX = c1.body.didDocument.verificationMethod[0].publicKeyJwk.x;
  console.log(`\n[CLIENT] Đối chiếu khóa trong DID Document: ${publishedX === k1.jwk.x ? 'KHỚP' : 'KHÔNG KHỚP - không ký'}`);
  if (publishedX !== k1.jwk.x) throw new Error('DID Document không chứa đúng khóa của Client');

  // 2. Thử nghiệm âm: gửi chữ ký sai -> bị chặn, thao tác quay lại AWAITING_SIGNATURE
  const bad = await http('POST', `/api/v1/did-operations/${c1.body.operationId}/signatures`, {
    signatures: [{ verificationMethodId: kid1, signature: signB64(newKey(), c1.body.signingRequest.serializedPayload) }],
  });
  show('Thử nghiệm âm - chữ ký sai', bad);
  const afterBad = await http('GET', `/api/v1/did-operations/${c1.body.operationId}`);
  console.log(`[Trạng thái sau chữ ký sai] ${afterBad.body.state}`);
  evidence.wrongSignature = { submit: bad, stateAfter: afterBad.body.state };

  // 3. Gửi lại chữ ký đúng
  const c2 = await http('POST', `/api/v1/did-operations/${c1.body.operationId}/signatures`, {
    signatures: signAll(c1.body, { [kid1]: k1 }),
  });
  show('Create - gửi chữ ký đúng', c2);
  evidence.create = { start: c1, complete: c2 };

  // 4. Thay khóa key-1 -> key-2
  const k2 = newKey();
  const u1 = await http('POST', `/api/v1/dids/${did}/keys`, { publicKeyJwk: k2.jwk });
  show('Update - khởi tạo thay khóa', u1);
  const kid2: string = u1.body.didDocument.verificationMethod[0].id;
  const u2 = await http('POST', `/api/v1/did-operations/${u1.body.operationId}/signatures`, {
    signatures: signAll(u1.body, { [kid1]: k1, [kid2]: k2 }),
  });
  show('Update - gửi chữ ký (khóa mới + khóa cũ)', u2);
  evidence.update = { start: u1, complete: u2 };

  // 5. Deactivate (ký bằng khóa hiện hành key-2)
  const d1 = await http('POST', `/api/v1/dids/${did}/deactivate`);
  show('Deactivate - khởi tạo', d1);
  const d2 = await http('POST', `/api/v1/did-operations/${d1.body.operationId}/signatures`, {
    signatures: signAll(d1.body, { [kid2]: k2 }),
  });
  show('Deactivate - gửi chữ ký', d2);
  evidence.deactivate = { start: d1, complete: d2 };

  // 6. DID Document trên mạng sau Deactivate
  const resolved = await http('GET', `/api/v1/dids/${did}`);
  console.log(`\n[Kiểm chứng trên mạng] deactivated = ${resolved.body?.didDocumentMetadata?.deactivated}`);
  evidence.resolved = resolved;

  // 7. Thử nghiệm âm: thay khóa DID đã vô hiệu hóa
  const after = await http('POST', `/api/v1/dids/${did}/keys`, { publicKeyJwk: newKey().jwk });
  show('Thử nghiệm âm - thay khóa sau Deactivate', after);
  evidence.updateAfterDeactivate = after;

  writeFileSync('java-e2e-output.json', JSON.stringify(evidence, null, 2));
  console.log('\nĐã ghi java-e2e-output.json');
}

main().catch((e) => { console.error('LỖI:', e); process.exit(1); });

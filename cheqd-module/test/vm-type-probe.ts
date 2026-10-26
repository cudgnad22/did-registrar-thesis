/**
 * Thử xem @cheqd/sdk 5.5.1 và mạng cheqd cục bộ có nhận các kiểu verificationMethod KHÁC JsonWebKey2020 không.
 * Dùng lại đúng code của module (buildDocSignBytes, broadcast, queryDid); chỉ bỏ qua verifySignatures
 * vì bước đó của ứng dụng chỉ đọc được publicKeyJwk.
 *
 *   OFFLINE=1 node --import tsx test/vm-type-probe.ts           chỉ kiểm tra SDK (không cần mạng, không tốn phí)
 *   node --env-file=.env --import tsx test/vm-type-probe.ts     chạy thật trên localnet (mỗi DID tạo tốn phí create)
 *
 * Mỗi kiểu khóa: (1) SDK kiểm tra đặc tả + mã hóa protobuf, (2) tạo DID, (3) resolve xem mạng trả lại thế nào,
 * (4) cập nhật thêm service bằng cùng khóa, (5) thử ký bằng khóa SAI để chắc mạng có kiểm tra chữ ký,
 * (6) multibase hỏng mà SDK để lọt: xem mạng có tự chặn không.
 */
import { generateKeyPairSync, sign, randomUUID, KeyObject } from 'node:crypto';
import { buildDocSignBytes } from '../src/payload.js';
import { broadcast, queryDid } from '../src/cheqd-client.js';

const OFFLINE = process.env.OFFLINE === '1';
const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
function base58(buf: Buffer): string {
  let n = BigInt('0x' + (buf.toString('hex') || '0')); let s = '';
  while (n > 0n) { s = B58[Number(n % 58n)] + s; n /= 58n; }
  for (const b of buf) { if (b === 0) s = '1' + s; else break; }
  return s;
}

type Kind = 'JsonWebKey2020' | 'Ed25519VerificationKey2020' | 'Ed25519VerificationKey2018';
const CONTEXT: Record<Kind, string> = {
  JsonWebKey2020: 'https://w3id.org/security/suites/jws-2020/v1',
  Ed25519VerificationKey2020: 'https://w3id.org/security/suites/ed25519-2020/v1',
  Ed25519VerificationKey2018: 'https://w3id.org/security/suites/ed25519-2018/v1',
};

function newKey() {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const x = (publicKey.export({ format: 'jwk' }) as any).x as string;
  return { privateKey, x, raw: Buffer.from(x, 'base64url') };
}
function vmFor(kind: Kind, kid: string, did: string, k: ReturnType<typeof newKey>) {
  const vm: any = { id: kid, type: kind, controller: did };
  if (kind === 'JsonWebKey2020') vm.publicKeyJwk = { kty: 'OKP', crv: 'Ed25519', x: k.x };
  if (kind === 'Ed25519VerificationKey2020') vm.publicKeyMultibase = 'z' + base58(Buffer.concat([Buffer.from([0xed, 0x01]), k.raw]));
  if (kind === 'Ed25519VerificationKey2018') vm.publicKeyBase58 = base58(k.raw);
  return vm;
}
const signB64 = (pk: KeyObject, bytes: Uint8Array) => new Uint8Array(sign(null, bytes, pk));
const line = (s = '') => console.log(s);
const short = (e: any) => String(e?.message ?? e).split('\n')[0].slice(0, 300);

async function probe(kind: Kind) {
  line(`\n================ ${kind} ================`);
  const did = `did:cheqd:testnet:${randomUUID()}`;
  const kid = `${did}#key-1`;
  const k = newKey();
  const doc: any = {
    '@context': ['https://www.w3.org/ns/did/v1', CONTEXT[kind]],
    id: did, controller: [did],
    verificationMethod: [vmFor(kind, kid, did, k)],
    authentication: [kid], assertionMethod: [kid],
  };
  line('verificationMethod gửi đi: ' + JSON.stringify(doc.verificationMethod[0]));

  // (1) SDK kiểm tra đặc tả và mã hóa protobuf (đúng hàm module dùng ở bước prepare)
  const v1 = randomUUID();
  let bytes: Uint8Array;
  try { bytes = await buildDocSignBytes('create', doc, v1); line(`(1) SDK nhận DID Document, dữ liệu cần ký ${bytes.length} byte`); }
  catch (e) { line(`(1) SDK TỪ CHỐI: ${short(e)}`); return { kind, sdk: false }; }
  if (OFFLINE) return { kind, sdk: true };

  // (2) tạo DID trên localnet
  const tx = await broadcast('create', doc, v1, [{ verificationMethodId: kid, signature: signB64(k.privateKey, bytes) }]).catch((e) => ({ code: -1, rawLog: short(e) } as any));
  line(`(2) create: code=${tx.code}${tx.code === 0 ? ` height=${tx.height} txHash=${tx.transactionHash}` : ` rawLog=${tx.rawLog}`}`);
  if (tx.code !== 0) return { kind, sdk: true, create: false };

  // (3) resolve: mạng lưu và trả lại khóa dưới dạng nào
  const r = await queryDid(did);
  line('(3) resolve verificationMethod: ' + JSON.stringify(r?.didDocument?.verificationMethod?.[0]));

  // (4) update thêm service, ký bằng cùng khóa
  const doc2 = { ...r!.didDocument, service: [{ id: `${did}#website`, type: 'LinkedDomains', serviceEndpoint: ['https://kma.example.vn'] }] };
  const v2 = randomUUID();
  const bytes2 = await buildDocSignBytes('update', doc2, v2);
  const tx2 = await broadcast('update', doc2, v2, [{ verificationMethodId: kid, signature: signB64(k.privateKey, bytes2) }]).catch((e) => ({ code: -1, rawLog: short(e) } as any));
  line(`(4) update (thêm service, dùng bản resolve làm gốc): code=${tx2.code}${tx2.code === 0 ? '' : ` rawLog=${tx2.rawLog}`}`);

  // (5) ký bằng khóa SAI: mạng phải từ chối
  const wrong = newKey();
  const doc3 = { ...doc2, service: [] };
  const v3 = randomUUID();
  const bytes3 = await buildDocSignBytes('update', doc3, v3);
  const tx3 = await broadcast('update', doc3, v3, [{ verificationMethodId: kid, signature: signB64(wrong.privateKey, bytes3) }]).catch((e) => ({ code: -1, rawLog: short(e) } as any));
  line(`(5) update ký bằng khóa sai: code=${tx3.code} ${tx3.code === 0 ? '<-- KHÔNG ĐÚNG: mạng đã nhận chữ ký sai' : `(bị từ chối như mong đợi) ${String(tx3.rawLog).slice(0, 160)}`}`);
  return { kind, sdk: true, create: true, update: tx2.code === 0, wrongRejected: tx3.code !== 0, did };
}

/** (6) SDK để lọt publicKeyMultibase hỏng (thiếu chữ z): xem mạng có tự chặn không */
async function probeBadMultibase() {
  line('\n================ Ed25519VerificationKey2020, multibase hỏng (thiếu z) ================');
  const did = `did:cheqd:testnet:${randomUUID()}`; const kid = `${did}#key-1`; const k = newKey();
  const vm = vmFor('Ed25519VerificationKey2020', kid, did, k); vm.publicKeyMultibase = vm.publicKeyMultibase.slice(1);
  const doc = { '@context': ['https://www.w3.org/ns/did/v1', CONTEXT.Ed25519VerificationKey2020], id: did, controller: [did], verificationMethod: [vm], authentication: [kid] };
  const v = randomUUID(); let bytes: Uint8Array;
  try { bytes = await buildDocSignBytes('create', doc, v); line('(6) SDK vẫn nhận multibase hỏng'); }
  catch (e) { line(`(6) SDK từ chối: ${short(e)}`); return { kind: 'multibase hỏng', sdk: false }; }
  if (OFFLINE) return { kind: 'multibase hỏng', sdk: true };
  const tx = await broadcast('create', doc, v, [{ verificationMethodId: kid, signature: signB64(k.privateKey, bytes) }]).catch((e) => ({ code: -1, rawLog: short(e) } as any));
  line(`(6) create: code=${tx.code} ${tx.code === 0 ? '<-- mạng NHẬN khóa hỏng' : `(mạng từ chối) ${String(tx.rawLog).slice(0, 200)}`}`);
  return { kind: 'multibase hỏng', sdk: true, create: tx.code === 0 };
}

const kinds: Kind[] = ['JsonWebKey2020', 'Ed25519VerificationKey2020', 'Ed25519VerificationKey2018'];
const results: any[] = [];
for (const kind of kinds) results.push(await probe(kind));
results.push(await probeBadMultibase());
line('\n================ TÓM TẮT ================');
console.table(results);
process.exit(0);

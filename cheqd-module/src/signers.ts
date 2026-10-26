/**
 * Xác định khóa nào phải ký và kiểm tra chữ ký trước khi gửi giao dịch.
 *
 * Quy tắc rút ra từ @cheqd/sdk 5.5.1 (validateAuthenticationAgainstSignaturesKeyRotation)
 * và đã kiểm chứng trên localnet:
 *   create     : các khóa trong authentication của DID Document mới
 *   update     : khóa được thêm (theo bản mới) + khóa bị gỡ (theo bản hiện hành);
 *                nếu không đổi khóa: mọi khóa authentication của bản mới
 *   deactivate : các khóa trong authentication của DID Document hiện hành
 * Key rotation (giữ nguyên id, đổi vật liệu khóa) không được hỗ trợ: ứng dụng dùng key replacement.
 *
 * Khóa Ed25519 được nhận ở hai dạng (mạng cheqd lưu nguyên dạng được gửi lên):
 *   JsonWebKey2020             publicKeyJwk { kty: OKP, crv: Ed25519, x: base64url(32 byte) }
 *   Ed25519VerificationKey2020 publicKeyMultibase "z" + base58btc(0xed 0x01 + 32 byte)
 */
import { createPublicKey, verify } from 'node:crypto';
import { ModuleError, Operation } from './config.js';

const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
function base58Decode(s: string): Buffer | null {
  let n = 0n;
  for (const c of s) { const i = B58.indexOf(c); if (i < 0) return null; n = n * 58n + BigInt(i); }
  let hex = n === 0n ? '' : n.toString(16); if (hex.length % 2) hex = '0' + hex;
  const lead = s.match(/^1*/)![0].length;
  return Buffer.concat([Buffer.alloc(lead), Buffer.from(hex, 'hex')]);
}

/**
 * 32 byte khóa công khai Ed25519 của một Verification Method, hoặc null nếu kiểu/dạng khóa chưa hỗ trợ.
 * Dùng chung cho xác minh chữ ký, so sánh khóa giữa hai phiên bản và kiểm tra sớm ở bước prepare.
 */
export function ed25519Raw(vm: any): Buffer | null {
  if (vm?.type === 'JsonWebKey2020' && vm.publicKeyJwk?.kty === 'OKP' && vm.publicKeyJwk?.crv === 'Ed25519' && typeof vm.publicKeyJwk.x === 'string') {
    const raw = Buffer.from(vm.publicKeyJwk.x, 'base64url');
    return raw.length === 32 ? raw : null;
  }
  if (vm?.type === 'Ed25519VerificationKey2020' && typeof vm.publicKeyMultibase === 'string' && vm.publicKeyMultibase.startsWith('z')) {
    const bytes = base58Decode(vm.publicKeyMultibase.slice(1));
    if (bytes && bytes.length === 34 && bytes[0] === 0xed && bytes[1] === 0x01) return bytes.subarray(2);
  }
  return null;
}

/** Mọi Verification Method của DID Document mới phải đọc được khóa (chặn trước khi Client ký, thay vì để mạng trả 1205) */
export function assertKeysReadable(doc: any) {
  for (const vm of doc?.verificationMethod ?? []) {
    if (!ed25519Raw(vm)) {
      throw new ModuleError(422, 'UNSUPPORTED_KEY',
        `${vm?.id}: chỉ hỗ trợ khóa Ed25519 kiểu JsonWebKey2020 (publicKeyJwk) hoặc Ed25519VerificationKey2020 (publicKeyMultibase hợp lệ)`);
    }
  }
}

const authIds = (doc: any): string[] =>
  (doc?.authentication ?? []).map((a: any) => (typeof a === 'string' ? a : a.id));

export function requiredSigners(operation: Operation, newDoc: any, currentDoc: any): string[] {
  if (operation === 'create') return [...new Set(authIds(newDoc))];
  if (operation === 'deactivate') return [...new Set(authIds(currentDoc))];

  // update
  // So vật liệu khóa theo byte: cùng một khóa viết ở dạng JWK hay multibase vẫn là một khóa
  const material = (vm: any) => ed25519Raw(vm)?.toString('hex') ?? JSON.stringify(vm.publicKeyJwk ?? vm.publicKeyMultibase ?? null);
  const rotated = (newDoc.verificationMethod ?? []).some((vm: any) =>
    (currentDoc.verificationMethod ?? []).some((pvm: any) => pvm.id === vm.id && material(pvm) !== material(vm)));
  if (rotated) {
    throw new ModuleError(422, 'KEY_ROTATION_NOT_SUPPORTED',
      'Không hỗ trợ đổi khóa khi giữ nguyên id Verification Method; hãy dùng id mới (key replacement)');
  }
  const current = new Set(authIds(currentDoc));
  const next = new Set(authIds(newDoc));
  const removed = [...current].filter((id) => !next.has(id));
  const added = [...next].filter((id) => !current.has(id));
  if (added.length && removed.length) return [...added, ...removed]; // key replacement
  return [...new Set([...next, ...removed])];                          // cập nhật thông thường
}

/** Tìm khóa công khai theo id: ưu tiên DID Document mới, sau đó bản hiện hành (khóa cũ bị gỡ); trả về dạng JWK để xác minh */
export function findPublicJwk(id: string, newDoc: any, currentDoc: any) {
  const vm = [...(newDoc?.verificationMethod ?? []), ...(currentDoc?.verificationMethod ?? [])]
    .find((v: any) => v.id === id);
  const raw = ed25519Raw(vm);
  if (!raw) {
    throw new ModuleError(422, 'UNSUPPORTED_KEY',
      `${id}: không đọc được khóa Ed25519 (chỉ hỗ trợ JsonWebKey2020/publicKeyJwk và Ed25519VerificationKey2020/publicKeyMultibase)`);
  }
  return { kty: 'OKP', crv: 'Ed25519', x: raw.toString('base64url') };
}

/**
 * Kiểm tra: đúng và đủ các khóa bắt buộc (mỗi khóa đúng một chữ ký), và từng chữ ký hợp lệ.
 * Chữ ký sai bị từ chối ở đây để không tốn phí giao dịch.
 */
export function verifySignatures(
  signBytes: Uint8Array,
  signatures: { verificationMethodId: string; signature: Uint8Array }[],
  required: string[],
  newDoc: any,
  currentDoc: any,
) {
  const provided = signatures.map((s) => s.verificationMethodId);
  const missing = required.filter((id) => !provided.includes(id));
  const extra = provided.filter((id) => !required.includes(id));
  const duplicated = provided.filter((id, i) => provided.indexOf(id) !== i);
  if (missing.length || extra.length || duplicated.length) {
    throw new ModuleError(400, 'SIGNERS_MISMATCH',
      `Chữ ký không khớp yêu cầu. Thiếu: [${missing}] | Thừa: [${extra}] | Trùng: [${duplicated}]`);
  }
  for (const s of signatures) {
    const pub = createPublicKey({ key: findPublicJwk(s.verificationMethodId, newDoc, currentDoc) as any, format: 'jwk' });
    if (!verify(null, signBytes, pub, s.signature)) {
      throw new ModuleError(400, 'SIGNATURE_INVALID', `Chữ ký của ${s.verificationMethodId} không hợp lệ`);
    }
  }
}

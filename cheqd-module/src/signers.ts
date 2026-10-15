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
 */
import { createPublicKey, verify } from 'node:crypto';
import { ModuleError, Operation } from './config.js';

const authIds = (doc: any): string[] =>
  (doc?.authentication ?? []).map((a: any) => (typeof a === 'string' ? a : a.id));

export function requiredSigners(operation: Operation, newDoc: any, currentDoc: any): string[] {
  if (operation === 'create') return [...new Set(authIds(newDoc))];
  if (operation === 'deactivate') return [...new Set(authIds(currentDoc))];

  // update
  const rotated = (newDoc.verificationMethod ?? []).some((vm: any) =>
    (currentDoc.verificationMethod ?? []).some((pvm: any) =>
      pvm.id === vm.id && JSON.stringify(pvm.publicKeyJwk ?? null) !== JSON.stringify(vm.publicKeyJwk ?? null)));
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

/** Tìm khóa công khai theo id: ưu tiên DID Document mới, sau đó bản hiện hành (khóa cũ bị gỡ) */
function findPublicJwk(id: string, newDoc: any, currentDoc: any) {
  const vm = [...(newDoc?.verificationMethod ?? []), ...(currentDoc?.verificationMethod ?? [])]
    .find((v: any) => v.id === id);
  if (!vm?.publicKeyJwk || vm.publicKeyJwk.crv !== 'Ed25519') {
    throw new ModuleError(422, 'UNSUPPORTED_KEY', `Không tìm thấy khóa Ed25519 dạng JWK cho ${id}`);
  }
  const { kty, crv, x } = vm.publicKeyJwk;
  return { kty, crv, x };
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

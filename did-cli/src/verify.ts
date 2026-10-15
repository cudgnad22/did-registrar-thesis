/**
 * Kiểm tra phía Client TRƯỚC KHI KÝ.
 * Mục đích: không ký mù. Ứng dụng Registrar có thể sai sót hoặc bị chiếm quyền và chèn
 * khóa lạ vào DID Document; Client chỉ ký khi mọi thứ khớp với điều mình yêu cầu.
 */

export interface CheckResult {
  ok: boolean;
  errors: string[];
}

const sameSet = (a: string[], b: string[]) =>
  a.length === b.length && a.every((x) => b.includes(x));

/**
 * DID Document phải:
 *  - đúng DID, controller chỉ gồm chính DID đó;
 *  - chỉ chứa ĐÚNG các khóa công khai Client mong đợi (không thừa, không thiếu);
 *  - authentication chỉ tham chiếu tới các khóa đó;
 *  - không có service hoặc quan hệ xác thực khác mà Client không yêu cầu.
 */
export function checkDidDocument(doc: any, did: string, expectedX: string[]): CheckResult {
  const errors: string[] = [];
  if (!doc) return { ok: false, errors: ['Không nhận được DID Document để đối chiếu'] };

  if (doc.id !== did) errors.push(`id của DID Document (${doc.id}) khác DID (${did})`);
  if (!Array.isArray(doc.controller) || !sameSet(doc.controller, [did])) {
    errors.push(`controller phải chỉ gồm ${did}, nhận được ${JSON.stringify(doc.controller)}`);
  }

  const vms: any[] = doc.verificationMethod ?? [];
  const xs = vms.map((vm) => vm?.publicKeyJwk?.x);
  if (!sameSet(xs, expectedX)) {
    errors.push(`Khóa công khai trong DID Document ${JSON.stringify(xs)} không khớp khóa của Client ${JSON.stringify(expectedX)}`);
  }
  for (const vm of vms) {
    if (vm.controller !== did) errors.push(`${vm.id}: controller khác ${did}`);
    if (vm.publicKeyJwk?.crv !== 'Ed25519') errors.push(`${vm.id}: không phải khóa Ed25519`);
  }

  const vmIds = vms.map((vm) => vm.id);
  const auth: string[] = (doc.authentication ?? []).map((a: any) => (typeof a === 'string' ? a : a.id));
  if (!sameSet(auth, vmIds)) {
    errors.push(`authentication ${JSON.stringify(auth)} không khớp danh sách khóa ${JSON.stringify(vmIds)}`);
  }

  for (const field of ['service', 'keyAgreement', 'capabilityInvocation', 'capabilityDelegation', 'alsoKnownAs']) {
    if (Array.isArray(doc[field]) && doc[field].length > 0) {
      errors.push(`DID Document có trường ${field} mà Client không yêu cầu`);
    }
  }
  return { ok: errors.length === 0, errors };
}

/** Danh sách khóa được yêu cầu ký phải đúng như Client dự đoán theo quy tắc của did:cheqd */
export function checkRequiredSigners(required: string[], expected: string[]): CheckResult {
  return sameSet(required, expected)
    ? { ok: true, errors: [] }
    : { ok: false, errors: [`Yêu cầu ký bằng ${JSON.stringify(required)}, Client dự kiến ${JSON.stringify(expected)}`] };
}

/**
 * Kiểm tra SƠ BỘ dữ liệu cần ký: phải chứa DID và các khóa công khai liên quan.
 * Đây không phải kiểm tra đầy đủ: muốn chắc chắn payload đúng là mã hóa của DID Document
 * đã đối chiếu, Client phải tự mã hóa lại bằng protobuf của cheqd (hướng phát triển).
 */
export function checkPayloadContains(payloadB64: string, mustContain: string[]): CheckResult {
  const bytes = Buffer.from(payloadB64, 'base64').toString('latin1');
  const missing = mustContain.filter((s) => !bytes.includes(s));
  return missing.length === 0
    ? { ok: true, errors: [] }
    : { ok: false, errors: missing.map((s) => `Dữ liệu cần ký không chứa ${s}`) };
}

export function merge(...results: CheckResult[]): CheckResult {
  const errors = results.flatMap((r) => r.errors);
  return { ok: errors.length === 0, errors };
}

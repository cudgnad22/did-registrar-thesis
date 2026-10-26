/**
 * Kiểm tra phía Client TRƯỚC KHI KÝ.
 * Mục đích: không ký mù. Ứng dụng Registrar có thể sai sót hoặc bị chiếm quyền và chèn
 * khóa lạ vào DID Document; Client chỉ ký khi mọi thứ khớp với điều mình yêu cầu.
 */

import { keyX } from './keys.ts';

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
 *  - service và alsoKnownAs giữ nguyên như bản hiện hành trên mạng (`current`; tạo DID thì phải trống),
 *    trừ khi Client đang sửa service (`allowServiceChange`): khi đó từng service phải đúng dạng;
 *  - không có quan hệ xác thực khác mà Client không yêu cầu.
 */
export function checkDidDocument(doc: any, did: string, expectedX: string[], current: any = null, allowServiceChange = false): CheckResult {
  const errors: string[] = [];
  if (!doc) return { ok: false, errors: ['Không nhận được DID Document để đối chiếu'] };

  if (doc.id !== did) errors.push(`id của DID Document (${doc.id}) khác DID (${did})`);
  if (!Array.isArray(doc.controller) || !sameSet(doc.controller, [did])) {
    errors.push(`controller phải chỉ gồm ${did}, nhận được ${JSON.stringify(doc.controller)}`);
  }

  const vms: any[] = doc.verificationMethod ?? [];
  const xs = vms.map((vm) => keyX(vm));
  if (!sameSet(xs, expectedX)) {
    errors.push(`Khóa công khai trong DID Document ${JSON.stringify(xs)} không khớp khóa của Client ${JSON.stringify(expectedX)}`);
  }
  for (const vm of vms) {
    if (vm.controller !== did) errors.push(`${vm.id}: controller khác ${did}`);
    if (!keyX(vm)) errors.push(`${vm.id}: không phải khóa Ed25519 kiểu JsonWebKey2020 hoặc Ed25519VerificationKey2020`);
  }

  const vmIds = vms.map((vm) => vm.id);
  const auth: string[] = (doc.authentication ?? []).map((a: any) => (typeof a === 'string' ? a : a.id));
  if (!sameSet(auth, vmIds)) {
    errors.push(`authentication ${JSON.stringify(auth)} không khớp danh sách khóa ${JSON.stringify(vmIds)}`);
  }

  for (const field of ['keyAgreement', 'capabilityInvocation', 'capabilityDelegation']) {
    if (Array.isArray(doc[field]) && doc[field].length > 0) {
      errors.push(`DID Document có trường ${field} mà Client không yêu cầu`);
    }
  }

  if (allowServiceChange) {
    errors.push(...checkServiceShape(doc, did));
  } else if (JSON.stringify(normServices(doc)) !== JSON.stringify(normServices(current))) {
    errors.push(current
      ? 'service trong DID Document khác bản hiện hành trên mạng, trong khi thao tác này không được đổi service'
      : 'DID Document có trường service mà Client không yêu cầu');
  }
  if (JSON.stringify(doc.alsoKnownAs ?? []) !== JSON.stringify(current?.alsoKnownAs ?? [])) {
    errors.push('alsoKnownAs trong DID Document khác bản hiện hành trên mạng');
  }
  return { ok: errors.length === 0, errors };
}

// ------------------------------------------------------------------ service

const absId = (id: any, did: string) => (typeof id === 'string' && id.startsWith('#') ? did + id : id);
const endpointsOf = (s: any): any[] => (Array.isArray(s?.serviceEndpoint) ? s.serviceEndpoint : s?.serviceEndpoint == null ? [] : [s.serviceEndpoint]);

/** Sắp xếp khóa của object để so sánh hai bản JSON không phụ thuộc thứ tự trường */
function canon(v: any): any {
  if (Array.isArray(v)) return v.map(canon);
  if (v && typeof v === 'object') return Object.fromEntries(Object.keys(v).sort().map((k) => [k, canon(v[k])]));
  return v;
}

/** Service ở dạng chuẩn để so sánh: id đầy đủ, serviceEndpoint luôn là mảng, sắp theo id */
export function normServices(doc: any): any[] {
  const did = doc?.id;
  return (doc?.service ?? [])
    .map((s: any) => canon({ ...s, id: absId(s?.id, did), serviceEndpoint: endpointsOf(s) }))
    .sort((a: any, b: any) => String(a.id).localeCompare(String(b.id)));
}

export interface ServiceDiff { added: any[]; removed: any[]; changed: { before: any; after: any }[] }

/** So sánh service của bản mới với bản hiện hành trên mạng */
export function diffServices(current: any, next: any): ServiceDiff {
  const before = new Map(normServices(current).map((s) => [s.id, s]));
  const after = new Map(normServices(next).map((s) => [s.id, s]));
  return {
    added: [...after.values()].filter((s) => !before.has(s.id)),
    removed: [...before.values()].filter((s) => !after.has(s.id)),
    changed: [...after.values()].filter((s) => before.has(s.id) && JSON.stringify(s) !== JSON.stringify(before.get(s.id)))
      .map((s) => ({ before: before.get(s.id), after: s })),
  };
}

function checkServiceShape(doc: any, did: string): string[] {
  const errors: string[] = [];
  const seen = new Set<string>();
  for (const s of normServices(doc)) {
    const id = String(s.id);
    if (!id.startsWith(did + '#') || !/^[A-Za-z0-9._~-]+$/.test(id.slice(did.length + 1))) errors.push(`service ${id}: id phải có dạng ${did}#<tên>`);
    if (seen.has(id)) errors.push(`service ${id}: trùng id`);
    seen.add(id);
    if (typeof s.type !== 'string' || !s.type.trim()) errors.push(`service ${id}: thiếu type`);
    const eps = s.serviceEndpoint;
    if (!eps.length || eps.some((e: any) => typeof e !== 'string' || !e.trim())) errors.push(`service ${id}: serviceEndpoint phải là chuỗi không rỗng`);
  }
  return errors;
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

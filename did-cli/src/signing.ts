/**
 * Phân tích yêu cầu ký do Registrar trả về, đối chiếu với kho khóa, và ký.
 * Dùng chung cho lệnh `sign` (dòng lệnh) và cho agent ký (HTTP).
 *
 * Bộ ký KHÔNG tin thông tin do Registrar hay trang web khai: loại thao tác, DID và danh sách khóa
 * dự kiến đều được suy ra từ nội dung cần ký và từ kho khóa của chính Client.
 */
import { Wallet, frag } from './wallet.ts';
import type { StoredKey } from './wallet.ts';
import { signerFor } from './signer.ts';
import { createPublicKey, verify } from 'node:crypto';
import { checkDidDocument, checkRequiredSigners, checkPayloadContains } from './verify.ts';

export type Operation = 'create' | 'update' | 'deactivate';

export interface CheckItem { title: string; errors: string[] }

export interface Analysis {
  ok: boolean;
  jobId: string;
  did: string;
  operation: Operation | null;
  endpoint: string | null;
  newKey?: StoredKey;
  newKid?: string;
  expectedSigners: string[];
  requests: Record<string, any>;
  checks: CheckItem[];
  summary: string[];
}

export const ENDPOINT: Record<Operation, string> = {
  create: '/1.0/create?method=cheqd',
  update: '/1.0/update',
  deactivate: '/1.0/deactivate',
};

const sameSet = (a: string[], b: string[]) => a.length === b.length && a.every((x) => b.includes(x)) && b.every((x) => a.includes(x));

/** `response` là phản hồi của lần gọi thứ nhất: { jobId, didState: { state: action, signingRequest } } */
/**
 * Trước khi phân tích yêu cầu ký, đọc trạng thái DID trên mạng để kho khóa phản ánh đúng khóa hiện hành
 * (ví dụ lần đối chiếu sau thao tác trước bị lỗi kết nối). Trả về thông báo lỗi nếu không đọc được.
 */
export async function refreshFromLedger(response: any, wallet: Wallet, resolve: (did: string) => Promise<any>): Promise<string | null> {
  const payload = (Object.values(response?.didState?.signingRequest ?? {})[0] as any)?.payload ?? {};
  const did = payload?.didDocument?.id ?? payload?.id;
  if (!did || !wallet.getDid(did)) return null;
  try { await syncDid(wallet, did, resolve); return null; }
  catch (e: any) { return e?.message ?? String(e); }
}

export function analyze(response: any, wallet: Wallet, keyRef?: string, syncError?: string | null): Analysis {
  const st = response?.didState;
  const fail = (msg: string): Analysis => ({
    ok: false, jobId: response?.jobId ?? '', did: st?.did ?? '', operation: null, endpoint: null,
    expectedSigners: [], requests: {}, checks: [{ title: 'Phản hồi là yêu cầu ký hợp lệ', errors: [msg] }], summary: [],
  });
  if (!response?.jobId) return fail('Thiếu jobId');
  if (st?.state !== 'action' || st?.action !== 'signPayload' || !st?.signingRequest) {
    return fail(`didState không phải yêu cầu ký (state = ${st?.state}, action = ${st?.action})`);
  }
  const requests: Record<string, any> = st.signingRequest;
  const list = Object.values(requests);
  if (list.length === 0) return fail('Không có signingRequest nào');
  const payload = list[0]?.payload ?? {};
  const checks: CheckItem[] = [];

  let did: string;
  let operation: Operation;
  let newKey: StoredKey | undefined;
  let newKid: string | undefined;
  let expectedSigners: string[];
  let expectedX: string[] | null = null;

  if (payload.didDocument) {
    const doc = payload.didDocument;
    did = doc.id;
    const vms: any[] = doc.verificationMethod ?? [];
    // Khóa mới phải là khóa do chính Client sinh và chưa ACTIVE
    let vm: any;
    if (keyRef) {
      newKey = wallet.findByRef(keyRef);
      vm = newKey && vms.find((v) => v?.publicKeyJwk?.x === newKey!.publicJwk.x);
    } else {
      for (const v of vms) {
        const k = wallet.findByX(v?.publicKeyJwk?.x);
        if (k && k.status !== 'ACTIVE') { newKey = k; vm = v; break; }
      }
    }
    if (!newKey || !vm) {
      return { ...fail('DID Document không chứa khóa mới nào do bộ ký này sinh ra'), did };
    }
    newKid = vm.id;
    const record = wallet.getDid(did);
    if (record?.status === 'DEACTIVATED') return { ...fail(`DID ${did} đã bị vô hiệu hóa`), did };
    // Thay khóa nếu kho đã có khóa khác của DID này (chưa bị thay); ngược lại là tạo DID
    const current = currentKeys(record, newKey, !!syncError);
    const others = (record?.keys ?? []).filter((k) => k !== newKey && k.status !== 'REPLACED');
    operation = current.length || others.length ? 'update' : 'create';
    if (operation === 'update' && current.length === 0) {
      return { ...fail('Kho khóa không có khóa ACTIVE của DID này nên không ký thay khóa được'), did };
    }
    expectedSigners = [newKid!, ...current.map((k) => k.kid!)];
    expectedX = [newKey.publicJwk.x];
  } else {
    did = payload.id;
    operation = 'deactivate';
    const record = wallet.getDid(did);
    if (!record) return { ...fail(`Kho khóa không có DID ${did}`), did };
    if (record.status === 'DEACTIVATED') return { ...fail(`DID ${did} đã bị vô hiệu hóa`), did };
    expectedSigners = currentKeys(record, undefined, !!syncError).map((k) => k.kid!);
    if (expectedSigners.length === 0) return { ...fail('Kho khóa không có khóa ACTIVE của DID này'), did };
  }

  // 0. Kho khóa phải phản ánh đúng mạng khi DID đã có trong kho
  const rec = wallet.getDid(did);
  if (syncError && rec && (rec.status === 'PENDING' || rec.keys.some((k) => k.status === 'PENDING' && k !== newKey))) {
    checks.push({ title: 'Trạng thái khóa trong kho đã được đối chiếu với mạng', errors: [
      `Không đọc được DID từ Registrar (${syncError}).`,
      'Kho khóa còn khóa ở trạng thái PENDING nên không xác định chắc khóa hiện hành. Kiểm tra DID_API_URL rồi chạy: did-cli sync <did>'] });
  }

  // 1. Cùng một dữ liệu cần ký, đúng thuật toán
  const e1: string[] = [];
  if (new Set(list.map((r: any) => r.serializedPayload)).size !== 1) e1.push('Các signingRequest không cùng một serializedPayload');
  if (list.some((r: any) => r.alg !== 'EdDSA')) e1.push('Có signingRequest không dùng thuật toán EdDSA');
  checks.push({ title: 'Mọi signingRequest dùng chung một serializedPayload, thuật toán EdDSA', errors: e1 });

  // 2. Đúng DID, đúng loại thao tác mà Registrar khai
  const e2: string[] = [];
  if (st.did !== did) e2.push(`didState.did (${st.did}) khác DID trong dữ liệu cần ký (${did})`);
  const claimed = response?.didRegistrationMetadata?.operation;
  if (claimed && claimed !== operation) e2.push(`Registrar khai operation = ${claimed}, nhưng nội dung cần ký là ${operation}`);
  checks.push({ title: `Thao tác ${operation} trên đúng DID ${did}`, errors: e2 });

  // 3. Danh sách khóa phải ký đúng quy tắc của did:cheqd
  const kids = list.map((r: any) => r.kid);
  checks.push({
    title: `Khóa phải ký: ${expectedSigners.map(frag).join(', ')}` + (operation === 'update' ? ' (khóa mới và khóa bị gỡ)' : ''),
    errors: checkRequiredSigners(kids, expectedSigners).errors,
  });

  // 4. DID Document chỉ chứa khóa của Client
  if (expectedX) {
    checks.push({ title: 'DID Document chỉ chứa khóa của Client; id, controller và authentication đúng',
      errors: checkDidDocument(payload.didDocument, did, expectedX).errors });
  }

  // 5. Kiểm tra sơ bộ dãy byte cần ký
  checks.push({ title: 'serializedPayload chứa DID' + (expectedX ? ' và khóa công khai mới' : '') + ' (kiểm tra sơ bộ)',
    errors: checkPayloadContains(list[0].serializedPayload ?? '', [did, ...(expectedX ?? [])]).errors });

  // 6. Có đủ khóa bí mật để ký
  const missing = kids.filter((kid: string) => kid !== newKid && !wallet.findByKid(kid));
  checks.push({ title: 'Kho khóa có đủ khóa cho mọi kid được yêu cầu', errors: missing.map((k: string) => `Không có khóa ${k}`) });

  const summary =
    operation === 'create' ? [`TẠO DID ${did}`, `Khóa: ${frag(newKid)} (x = ${newKey!.publicJwk.x})`]
    : operation === 'update' ? [`THAY KHÓA của ${did}`, `Gỡ: ${expectedSigners.slice(1).map(frag).join(', ')}`, `Thêm: ${frag(newKid)} (x = ${newKey!.publicJwk.x})`]
    : [`VÔ HIỆU HÓA VĨNH VIỄN ${did}`, 'DID đã vô hiệu hóa không thể cập nhật hay kích hoạt lại', `Ký bằng: ${expectedSigners.map(frag).join(', ')}`];

  const ok = checks.every((c) => c.errors.length === 0) && sameSet(kids, expectedSigners);
  return { ok, jobId: response.jobId, did, operation, endpoint: ENDPOINT[operation], newKey, newKid, expectedSigners, requests, checks, summary };
}

/** Khóa hiện hành của DID theo kho khóa: ACTIVE; nếu không đọc được mạng thì tính cả khóa PENDING (đã cảnh báo) */
function currentKeys(record: ReturnType<Wallet['getDid']>, exclude: StoredKey | undefined, syncFailed: boolean): StoredKey[] {
  const keys = (record?.keys ?? []).filter((k) => k !== exclude);
  const active = keys.filter((k) => k.status === 'ACTIVE');
  return active.length || !syncFailed ? active : keys.filter((k) => k.status === 'PENDING');
}

/** Ký mọi signingRequest. Khóa mới được lưu ở trạng thái PENDING trước khi trả chữ ký. */
export async function signAll(a: Analysis, wallet: Wallet, label?: string) {
  if (!a.ok) throw new Error('Đối chiếu không đạt, không ký');
  if (a.newKey && a.newKid) wallet.attachPending(a.did, a.newKid, a.newKey, label);
  const signingResponse: Record<string, any> = {};
  for (const [id, r] of Object.entries(a.requests)) {
    const key = r.kid === a.newKid ? a.newKey! : wallet.findByKid(r.kid)!;
    const bytes = new Uint8Array(Buffer.from(r.serializedPayload, 'base64'));
    const sig = await signerFor(key.kms).sign(key, bytes);
    // Tự kiểm tra chữ ký bằng khóa công khai trước khi gửi đi (bắt lỗi của bộ ký ngoài, ký nhầm khóa...)
    const pub = createPublicKey({ key: key.publicJwk as any, format: 'jwk' });
    if (sig.length !== 64 || !verify(null, bytes, pub, sig)) {
      throw new Error(`Chữ ký do bộ ký ${key.kms} tạo cho ${r.kid} không khớp khóa công khai trong kho`);
    }
    signingResponse[id] = { signature: Buffer.from(sig).toString('base64'), kid: r.kid, alg: 'EdDSA' };
  }
  return { jobId: a.jobId, secret: { signingResponse } };
}

/** Đọc DID trên mạng (qua Registrar) và cập nhật trạng thái khóa trong kho */
export async function syncDid(wallet: Wallet, did: string, resolve: (did: string) => Promise<any>) {
  try {
    const r = await resolve(did);
    return wallet.applyLedgerState(did, r?.didDocument ?? null, !!r?.didDocumentMetadata?.deactivated);
  } catch (e: any) {
    if (e?.status === 404) return ['DID chưa có trên mạng; khóa đang chờ giữ nguyên PENDING'];
    throw e;
  }
}

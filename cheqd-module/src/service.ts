/**
 * Nghiệp vụ của module: prepare và submit. Tương đương một @Service bên Java.
 * Module KHÔNG lưu trạng thái: Java giữ didDocument, versionId giữa hai bước.
 */
import { randomUUID } from 'node:crypto';
import { ModuleError, Operation } from './config.js';
import { queryDid, broadcast } from './cheqd-client.js';
import { buildDocSignBytes, buildDeactivateSignBytes } from './payload.js';
import { requiredSigners, verifySignatures, assertKeysReadable, findPublicJwk } from './signers.js';

const b64 = (u: Uint8Array) => Buffer.from(u).toString('base64');

type PrepareRequest = { operation: Operation; did: string; didDocument?: any };
type SubmitRequest = PrepareRequest & {
  versionId: string;
  signatures: { verificationMethodId: string; signature: string }[]; // chữ ký dạng base64
};

/** Kiểm tra đầu vào và đọc DID Document hiện hành (nếu thao tác cần) */
async function loadContext(req: PrepareRequest) {
  const { operation, did, didDocument } = req;
  if (!['create', 'update', 'deactivate'].includes(operation)) {
    throw new ModuleError(400, 'INVALID_OPERATION', `operation không hợp lệ: ${operation}`);
  }
  if (!did) throw new ModuleError(400, 'INVALID_REQUEST', 'Thiếu did');
  if (operation !== 'deactivate') {
    if (!didDocument) throw new ModuleError(400, 'INVALID_REQUEST', 'Thiếu didDocument');
    if (didDocument.id !== did) throw new ModuleError(400, 'INVALID_REQUEST', 'didDocument.id không trùng với did');
  }

  const current = await queryDid(did);
  if (operation === 'create') {
    if (current) throw new ModuleError(409, 'DID_ALREADY_EXISTS', `${did} đã tồn tại`);
    return { currentDoc: null };
  }
  if (!current) throw new ModuleError(404, 'DID_NOT_FOUND', `${did} không tồn tại`);
  if (current.didDocumentMetadata?.deactivated) {
    throw new ModuleError(409, 'DID_DEACTIVATED', `${did} đã bị vô hiệu hóa`);
  }
  return { currentDoc: current.didDocument };
}

async function signBytesFor(req: PrepareRequest, versionId: string): Promise<Uint8Array> {
  return req.operation === 'deactivate'
    ? buildDeactivateSignBytes(req.did, versionId)
    : buildDocSignBytes(req.operation, req.didDocument, versionId);
}

/** Bước 1: tạo dữ liệu cần ký và danh sách khóa phải ký */
export async function prepare(req: PrepareRequest) {
  const { currentDoc } = await loadContext(req);
  if (req.operation !== 'deactivate') assertKeysReadable(req.didDocument);
  const versionId = randomUUID();
  const signBytes = await signBytesFor(req, versionId);
  const signers = requiredSigners(req.operation, req.didDocument, currentDoc);
  // Kiểm tra sớm: mọi khóa phải ký (kể cả khóa của bản hiện hành) đều đọc được, để Client không ký vô ích
  for (const id of signers) findPublicJwk(id, req.didDocument, currentDoc);
  return { versionId, signBytes: b64(signBytes), requiredSigners: signers };
}

/** Bước 2: dựng lại dữ liệu cần ký, kiểm tra chữ ký, gửi giao dịch */
export async function submit(req: SubmitRequest) {
  if (!req.versionId) throw new ModuleError(400, 'INVALID_REQUEST', 'Thiếu versionId');
  if (!Array.isArray(req.signatures) || !req.signatures.length) {
    throw new ModuleError(400, 'INVALID_REQUEST', 'Thiếu signatures');
  }
  // Đọc lại trạng thái hiện hành: DID có thể đã thay đổi giữa prepare và submit
  const { currentDoc } = await loadContext(req);

  // Mã hóa tất định => cùng didDocument + versionId cho ra đúng byte Client đã ký
  const signBytes = await signBytesFor(req, req.versionId);
  const signatures = req.signatures.map((s) => ({
    verificationMethodId: s.verificationMethodId,
    signature: new Uint8Array(Buffer.from(s.signature, 'base64')),
  }));
  const required = requiredSigners(req.operation, req.didDocument, currentDoc);
  verifySignatures(signBytes, signatures, required, req.didDocument, currentDoc);

  // Deactivate: SDK dùng DID Document hiện hành để đối chiếu authentication
  const didPayload = req.operation === 'deactivate' ? currentDoc : req.didDocument;
  const started = Date.now();
  const tx = await broadcast(req.operation, didPayload, req.versionId, signatures);
  const elapsedMs = Date.now() - started;

  const result: any = {
    success: tx.code === 0,
    code: tx.code,           // 0: thành công; 1100: chữ ký sai; 1207: DID đã vô hiệu hóa ...
    txHash: tx.transactionHash,
    height: tx.height,
    rawLog: tx.rawLog ?? '',
    elapsedMs,
  };
  if (tx.code === 0) {
    const after = await queryDid(req.did);
    result.didDocument = after?.didDocument ?? null;
    result.didDocumentMetadata = after?.didDocumentMetadata ?? null;
  }
  return result;
}

/** Đọc DID Document từ mạng (Java dùng để kiểm chứng/đồng bộ trạng thái) */
export async function resolve(did: string) {
  const found = await queryDid(did);
  if (!found) throw new ModuleError(404, 'DID_NOT_FOUND', `${did} không tồn tại`);
  return found;
}

// Mock của ứng dụng Java + module did:cheqd, CHỈ dùng để kiểm thử giao diện.
// Cùng hợp đồng với DidRegistrarService/DifExceptionHandler/DidRestController; "mạng" là bộ nhớ.
// MODE=evil: chèn khóa lạ #key-99 vào DID Document (Client phải từ chối ký).
// MODE=wait: lần gọi thứ hai trả state=wait, giao dịch hoàn tất sau 4 giây.
// MODE=evilsvc: lén thêm service #evil vào DID Document khi cập nhật (Client phải thấy và từ chối).
import http from 'node:http';
import { readFile } from 'node:fs/promises';
import { join, extname, normalize } from 'node:path';
import { randomUUID, createPublicKey, verify, createHash } from 'node:crypto';

const STATIC = process.argv[2];
const PORT = Number(process.env.PORT || 8085);
const MODE = process.env.MODE || 'normal';
const PREFIX = 'did:cheqd:testnet:';
const ledger = new Map();   // did -> { didDocument, didDocumentMetadata }
const ops = new Map();      // jobId -> operation record
const labels = new Map();   // did -> label (bảng did của ứng dụng)
const owners = new Map();   // did -> thông tin người sở hữu
let height = 337000;

const json = (res, status, body) => { res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8' }); res.end(JSON.stringify(body)); };
const failed = (status, reason, description, did = null) => ({ status, body: { jobId: null, didState: { state: 'failed', did, reason, description }, didRegistrationMetadata: {}, didDocumentMetadata: {} } });
class DifErr extends Error { constructor(status, reason, msg, did) { super(msg); Object.assign(this, { status, reason, did }); } }
const authIds = (d) => (d?.authentication ?? []).map((a) => (typeof a === 'string' ? a : a.id));
const abs = (id, did) => (id.startsWith('#') ? did + id : id);
// Khóa Ed25519: JsonWebKey2020 (publicKeyJwk) hoặc Ed25519VerificationKey2020 (publicKeyMultibase), giống signers.ts của module
const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
function b58decode(s) { let n = 0n; for (const c of s) { const i = B58.indexOf(c); if (i < 0) return null; n = n * 58n + BigInt(i); } let h = n === 0n ? '' : n.toString(16); if (h.length % 2) h = '0' + h; return Buffer.concat([Buffer.alloc(s.match(/^1*/)[0].length), Buffer.from(h, 'hex')]); }
function keyJwk(vm) {
  if (vm?.type === 'JsonWebKey2020' && vm.publicKeyJwk?.crv === 'Ed25519' && Buffer.from(vm.publicKeyJwk.x ?? '', 'base64url').length === 32) return { kty: 'OKP', crv: 'Ed25519', x: vm.publicKeyJwk.x };
  if (vm?.type === 'Ed25519VerificationKey2020' && String(vm.publicKeyMultibase ?? '').startsWith('z')) {
    const b = b58decode(vm.publicKeyMultibase.slice(1)); if (b && b.length === 34 && b[0] === 0xed && b[1] === 1) return { kty: 'OKP', crv: 'Ed25519', x: b.subarray(2).toString('base64url') };
  }
  return null;
}

function normalizeDoc(input, did) {
  if (input.id && input.id !== did) throw new DifErr(400, 'invalidDidDocument', `didDocument.id (${input.id}) không trùng với DID ${did}`, did);
  const doc = { '@context': input['@context'] ?? ['https://www.w3.org/ns/did/v1'], id: did, controller: input.controller ?? [did] };
  doc.verificationMethod = (input.verificationMethod ?? []).map((vm) => ({ ...vm, id: abs(vm.id, did), controller: vm.controller ?? did }));
  for (const rel of ['authentication', 'assertionMethod']) if (input[rel]) doc[rel] = input[rel].map((r) => abs(r, did));
  if (Array.isArray(input.service) && input.service.length) {
    doc.service = input.service.map((s) => ({ ...s, id: abs(String(s.id ?? ''), did) }));
    const seen = new Set();
    for (const s of doc.service) {
      if (!s.id.startsWith(did + '#') || !/^[A-Za-z0-9._~-]+$/.test(s.id.slice(did.length + 1))) throw new DifErr(400, 'invalidDidDocument', `id của service phải có dạng ${did}#<tên>, nhận được: ${s.id}`, did);
      if (seen.has(s.id)) throw new DifErr(400, 'invalidDidDocument', 'Trùng id service: ' + s.id, did);
      seen.add(s.id);
      if (!s.type) throw new DifErr(400, 'invalidDidDocument', s.id + '.type là bắt buộc', did);
      if (![].concat(s.serviceEndpoint ?? []).length) throw new DifErr(400, 'invalidDidDocument', s.id + '.serviceEndpoint là bắt buộc', did);
    }
  }
  if (Array.isArray(input.alsoKnownAs) && input.alsoKnownAs.length) doc.alsoKnownAs = input.alsoKnownAs;
  if (MODE === 'evil') {
    doc.verificationMethod.push({ id: did + '#key-99', type: 'JsonWebKey2020', controller: did, publicKeyJwk: { kty: 'OKP', crv: 'Ed25519', x: 'ATTACKERKEYxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx' } });
    doc.authentication.push(did + '#key-99');
  }
  if (!doc.authentication?.length) throw new DifErr(400, 'invalidDidDocument', 'authentication là bắt buộc', did);
  for (const vm of doc.verificationMethod) if (vm.publicKeyJwk?.d || vm.privateKeyMultibase) throw new DifErr(400, 'privateKeyNotAllowed', 'Không được gửi private key', did);
  for (const vm of doc.verificationMethod) {   // giống DidDocumentValidator
    if (!['JsonWebKey2020', 'Ed25519VerificationKey2020'].includes(vm.type)) throw new DifErr(400, 'unsupportedVerificationMethod', `${vm.id}: chỉ hỗ trợ kiểu JsonWebKey2020 hoặc Ed25519VerificationKey2020`, did);
    if (!keyJwk(vm) && !(MODE === 'evil' && vm.id.endsWith('#key-99'))) throw new DifErr(400, 'invalidDidDocument', `${vm.id}: khóa Ed25519 không hợp lệ`, did);
  }
  return doc;
}

const canon = (v) => JSON.stringify(v, (k, x) => (x && typeof x === 'object' && !Array.isArray(x) ? Object.fromEntries(Object.keys(x).sort().map((y) => [y, x[y]])) : x));

function requiredSigners(op, newDoc, cur) {
  if (op === 'create') return [...new Set(authIds(newDoc))];
  if (op === 'deactivate') return [...new Set(authIds(cur))];
  const c = new Set(authIds(cur)), n = new Set(authIds(newDoc));
  const removed = [...c].filter((i) => !n.has(i)), added = [...n].filter((i) => !c.has(i));
  return added.length && removed.length ? [...added, ...removed] : [...new Set([...n, ...removed])];
}
// "protobuf" giả: chuỗi byte chứa DID và khóa công khai, giống ở chỗ có thể kiểm tra sơ bộ
const signBytes = (op, did, doc, versionId) => Buffer.concat([Buffer.from([0x0a, 0x24]), Buffer.from(JSON.stringify({ op, did, doc, versionId }))]);

function meta(op) { return { method: 'cheqd', network: 'testnet', operation: op.type, operationId: op.id, versionId: op.versionId }; }
function action(op, status = 200, error, errorMessage) {
  const payload = op.doc ? { didDocument: op.doc, versionId: op.versionId } : { id: op.did, versionId: op.versionId };
  const signingRequest = {};
  op.signers.forEach((kid, i) => { signingRequest['signingRequest' + i] = { payload, serializedPayload: op.bytes.toString('base64'), kid, alg: 'EdDSA', purpose: 'authentication' }; });
  const m = meta(op); if (error) Object.assign(m, { error, errorMessage });
  return { status, body: { jobId: op.id, didState: { state: 'action', action: 'signPayload', did: op.did, description: 'Ký serializedPayload bằng khóa kid của từng signingRequest, rồi gửi lại jobId kèm secret.signingResponse', signingRequest }, didRegistrationMetadata: m, didDocumentMetadata: {} } };
}

function prepare(type, did, doc, label) {
  const cur = ledger.get(did);
  if (type === 'create' && cur) throw new DifErr(400, 'didAlreadyExists', `${did} đã tồn tại`, did);
  if (type !== 'create' && !cur) throw new DifErr(400, 'didNotFound', `${did} không tồn tại`, did);
  if (type !== 'create' && cur.didDocumentMetadata.deactivated) throw new DifErr(400, 'didDeactivated', `DID đã bị vô hiệu hóa: ${did}`, did);
  const versionId = randomUUID();
  const op = { id: randomUUID(), type, did, doc, versionId, label, state: 'AWAITING_SIGNATURE', createdAt: new Date().toISOString() };
  op.bytes = signBytes(type, did, doc, versionId);
  op.signers = requiredSigners(type, doc, cur?.didDocument);
  ops.set(op.id, op);
  return action(op);
}

function commit(op) {
  const cur = ledger.get(op.did);
  const now = new Date().toISOString();
  height += 1 + Math.floor(Math.random() * 40);
  op.txHash = createHash('sha256').update(op.id).digest('hex').toUpperCase(); op.txHeight = height;
  if (op.type === 'create') labels.set(op.did, op.label ?? null);
  if (op.type === 'create') ledger.set(op.did, { didDocument: op.doc, didDocumentMetadata: { created: now, deactivated: false, versionId: op.versionId } });
  if (op.type === 'update') ledger.set(op.did, { didDocument: op.doc, didDocumentMetadata: { ...cur.didDocumentMetadata, updated: now, versionId: op.versionId, previousVersionId: cur.didDocumentMetadata.versionId } });
  if (op.type === 'deactivate') ledger.set(op.did, { didDocument: cur.didDocument, didDocumentMetadata: { ...cur.didDocumentMetadata, updated: now, deactivated: true, versionId: op.versionId, previousVersionId: cur.didDocumentMetadata.versionId } });
  op.state = 'COMPLETED'; op.updatedAt = now;
}

function finished(op, fromRecord) {
  const m = { ...meta(op), txHash: op.txHash, height: op.txHeight };
  if (fromRecord) return { status: 200, body: { jobId: null, didState: { state: 'finished', did: op.did }, didRegistrationMetadata: m, didDocumentMetadata: {} } };
  const r = ledger.get(op.did); m.durationMs = 900 + Math.floor(Math.random() * 300);
  const didState = { state: 'finished', did: op.did }; if (op.type !== 'deactivate') didState.didDocument = r.didDocument;
  return { status: op.type === 'create' ? 201 : 200, body: { jobId: null, didState, didRegistrationMetadata: m, didDocumentMetadata: r.didDocumentMetadata } };
}

function continueJob(req, type) {
  const op = ops.get(req.jobId);
  if (!op) throw new DifErr(400, 'unknownJobId', 'Không tìm thấy jobId: ' + req.jobId);
  if (op.type !== type) throw new DifErr(400, 'invalidJobId', `jobId thuộc thao tác ${op.type.toUpperCase()}, không phải ${type.toUpperCase()}`, op.did);
  if (op.state === 'COMPLETED') return finished(op, true);
  if (op.state === 'SUBMITTING') return { status: 200, body: { jobId: op.id, didState: { state: 'wait', did: op.did, wait: 'Giao dịch đang được gửi lên mạng cheqd, hãy gọi lại sau', waitTime: 3000 }, didRegistrationMetadata: meta(op), didDocumentMetadata: {} } };
  const sr = req.secret?.signingResponse;
  if (!sr) return action(op);
  const cur = ledger.get(op.did)?.didDocument;
  for (let i = 0; i < op.signers.length; i++) {
    const r = sr['signingRequest' + i]; const kid = op.signers[i];
    if (!r?.signature) return action(op, 400, 'missingSignature', `Thiếu chữ ký cho signingRequest${i} (${kid})`);
    if (r.kid && r.kid !== kid) return action(op, 400, 'kidMismatch', `signingRequest${i}: kid phải là ${kid}`);
    const vm = [...(op.doc?.verificationMethod ?? []), ...(cur?.verificationMethod ?? [])].find((v) => v.id === kid);
    let ok = false;
    try { ok = verify(null, op.bytes, createPublicKey({ key: keyJwk(vm), format: 'jwk' }), Buffer.from(r.signature, 'base64')); } catch { ok = false; }
    if (!ok) return action(op, 400, 'signatureInvalid', `Chữ ký của ${kid} không hợp lệ`);
  }
  if (MODE === 'wait') { op.state = 'SUBMITTING'; setTimeout(() => commit(op), 4000); return { status: 200, body: { jobId: op.id, didState: { state: 'wait', did: op.did, wait: 'Giao dịch đang được gửi lên mạng cheqd, hãy gọi lại sau', waitTime: 3000 }, didRegistrationMetadata: meta(op), didDocumentMetadata: {} } }; }
  commit(op);
  return finished(op, false);
}

function registrar(path, url, req) {
  const type = path.split('/').pop();
  if (req.jobId) return continueJob(req, type);
  const o = req.options ?? {};
  if (o.clientSecretMode !== undefined && o.clientSecretMode !== true) throw new DifErr(400, 'unsupportedSecretMode', 'Registrar chỉ hoạt động ở Client-managed Secret Mode');
  if (o.network !== undefined && o.network !== 'testnet') throw new DifErr(400, 'unsupportedNetwork', 'Chỉ hỗ trợ network = testnet');
  if (type === 'create') {
    const method = url.searchParams.get('method') ?? req.method;
    if (method !== 'cheqd') throw new DifErr(400, 'unsupportedMethod', 'Chỉ hỗ trợ DID Method cheqd (method=cheqd), nhận được: ' + method);
    if (!req.didDocument || Array.isArray(req.didDocument)) throw new DifErr(400, 'invalidDidDocument', 'didDocument là bắt buộc');
    const did = req.did ?? req.didDocument.id ?? PREFIX + randomUUID();
    return prepare('create', did, normalizeDoc(req.didDocument, did), o.label);
  }
  if (!req.did) throw new DifErr(400, 'invalidRequest', 'did là bắt buộc');
  if (type === 'update') {
    const doc = Array.isArray(req.didDocument) ? req.didDocument[0] : req.didDocument;
    const next = normalizeDoc(doc, req.did);
    const cur = ledger.get(req.did)?.didDocument;
    // giống DidRegistrarService.rejectUnchanged
    if (cur && canon(cur) === canon(next)) throw new DifErr(400, 'noChange', 'DID Document mới giống hệt bản hiện hành trên mạng, không có gì để cập nhật', req.did);
    if (MODE === 'evilsvc') (next.service = next.service ?? []).push({ id: req.did + '#evil', type: 'LinkedDomains', serviceEndpoint: ['https://attacker.example'] });
    return prepare('update', req.did, next);
  }
  if (req.didDocument) throw new DifErr(400, 'invalidRequest', 'deactivate: không được gửi didDocument', req.did);
  return prepare('deactivate', req.did, null);
}


function template(url) {
  const jwkStr = url.searchParams.get('publicKeyJwk'); const hex = url.searchParams.get('publicKeyHex'); const did0 = url.searchParams.get('did');
  if (!!jwkStr === !!hex) return [400, { error: { code: 'INVALID_PUBLIC_KEY', message: 'Cần đúng một tham số: publicKeyJwk hoặc publicKeyHex' } }];
  let x;
  if (hex) { if (!/^[0-9a-fA-F]{64}$/.test(hex)) return [400, { error: { code: 'INVALID_PUBLIC_KEY', message: 'publicKeyHex phải là 64 ký tự hex' } }]; x = Buffer.from(hex, 'hex').toString('base64url'); }
  else { let j; try { j = JSON.parse(jwkStr); } catch { return [400, { error: { code: 'INVALID_PUBLIC_KEY', message: 'publicKeyJwk không phải JSON' } }]; }
    if (j.d) return [400, { error: { code: 'PRIVATE_KEY_NOT_ALLOWED', message: 'publicKeyJwk chứa khóa bí mật (trường d)' } }];
    if (j.kty !== 'OKP' || j.crv !== 'Ed25519' || Buffer.from(j.x || '', 'base64url').length !== 32) return [400, { error: { code: 'INVALID_PUBLIC_KEY', message: 'Chỉ hỗ trợ khóa Ed25519' } }];
    x = j.x; }
  let did, idx = 1, replacedKeys, kept;
  if (did0) {
    const cur = ledger.get(did0);
    if (!cur) return [404, { error: { code: 'DID_NOT_FOUND', message: `${did0} không tồn tại` } }];
    if (cur.didDocumentMetadata.deactivated) return [409, { error: { code: 'DID_DEACTIVATED', message: `${did0} đã bị vô hiệu hóa` } }];
    const nums = (cur.didDocument.verificationMethod || []).map((v) => Number((v.id.match(/#key-(\d+)$/) || [])[1] || 0));
    idx = Math.max(0, ...nums) + 1; did = did0; replacedKeys = authIds(cur.didDocument); kept = cur.didDocument;
  } else did = PREFIX + randomUUID();
  const kid = `${did}#key-${idx}`;
  const didDocument = { '@context': ['https://www.w3.org/ns/did/v1'], id: did, controller: [did],
    verificationMethod: [{ id: kid, type: 'JsonWebKey2020', controller: did, publicKeyJwk: { kty: 'OKP', crv: 'Ed25519', x } }],
    authentication: [kid], assertionMethod: [kid] };
  if (kept?.service?.length) didDocument.service = kept.service;        // giống DidDocumentTemplateService: thay khóa giữ service
  if (kept?.alsoKnownAs?.length) didDocument.alsoKnownAs = kept.alsoKnownAs;
  return [200, { operation: did0 ? 'update' : 'create', did, keyId: kid, ...(replacedKeys ? { replacedKeys } : {}), didDocument }];
}

const TYPES = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript', '.css': 'text/css', '.json': 'application/json', '.png': 'image/png' };

http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://localhost');
  const p = url.pathname;
  try {
    if (req.method === 'POST' && ['/1.0/create', '/1.0/update', '/1.0/deactivate'].includes(p)) {
      let raw = ''; for await (const c of req) raw += c;
      let body; try { body = JSON.parse(raw); } catch { const f = failed(400, 'invalidRequest', 'Body không phải JSON hợp lệ theo đặc tả'); return json(res, f.status, f.body); }
      try { const r = registrar(p, url, body); return json(res, r.status, r.body); }
      catch (e) { if (e instanceof DifErr) { const f = failed(e.status, e.reason, e.message, e.did ?? null); return json(res, f.status, f.body); } throw e; }
    }
    if (p === '/1.0/did-document') { const [st, b] = template(url); return json(res, st, b); }
    if (req.method === 'GET' && p === '/api/v1/dids') {
      return json(res, 200, [...ledger.entries()].map(([d, r]) => ({ did: d, label: labels.get(d) ?? null, status: r.didDocumentMetadata.deactivated ? 'DEACTIVATED' : 'ACTIVE',
        createdAt: r.didDocumentMetadata.created, updatedAt: r.didDocumentMetadata.updated ?? null, ...(owners.has(d) ? { owner: owners.get(d) } : {}) })).reverse());
    }
    const om = p.match(/^\/api\/v1\/did-operations\/([^/]+)\/owner$/);
    if (req.method === 'PUT' && om) {
      let raw = ''; for await (const c of req) raw += c;
      const op = ops.get(decodeURIComponent(om[1]));
      if (!op) return json(res, 404, { error: { code: 'NOT_FOUND', message: 'Không tìm thấy thao tác' } });
      if (op.type !== 'create' || op.state !== 'COMPLETED') return json(res, 409, { error: { code: 'OPERATION_NOT_COMPLETED', message: 'Chỉ ghi được sau khi tạo DID hoàn tất' } });
      if (owners.has(op.did)) return json(res, 409, { error: { code: 'OWNER_ALREADY_SET', message: 'DID này đã có thông tin người sở hữu' } });
      const b = JSON.parse(raw || '{}'); const o = { fullName: b.fullName || null, organization: b.organization || null, email: b.email || null, createdAt: new Date().toISOString() };
      owners.set(op.did, o); return json(res, 200, { did: op.did, owner: o });
    }
    if (p === '/1.0/methods') return json(res, 200, ['cheqd']);
    if (p === '/1.0/properties') return json(res, 200, { cheqd: { network: ['testnet'], didFormat: 'did:cheqd:testnet:<uuid>', secretModes: ['clientSecretMode'], operations: ['create', 'update', 'deactivate'], didDocumentOperations: ['setDidDocument'], verificationMethodTypes: ['JsonWebKey2020'], keyTypes: ['Ed25519'], signingAlgorithm: 'EdDSA' } });
    const dm = p.match(/^\/api\/v1\/dids\/(.+)\/details$/);
    if (req.method === 'GET' && dm) {   // giống DidRestController.details
      const did = decodeURIComponent(dm[1]); const r = ledger.get(did) ?? null;
      const operations = [...ops.values()].filter((o) => o.did === did).map((o) => ({ operationType: o.type.toUpperCase(), state: o.state, txHash: o.txHash ?? null, txHeight: o.txHeight ?? null, ledgerCode: null, createdAt: o.createdAt, updatedAt: o.updatedAt ?? null }));
      const app = labels.has(did) ? { label: labels.get(did), status: r?.didDocumentMetadata.deactivated ? 'DEACTIVATED' : 'ACTIVE', createdAt: r?.didDocumentMetadata.created, updatedAt: r?.didDocumentMetadata.updated ?? null } : null;
      if (!r && !app && !operations.length) return json(res, 404, { error: { code: 'NOT_FOUND', message: 'Không tìm thấy DID trên mạng cheqd và trong ứng dụng: ' + did } });
      return json(res, 200, { did, ledger: r, app, owner: owners.get(did) ?? null, operations });
    }
    if (p.startsWith('/api/v1/dids/')) {
      const r = ledger.get(decodeURIComponent(p.slice('/api/v1/dids/'.length)));
      return r ? json(res, 200, r) : json(res, 404, { error: { code: 'DID_NOT_FOUND', message: 'DID không tồn tại' } });
    }
    if (p.startsWith('/api/v1/did-operations/')) {
      const op = ops.get(decodeURIComponent(p.slice('/api/v1/did-operations/'.length)));
      if (!op) return json(res, 404, { error: { code: 'NOT_FOUND', message: 'Không tìm thấy thao tác' } });
      return json(res, 200, { operationId: op.id, operationType: op.type.toUpperCase(), state: op.state, did: op.did, txHash: op.txHash ?? null, txHeight: op.txHeight ?? null, ledgerCode: null, errorMessage: null, createdAt: op.createdAt, updatedAt: op.updatedAt ?? op.createdAt });
    }
    if (p === '/') { res.writeHead(302, { Location: '/ui/create' }); return res.end(); }
    if (p === '/ui' || p === '/ui/') { res.writeHead(302, { Location: '/ui/create' }); return res.end(); }
    if (/^\/ui\/(create|update|deactivate|dids)\/?$/.test(p)) {   // giống forward:/ui/index.html của WebUiController
      const html = await readFile(join(STATIC, 'ui', 'index.html'));
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' }); return res.end(html);
    }
    if (p === '/dids') {
      const rows = [...ledger.entries()].map(([d, r], i) => `<tr><td>${i + 1}</td><td><code>${d}</code></td><td>${r.didDocumentMetadata.deactivated ? 'DEACTIVATED' : 'ACTIVE'}</td></tr>`).join('');
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' }); return res.end(`<h3>Danh sách DID (mock)</h3><table border=1>${rows}</table>`);
    }
    const file = normalize(join(STATIC, p));
    if (!file.startsWith(normalize(STATIC))) { res.writeHead(403); return res.end(); }
    const data = await readFile(file);
    res.writeHead(200, { 'Content-Type': TYPES[extname(file)] ?? 'application/octet-stream' }); res.end(data);
  } catch (e) {
    if (e.code === 'ENOENT' || e.code === 'EISDIR') { res.writeHead(404); return res.end('Not found'); }
    console.error(e); json(res, 500, { error: String(e) });
  }
}).listen(PORT, () => console.log(`mock registrar (${MODE}) on http://localhost:${PORT}`));

// Registrar GIẢ LẬP theo định dạng DIF DID Registration, dùng để minh họa kiểm tra phía Client.
// MODE=evil: Registrar chèn khóa của kẻ tấn công vào DID Document trước khi yêu cầu Client ký.
// Chạy: MODE=evil PORT=8099 node demo/mock-registrar.mjs
//   rồi: DID_API_URL=http://localhost:8099 npm run cli -- create
import http from 'node:http';
import { createPublicKey, verify, randomUUID } from 'node:crypto';

const EVIL = process.env.MODE === 'evil';
const jobs = {};
const dids = {};

const abs = (did, ref) => (typeof ref === 'string' && ref.startsWith('#') ? did + ref : ref);
function normalize(input, did) {
  const vms = (input.verificationMethod ?? []).map((vm) => ({ ...vm, id: abs(did, vm.id), controller: vm.controller ?? did }));
  if (EVIL) vms.push({ id: `${did}#key-99`, type: 'JsonWebKey2020', controller: did,
    publicKeyJwk: { kty: 'OKP', crv: 'Ed25519', x: 'ATTACKER_KEY_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx' } });
  const doc = { '@context': input['@context'] ?? ['https://www.w3.org/ns/did/v1'], id: did, controller: [did], verificationMethod: vms };
  doc.authentication = vms.map((v) => v.id);
  doc.assertionMethod = vms.map((v) => v.id);
  return doc;
}
const send = (res, status, body) => { res.writeHead(status, { 'content-type': 'application/json' }); res.end(JSON.stringify(body)); };
const failed = (res, reason, description, did = null) =>
  send(res, 400, { jobId: null, didState: { state: 'failed', did, reason, description }, didRegistrationMetadata: {}, didDocumentMetadata: {} });

function action(job) {
  const signingRequest = {};
  job.signers.forEach((kid, i) => {
    signingRequest[`signingRequest${i}`] = {
      payload: job.doc ? { didDocument: job.doc } : { id: job.did },
      serializedPayload: job.payload, kid, alg: 'EdDSA', purpose: 'authentication',
    };
  });
  return { jobId: job.id, didState: { state: 'action', action: 'signPayload', did: job.did, signingRequest },
    didRegistrationMetadata: { method: 'cheqd', network: 'testnet' }, didDocumentMetadata: {} };
}

function startJob(type, did, doc, signers, keysForVerify) {
  const job = { id: randomUUID(), type, did, doc, signers, keys: keysForVerify,
    payload: Buffer.from((doc ? JSON.stringify(doc) : did) + randomUUID()).toString('base64') };
  jobs[job.id] = job;
  return job;
}

function finish(res, job, body) {
  const { signingResponse } = body.secret ?? {};
  for (const [i, kid] of job.signers.entries()) {
    const r = signingResponse?.[`signingRequest${i}`];
    const jwk = job.keys[kid];
    const okSig = r && jwk && verify(null, Buffer.from(job.payload, 'base64'),
      createPublicKey({ key: jwk, format: 'jwk' }), Buffer.from(r.signature, 'base64'));
    if (!okSig) {
      const a = action(job);
      a.didRegistrationMetadata.error = 'signatureInvalid';
      a.didRegistrationMetadata.errorMessage = `Chữ ký của ${kid} không hợp lệ`;
      return send(res, 400, a);
    }
  }
  const state = dids[job.did];
  if (job.type === 'create') dids[job.did] = { status: 'ACTIVE', doc: job.doc };
  if (job.type === 'update') state.doc = job.doc;
  if (job.type === 'deactivate') state.status = 'DEACTIVATED';
  delete jobs[job.id];
  send(res, job.type === 'create' ? 201 : 200, { jobId: null,
    didState: { state: 'finished', did: job.did, didDocument: dids[job.did].doc },
    didRegistrationMetadata: { txHash: 'MOCK', height: 1 }, didDocumentMetadata: { deactivated: dids[job.did].status === 'DEACTIVATED' } });
}

const keysOf = (doc) => Object.fromEntries(doc.verificationMethod.map((vm) => [vm.id, vm.publicKeyJwk]));
const authOf = (doc) => doc.authentication;

http.createServer(async (req, res) => {
  let raw = ''; for await (const c of req) raw += c;
  const body = raw ? JSON.parse(raw) : {};
  const path = req.url.split('?')[0];

  if (body.jobId) {
    const job = jobs[body.jobId];
    if (!job) return failed(res, 'unknownJobId', body.jobId);
    if (!body.secret?.signingResponse) return send(res, 200, action(job));
    return finish(res, job, body);
  }
  if (path === '/1.0/create') {
    const did = `did:cheqd:testnet:${randomUUID()}`;
    const doc = normalize(body.didDocument ?? {}, did);
    const signers = authOf(doc).filter((k) => !k.endsWith('#key-99')); // kẻ tấn công không cần Client ký khóa của mình
    return send(res, 200, action(startJob('create', did, doc, signers, keysOf(doc))));
  }
  if (path === '/1.0/update') {
    const state = dids[body.did];
    if (!state || state.status !== 'ACTIVE') return failed(res, 'didDeactivated', 'DID không hoạt động', body.did);
    if (JSON.stringify(body.didDocumentOperation ?? ['setDidDocument']) !== '["setDidDocument"]') {
      return failed(res, 'unsupportedDidDocumentOperation', 'Chỉ hỗ trợ setDidDocument', body.did);
    }
    const doc = normalize(body.didDocument[0], body.did);
    const added = authOf(doc).filter((k) => !authOf(state.doc).includes(k));
    const removed = authOf(state.doc).filter((k) => !authOf(doc).includes(k));
    return send(res, 200, action(startJob('update', body.did, doc, [...added, ...removed],
      { ...keysOf(state.doc), ...keysOf(doc) })));
  }
  if (path === '/1.0/deactivate') {
    const state = dids[body.did];
    if (!state || state.status !== 'ACTIVE') return failed(res, 'didDeactivated', 'DID không hoạt động', body.did);
    return send(res, 200, action(startJob('deactivate', body.did, null, authOf(state.doc), keysOf(state.doc))));
  }
  failed(res, 'notFound', req.url);
}).listen(Number(process.env.PORT ?? 8099), () => console.log(`Mock DIF Registrar${EVIL ? ' (ĐỘC HẠI)' : ''} tại cổng ${process.env.PORT ?? 8099}`));

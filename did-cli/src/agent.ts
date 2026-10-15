/**
 * Agent ký: một dịch vụ HTTP chỉ nghe trên 127.0.0.1 để giao diện của Registrar (chạy trong trình
 * duyệt) xin khóa công khai và xin chữ ký mà không phải chép tay.
 *
 *   GET  /status           thông tin agent
 *   GET  /keys             danh sách DID và khóa (chỉ phần công khai)
 *   POST /keys             sinh khóa mới -> { keyRef, publicKeyJwk }
 *   POST /sign             { response, keyRef?, label? } -> đối chiếu, xác nhận ở terminal, ký
 *   POST /sync             { did } -> đối chiếu kho khóa với DID Document trên mạng
 *
 * Bảo vệ: chỉ nghe 127.0.0.1; chỉ nhận yêu cầu từ origin đã khai báo (CORS); mỗi yêu cầu phải có
 * mã ghép cặp X-Agent-Token; mọi chữ ký đều cần người dùng xác nhận ở terminal (trừ khi chạy --yes
 * để kiểm thử). Khóa bí mật không bao giờ nằm trong phản hồi của agent.
 */
import { createServer } from 'node:http';
import type { IncomingMessage, ServerResponse } from 'node:http';
import { randomBytes, timingSafeEqual } from 'node:crypto';
import { Wallet, frag, newKeyRef } from './wallet.ts';
import { signerFor } from './signer.ts';
import { analyze, signAll, syncDid, refreshFromLedger } from './signing.ts';
import { printAnalysis, confirm } from './confirm.ts';
import { api, API_URL } from './api.ts';

export interface AgentOptions {
  port: number;
  origins: string[];
  token?: string;
  autoConfirm: boolean;
  kms: string;
}

const MAX_BODY = 1 << 20;

function readJson(req: IncomingMessage): Promise<any> {
  return new Promise((resolve, reject) => {
    let size = 0; const chunks: Buffer[] = [];
    req.on('data', (c: Buffer) => {
      size += c.length;
      if (size > MAX_BODY) { reject(new Error('Body quá lớn')); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', () => {
      const text = Buffer.concat(chunks).toString('utf8');
      try { resolve(text ? JSON.parse(text) : {}); } catch { reject(new Error('Body không phải JSON')); }
    });
    req.on('error', reject);
  });
}

function publicView(w: Wallet) {
  const key = (k: any) => ({ keyRef: k.keyRef, kid: k.kid ?? null, status: k.status, kms: k.kms, publicKeyJwk: k.publicJwk });
  return {
    dids: w.listDids().map((d) => ({ did: d.did, label: d.label ?? null, status: d.status, keys: d.keys.map(key) })),
    looseKeys: w.looseKeys().map(key),
  };
}

export function startAgent(opt: AgentOptions) {
  const token = opt.token ?? randomBytes(9).toString('base64url');
  const tokenBuf = Buffer.from(token);
  const allowed = new Set(opt.origins);

  const send = (res: ServerResponse, origin: string | undefined, status: number, body: unknown) => {
    const headers: Record<string, string> = { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' };
    if (origin && allowed.has(origin)) { headers['Access-Control-Allow-Origin'] = origin; headers['Vary'] = 'Origin'; }
    res.writeHead(status, headers); res.end(JSON.stringify(body));
  };

  const server = createServer(async (req, res) => {
    const origin = req.headers.origin;
    const url = new URL(req.url ?? '/', 'http://127.0.0.1');

    if (origin && !allowed.has(origin)) return send(res, undefined, 403, { error: { code: 'ORIGIN_NOT_ALLOWED', message: `Origin ${origin} không được phép` } });
    if (req.method === 'OPTIONS') {
      res.writeHead(204, {
        'Access-Control-Allow-Origin': origin ?? '',
        'Access-Control-Allow-Methods': 'GET, POST',
        'Access-Control-Allow-Headers': 'Content-Type, X-Agent-Token',
        'Access-Control-Allow-Private-Network': 'true',
        'Access-Control-Max-Age': '600',
        'Vary': 'Origin',
      });
      return res.end();
    }
    const given = Buffer.from(String(req.headers['x-agent-token'] ?? ''));
    if (given.length !== tokenBuf.length || !timingSafeEqual(given, tokenBuf)) {
      return send(res, origin, 401, { error: { code: 'BAD_TOKEN', message: 'Sai hoặc thiếu mã ghép cặp X-Agent-Token' } });
    }

    try {
      const wallet = Wallet.load();
      if (req.method === 'GET' && url.pathname === '/status') {
        return send(res, origin, 200, { agent: 'did-cli', kms: opt.kms, registrar: API_URL, keys: wallet.allKeys().length });
      }
      if (req.method === 'GET' && url.pathname === '/keys') return send(res, origin, 200, publicView(wallet));

      if (req.method === 'POST' && url.pathname === '/keys') {
        const created = await signerFor(opt.kms).createKey();
        const k = wallet.addLooseKey({ keyRef: newKeyRef(), kms: opt.kms, ...created });
        process.stderr.write(`\n[agent] Sinh khóa mới ${k.keyRef} (x = ${k.publicJwk.x})\n`);
        return send(res, origin, 201, { keyRef: k.keyRef, publicKeyJwk: k.publicJwk });
      }

      if (req.method === 'POST' && url.pathname === '/sign') {
        const body = await readJson(req);
        const syncError = await refreshFromLedger(body.response, wallet, api.resolve);
        if (syncError) process.stderr.write(`\n[agent] Không đối chiếu được với mạng: ${syncError}\n`);
        const a = analyze(body.response, wallet, body.keyRef, syncError);
        printAnalysis(a);
        const checks = a.checks;
        if (!a.ok) {
          process.stderr.write('  => Từ chối ký: đối chiếu không đạt.\n');
          return send(res, origin, 422, { ok: false, reason: 'CHECK_FAILED', operation: a.operation, did: a.did, summary: a.summary, checks });
        }
        const yes = opt.autoConfirm || await confirm(a.operation === 'deactivate' ? `Ký để VÔ HIỆU HÓA VĨNH VIỄN ${a.did}?` : `Ký yêu cầu ${a.operation} cho ${a.did}?`);
        if (!yes) {
          process.stderr.write('  => Người dùng từ chối.\n');
          return send(res, origin, 403, { ok: false, reason: 'USER_REJECTED', operation: a.operation, did: a.did, summary: a.summary, checks });
        }
        const secondCall = await signAll(a, wallet, typeof body.label === 'string' ? body.label : undefined);
        process.stderr.write(`  => Đã ký ${Object.keys(secondCall.secret.signingResponse).length} yêu cầu (${a.expectedSigners.map(frag).join(', ')}).\n`);
        return send(res, origin, 200, { ok: true, operation: a.operation, did: a.did, endpoint: a.endpoint, summary: a.summary, checks, body: secondCall });
      }

      if (req.method === 'POST' && url.pathname === '/sync') {
        const body = await readJson(req);
        if (typeof body.did !== 'string') return send(res, origin, 400, { error: { code: 'INVALID_REQUEST', message: 'Thiếu did' } });
        let changes: string[];
        try { changes = await syncDid(wallet, body.did, api.resolve); }
        catch (e: any) {
          process.stderr.write(`\n[agent] Không đối chiếu được ${body.did}: ${e?.message ?? e}\n`);
          return send(res, origin, 502, { error: { code: e?.code ?? 'SYNC_FAILED', message: `Agent không đọc được DID từ Registrar tại ${API_URL}: ${e?.message ?? e}` } });
        }
        const d = wallet.getDid(body.did);
        process.stderr.write(`\n[agent] Đối chiếu ${body.did}: ${changes.length ? changes.join('; ') : 'không đổi'}\n`);
        return send(res, origin, 200, { did: body.did, changes, status: d?.status ?? null, keys: (d?.keys ?? []).map((k) => ({ kid: k.kid, status: k.status })) });
      }
      return send(res, origin, 404, { error: { code: 'NOT_FOUND', message: 'Không có điểm cuối này' } });
    } catch (e: any) {
      return send(res, origin, 500, { error: { code: e?.code ?? 'AGENT_ERROR', message: e?.message ?? String(e) } });
    }
  });

  server.listen(opt.port, '127.0.0.1', () => {
    process.stderr.write(
      `did-cli agent đang chạy tại http://127.0.0.1:${opt.port}\n` +
      `  Bộ ký        : ${opt.kms}\n` +
      `  Registrar    : ${API_URL}\n` +
      `  Origin cho phép: ${[...allowed].join(', ')}\n` +
      `  Mã ghép cặp  : ${token}   (nhập mã này trên giao diện của Registrar)\n` +
      (opt.autoConfirm ? '  CẢNH BÁO: --yes đang bật, agent ký mà không hỏi xác nhận (chỉ dùng để kiểm thử)\n' : '') +
      'Nhấn Ctrl+C để dừng.\n');
  });
  return server;
}

/**
 * did-cli: bộ ký phía Client cho ứng dụng DID Registrar (Client-managed Secret).
 *
 * did-cli chỉ làm phần việc của Client: sinh và giữ khóa, đối chiếu yêu cầu ký, xin xác nhận, ký.
 * Việc soạn DID Document, gửi yêu cầu và hiển thị kết quả do DID Registrar và giao diện của nó đảm nhận.
 *
 *   keygen                           sinh khóa mới, in khóa công khai (JWK và hex)
 *   sign <tệp> [--key <keyRef>]      đối chiếu + ký yêu cầu ký (phản hồi lần gọi thứ nhất),
 *                                    in body cho lần gọi thứ hai (ký thủ công, dùng với Swagger UI)
 *   keys                             liệt kê DID và khóa trong kho
 *   sync <did> | --all               đối chiếu kho khóa với DID Document trên mạng
 *   discard <did> <keyRef>           bỏ một khóa PENDING chưa từng lên mạng
 *   agent [--port 7070] [--origin <url>] [--token <mã>] [--yes]
 *                                    chạy agent ký cho giao diện của Registrar
 *   resolve <did> | status <jobId>   tra cứu (qua Registrar)
 *
 * Biến môi trường: DID_API_URL (mặc định http://localhost:8085), DID_CLI_WALLET (vị trí tệp kho khóa)
 */
import { readFileSync } from 'node:fs';
import { Wallet, WALLET_PATH, frag, newKeyRef } from './wallet.ts';
import { signerFor } from './signer.ts';
import { analyze, signAll, syncDid, refreshFromLedger } from './signing.ts';
import { printAnalysis, confirm } from './confirm.ts';
import { startAgent } from './agent.ts';
import { api, ApiError, API_URL } from './api.ts';

const argv = process.argv.slice(2);
const command = argv[0];
const flag = (name: string) => argv.includes(`--${name}`);
const option = (name: string) => { const i = argv.indexOf(`--${name}`); return i >= 0 ? argv[i + 1] : undefined; };
const valued = new Set(['--key', '--port', '--origin', '--token', '--label']);
const positional = argv.slice(1).filter((a, i, arr) => !a.startsWith('--') && !(i > 0 && valued.has(arr[i - 1])));
const out = (s = '') => process.stdout.write(s + '\n');
const info = (s = '') => process.stderr.write(s + '\n');

async function cmdKeygen() {
  const kms = 'local';
  const wallet = Wallet.load();
  const created = await signerFor(kms).createKey();
  const k = wallet.addLooseKey({ keyRef: newKeyRef(), kms, ...created });
  info(`Đã sinh khóa ${k.keyRef} (bộ ký ${kms}), lưu tại ${WALLET_PATH}. Khóa bí mật không được in ra.`);
  out(JSON.stringify({ keyRef: k.keyRef, publicKeyJwk: k.publicJwk, publicKeyHex: Buffer.from(k.publicJwk.x, 'base64url').toString('hex') }, null, 2));
}

async function cmdSign(file: string) {
  if (file === '-' && !flag('yes')) throw new Error('Đọc từ stdin thì không hỏi xác nhận được; hãy lưu phản hồi ra tệp, hoặc thêm --yes');
  const response = JSON.parse(readFileSync(file === '-' ? 0 : file, 'utf8'));
  const wallet = Wallet.load();
  const syncError = await refreshFromLedger(response, wallet, api.resolve);
  if (syncError) info(`Cảnh báo: không đối chiếu được với mạng (${syncError})`);
  const a = analyze(response, wallet, option('key'), syncError);
  printAnalysis(a);
  if (!a.ok) throw new Error('Từ chối ký: đối chiếu không đạt. Không có chữ ký nào được tạo.');
  const yes = flag('yes') || await confirm(a.operation === 'deactivate' ? `Ký để VÔ HIỆU HÓA VĨNH VIỄN ${a.did}?` : `Ký yêu cầu ${a.operation} cho ${a.did}?`);
  if (!yes) throw new Error('Đã hủy, không ký.');
  const body = await signAll(a, wallet, option('label'));
  info(`\nGửi body dưới đây tới POST ${a.endpoint} (cùng điểm cuối với lần gọi thứ nhất):`);
  out(JSON.stringify(body, null, 2));
}

function cmdKeys() {
  const w = Wallet.load();
  out(`Kho khóa: ${WALLET_PATH}`);
  for (const d of w.listDids()) {
    out(`\n${d.did}  [${d.status}]${d.label ? `  "${d.label}"` : ''}`);
    for (const k of d.keys) out(`   ${frag(k.kid).padEnd(7)} ${k.status.padEnd(8)} ${k.keyRef}  x=${k.publicJwk.x}`);
  }
  if (w.looseKeys().length) {
    out('\nKhóa chưa gắn DID:');
    for (const k of w.looseKeys()) out(`   ${k.keyRef}  x=${k.publicJwk.x}`);
  }
  if (!w.listDids().length && !w.looseKeys().length) out('(trống)');
}

async function cmdSync(did?: string) {
  const w = Wallet.load();
  const targets = flag('all') ? w.listDids().map((d) => d.did) : did ? [did] : [];
  if (!targets.length) throw new Error('Cần <did> hoặc --all');
  for (const t of targets) {
    const changes = await syncDid(w, t, api.resolve);
    out(`${t}: ${changes.length ? changes.join('; ') : 'khớp với mạng, không đổi'}`);
  }
}

function usage() {
  out(`did-cli - bộ ký phía Client cho DID Registrar (Client-managed Secret)

  keygen                              Sinh khóa mới, in khóa công khai
  sign <tệp> [--key <keyRef>] [--yes] Đối chiếu và ký phản hồi lần gọi thứ nhất (ký thủ công)
  keys                                Liệt kê DID và khóa
  sync <did> | --all                  Đối chiếu kho khóa với mạng
  discard <did> <keyRef>              Bỏ khóa PENDING chưa lên mạng
  agent [--port 7070] [--origin http://localhost:8085] [--token <mã>] [--yes]
                                      Chạy agent ký cho giao diện /ui của Registrar
  resolve <did> | status <jobId>      Tra cứu qua Registrar

Registrar: ${API_URL}   (DID_API_URL)
Kho khóa : ${WALLET_PATH}   (DID_CLI_WALLET)`);
}

async function main() {
  const need = (i: number, name: string) => { const v = positional[i]; if (!v) throw new Error(`Thiếu tham số <${name}>`); return v; };
  switch (command) {
    case 'keygen': return cmdKeygen();
    case 'sign': return cmdSign(need(0, 'tệp'));
    case 'keys': return cmdKeys();
    case 'sync': return cmdSync(positional[0]);
    case 'discard': {
      const ok = Wallet.load().discardPending(need(0, 'did'), need(1, 'keyRef'));
      return out(ok ? 'Đã bỏ khóa PENDING' : 'Không có khóa PENDING như vậy');
    }
    case 'agent': {
      const origins = argv.flatMap((a, i) => (a === '--origin' ? [argv[i + 1]] : []));
      startAgent({ port: Number(option('port') ?? 7070), origins: origins.length ? origins : ['http://localhost:8085'],
        token: option('token'), autoConfirm: flag('yes'), kms: 'local' });
      return;
    }
    case 'resolve': return out(JSON.stringify(await api.resolve(need(0, 'did')), null, 2));
    case 'status': return out(JSON.stringify(await api.getOperation(need(0, 'jobId')), null, 2));
    default: return usage();
  }
}

main().catch((e) => {
  if (e instanceof ApiError) info(`\n✘ ${e.status} ${e.code}: ${e.message}`);
  else info(`\n✘ ${e?.message ?? e}`);
  process.exit(1);
});

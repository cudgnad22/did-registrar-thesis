/**
 * Kho khóa của Client. Khóa bí mật CHỈ nằm ở đây (hoặc trong ví ngoài), không bao giờ được gửi
 * tới ứng dụng DID Registrar.
 *
 * Giới hạn (ghi nhận trong chuyên đề): khóa bí mật lưu dạng JWK trong một tệp JSON, chỉ được bảo vệ
 * bằng quyền truy cập tệp (600). Kho khóa thực tế cần mã hóa bằng mật khẩu, dùng kho khóa của hệ
 * điều hành hoặc phần cứng bảo mật.
 *
 * Định dạng tương thích với bản did-cli trước: { version, dids }, thêm looseKeys cho các khóa đã sinh
 * nhưng chưa gắn với DID nào (sinh bằng keygen, chờ được dùng trong một thao tác tạo DID hoặc thay khóa).
 */
import { readFileSync, writeFileSync, existsSync, mkdirSync, chmodSync, renameSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { homedir } from 'node:os';
import { randomBytes } from 'node:crypto';

export type PublicJwk = { kty: string; crv: string; x: string };
export type PrivateJwk = PublicJwk & { d: string };

export type KeyStatus = 'PENDING' | 'ACTIVE' | 'REPLACED';
export type DidStatus = 'PENDING' | 'ACTIVE' | 'DEACTIVATED';

export interface StoredKey {
  keyRef: string;            // mã tham chiếu cục bộ, không đổi suốt vòng đời khóa
  kid?: string;              // id Verification Method, ví dụ did:cheqd:testnet:<uuid>#key-2 (khi đã gắn DID)
  publicJwk: PublicJwk;
  privateJwk?: PrivateJwk;   // chỉ có với bộ ký cục bộ; KHÔNG rời khỏi kho khóa
  kms: string;               // bộ ký giữ khóa này; hiện chỉ có 'local'
  status: KeyStatus;
  createdAt: string;
}

export interface StoredDid {
  did: string;
  label?: string;
  status: DidStatus;
  keys: StoredKey[];
}

interface WalletData {
  version: 1;
  dids: Record<string, StoredDid>;
  looseKeys?: StoredKey[];
}

export const WALLET_PATH = process.env.DID_CLI_WALLET ?? join(homedir(), '.did-cli', 'wallet.json');

export const newKeyRef = () => 'k-' + randomBytes(6).toString('hex');

export class Wallet {
  private data: WalletData;

  private constructor(data: WalletData) {
    this.data = data;
    this.data.dids ??= {};
    this.data.looseKeys ??= [];
    // Ví của bản did-cli trước không có keyRef / kms
    for (const k of this.allKeys()) {
      if (!k.keyRef) { k.keyRef = newKeyRef(); this.migrated = true; }
      if (!k.kms) { k.kms = 'local'; this.migrated = true; }
    }
  }

  private migrated = false;

  static load(): Wallet {
    if (!existsSync(WALLET_PATH)) return new Wallet({ version: 1, dids: {}, looseKeys: [] });
    const w = new Wallet(JSON.parse(readFileSync(WALLET_PATH, 'utf8')));
    if (w.migrated) w.save();   // lưu lại keyRef cho ví của bản cũ, để keyRef không đổi giữa các lần chạy
    return w;
  }

  save(): void {
    mkdirSync(dirname(WALLET_PATH), { recursive: true });
    const tmp = WALLET_PATH + '.tmp';
    writeFileSync(tmp, JSON.stringify(this.data, null, 2), { mode: 0o600 });
    renameSync(tmp, WALLET_PATH);   // ghi nguyên khối, không để tệp ví dở dang
    chmodSync(WALLET_PATH, 0o600);  // chỉ chủ sở hữu được đọc/ghi
  }

  listDids(): StoredDid[] { return Object.values(this.data.dids); }
  looseKeys(): StoredKey[] { return this.data.looseKeys!; }
  getDid(did: string): StoredDid | undefined { return this.data.dids[did]; }

  allKeys(): StoredKey[] {
    return [...this.data.looseKeys!, ...this.listDids().flatMap((d) => d.keys)];
  }

  activeKeys(did: string): StoredKey[] {
    return (this.getDid(did)?.keys ?? []).filter((k) => k.status === 'ACTIVE');
  }

  findByRef(keyRef: string): StoredKey | undefined { return this.allKeys().find((k) => k.keyRef === keyRef); }
  findByKid(kid: string): StoredKey | undefined { return this.allKeys().find((k) => k.kid === kid); }
  findByX(x: string): StoredKey | undefined { return this.allKeys().find((k) => k.publicJwk.x === x); }

  /** keygen: khóa mới chưa gắn DID */
  addLooseKey(key: Omit<StoredKey, 'status' | 'createdAt'>): StoredKey {
    const stored: StoredKey = { ...key, status: 'PENDING', createdAt: new Date().toISOString() };
    this.data.looseKeys!.push(stored);
    this.save();
    return stored;
  }

  /**
   * Gắn khóa vào DID ở trạng thái PENDING, TRƯỚC khi trả chữ ký. Nếu giao dịch đã lên mạng mà kết nối
   * bị gián đoạn, Client vẫn còn khóa để kiểm soát DID.
   */
  attachPending(did: string, kid: string, key: StoredKey, label?: string): void {
    this.data.looseKeys = this.data.looseKeys!.filter((k) => k !== key);
    if (!this.data.dids[did]) this.data.dids[did] = { did, label, status: 'PENDING', keys: [] };
    const d = this.data.dids[did];
    if (!d.keys.includes(key)) d.keys.push(key);
    key.kid = kid;
    key.status = key.status === 'ACTIVE' ? 'ACTIVE' : 'PENDING';
    this.save();
  }

  /**
   * Đối chiếu kho khóa với DID Document hiện hành trên mạng:
   * khóa có trên mạng -> ACTIVE; khóa đang ACTIVE mà không còn trên mạng -> REPLACED;
   * khóa PENDING không có trên mạng giữ nguyên (thao tác chưa được ghi).
   */
  applyLedgerState(did: string, didDocument: any | null, deactivated: boolean): string[] {
    const d = this.getDid(did);
    if (!d) return [];
    const changes: string[] = [];
    if (didDocument) {
      const ledgerX = (didDocument.verificationMethod ?? []).map((vm: any) => vm?.publicKeyJwk?.x);
      for (const k of d.keys) {
        const next: KeyStatus = ledgerX.includes(k.publicJwk.x) ? 'ACTIVE' : k.status === 'PENDING' ? 'PENDING' : 'REPLACED';
        if (next !== k.status) { changes.push(`${frag(k.kid)}: ${k.status} -> ${next}`); k.status = next; }
      }
      const nextDid: DidStatus = deactivated ? 'DEACTIVATED' : 'ACTIVE';
      if (d.status !== nextDid) { changes.push(`DID: ${d.status} -> ${nextDid}`); d.status = nextDid; }
    }
    this.save();
    return changes;
  }

  /** Bỏ khóa PENDING chưa từng lên mạng (và DID nếu không còn khóa nào) */
  discardPending(did: string, keyRef: string): boolean {
    const d = this.getDid(did);
    if (!d) return false;
    const before = d.keys.length;
    d.keys = d.keys.filter((k) => !(k.keyRef === keyRef && k.status === 'PENDING'));
    if (d.status === 'PENDING' && d.keys.length === 0) delete this.data.dids[did];
    this.save();
    return d.keys.length !== before;
  }
}

export const frag = (kid?: string) => (kid ? kid.split('#')[1] ?? kid : '(chưa gắn DID)');

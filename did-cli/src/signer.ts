/**
 * Bộ ký: nơi giữ khóa bí mật và tạo chữ ký. Phần còn lại của Client (đối chiếu, xác nhận, kho trạng thái)
 * không phụ thuộc bộ ký cụ thể. Muốn dùng một ví bên ngoài hoặc thiết bị phần cứng, chỉ cần viết thêm một lớp
 * cài đặt giao diện Signer: sinh khóa Ed25519 và ký một dãy byte tùy ý.
 */
import { generateKeyPairSync, createPrivateKey, sign } from 'node:crypto';
import type { PublicJwk, PrivateJwk, StoredKey } from './wallet.ts';

export interface Signer {
  readonly name: string;
  /** Sinh cặp khóa Ed25519; trả khóa công khai và (nếu bộ ký giữ khóa tại kho này) khóa bí mật */
  createKey(): Promise<{ publicJwk: PublicJwk; privateJwk?: PrivateJwk }>;
  /** Ký dãy byte; Ed25519 ký trực tiếp, không băm trước. Trả chữ ký 64 byte */
  sign(key: StoredKey, data: Uint8Array): Promise<Uint8Array>;
}

/** Bộ ký cục bộ: khóa bí mật nằm trong tệp kho khóa của did-cli */
export class LocalSigner implements Signer {
  readonly name = 'local';

  async createKey() {
    const { privateKey } = generateKeyPairSync('ed25519');
    const jwk = privateKey.export({ format: 'jwk' }) as PrivateJwk;
    return {
      publicJwk: { kty: jwk.kty, crv: jwk.crv, x: jwk.x },
      privateJwk: { kty: jwk.kty, crv: jwk.crv, x: jwk.x, d: jwk.d },
    };
  }

  async sign(key: StoredKey, data: Uint8Array) {
    if (!key.privateJwk) throw new Error(`Khóa ${key.keyRef} không do bộ ký cục bộ giữ`);
    const privateKey = createPrivateKey({ key: key.privateJwk as any, format: 'jwk' });
    return new Uint8Array(sign(null, data, privateKey));
  }
}

export function signerFor(kms: string): Signer {
  if (kms === 'local') return new LocalSigner();
  throw new Error(`Chưa hỗ trợ bộ ký "${kms}". Hiện có: local`);
}

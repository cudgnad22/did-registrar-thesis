/**
 * Đọc khóa công khai Ed25519 từ một Verification Method ở hai dạng ứng dụng hỗ trợ:
 *   JsonWebKey2020             publicKeyJwk { kty: OKP, crv: Ed25519, x }
 *   Ed25519VerificationKey2020 publicKeyMultibase "z" + base58btc(0xed 0x01 + 32 byte)
 * Kho khóa lưu khóa ở dạng JWK; mọi so sánh khóa dùng x (base64url của 32 byte) làm chuẩn chung.
 */
const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

function base58Decode(s: string): Buffer | null {
  let n = 0n;
  for (const c of s) { const i = B58.indexOf(c); if (i < 0) return null; n = n * 58n + BigInt(i); }
  let hex = n === 0n ? '' : n.toString(16); if (hex.length % 2) hex = '0' + hex;
  const lead = s.match(/^1*/)![0].length;
  return Buffer.concat([Buffer.alloc(lead), Buffer.from(hex, 'hex')]);
}

function base58Encode(buf: Buffer): string {
  let n = BigInt('0x' + (buf.toString('hex') || '0')); let s = '';
  while (n > 0n) { s = B58[Number(n % 58n)] + s; n /= 58n; }
  for (const b of buf) { if (b === 0) s = '1' + s; else break; }
  return s;
}

/** x (base64url của 32 byte) của khóa trong Verification Method, hoặc null nếu kiểu/dạng khóa không hỗ trợ */
export function keyX(vm: any): string | null {
  if (vm?.type === 'JsonWebKey2020' && vm.publicKeyJwk?.kty === 'OKP' && vm.publicKeyJwk?.crv === 'Ed25519' && typeof vm.publicKeyJwk.x === 'string') {
    return Buffer.from(vm.publicKeyJwk.x, 'base64url').length === 32 ? vm.publicKeyJwk.x : null;
  }
  if (vm?.type === 'Ed25519VerificationKey2020' && typeof vm.publicKeyMultibase === 'string' && vm.publicKeyMultibase.startsWith('z')) {
    const b = base58Decode(vm.publicKeyMultibase.slice(1));
    if (b && b.length === 34 && b[0] === 0xed && b[1] === 0x01) return b.subarray(2).toString('base64url');
  }
  return null;
}

/** Chuỗi khóa đúng như nó xuất hiện trong dữ liệu cần ký (protobuf của cheqd giữ nguyên dạng được gửi) */
export function keyMaterial(vm: any): string | null {
  if (vm?.type === 'Ed25519VerificationKey2020') return typeof vm.publicKeyMultibase === 'string' ? vm.publicKeyMultibase : null;
  return typeof vm?.publicKeyJwk?.x === 'string' ? vm.publicKeyJwk.x : null;
}

/** Dạng multibase của một khóa x, để người dùng tự soạn DID Document kiểu Ed25519VerificationKey2020 */
export function multibaseOf(x: string): string {
  return 'z' + base58Encode(Buffer.concat([Buffer.from([0xed, 0x01]), Buffer.from(x, 'base64url')]));
}

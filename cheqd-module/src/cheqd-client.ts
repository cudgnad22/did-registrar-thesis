/**
 * Kết nối tới mạng cheqd thông qua @cheqd/sdk.
 * Chỉ file này giữ ví trả phí (fee payer). Khóa kiểm soát DID không bao giờ đi qua đây.
 */
import { DirectSecp256k1HdWallet } from '@cosmjs/proto-signing';
import { createCheqdSDK, DIDModule, CheqdNetwork } from '@cheqd/sdk';
import { config, ModuleError, Operation } from './config.js';

type Connection = { sdk: any; feePayer: string };
let connection: Promise<Connection> | null = null;

/** Khởi tạo SDK một lần, dùng lại cho mọi request (tương tự một @Bean singleton) */
export function getConnection(): Promise<Connection> {
  if (!connection) {
    connection = (async () => {
      if (!config.feePayerMnemonic) throw new Error('Thiếu biến môi trường FEE_PAYER_MNEMONIC');
      const wallet = await DirectSecp256k1HdWallet.fromMnemonic(config.feePayerMnemonic, { prefix: 'cheqd' });
      const [{ address }] = await wallet.getAccounts();
      const sdk = await createCheqdSDK({
        modules: [DIDModule as any],
        rpcUrl: config.rpcUrl,
        wallet,
        network: CheqdNetwork.Testnet,
      });
      return { sdk, feePayer: address };
    })();
    // Nếu khởi tạo lỗi (ví dụ localnet chưa chạy) thì cho phép thử lại ở request sau
    connection.catch(() => { connection = null; });
  }
  return connection;
}

/** Lỗi kết nối tới RPC -> 502 để Java biết là lỗi hạ tầng, có thể thử lại */
export function isConnectionError(e: any): boolean {
  const text = `${e?.message ?? ''} ${e?.cause?.code ?? ''}`;
  return /fetch failed|ECONNREFUSED|ENOTFOUND|ETIMEDOUT/i.test(text);
}

/** Đọc DID Document hiện hành từ mạng. Trả về null nếu DID chưa tồn tại. */
export async function queryDid(did: string): Promise<{ didDocument: any; didDocumentMetadata: any } | null> {
  const { sdk } = await getConnection();
  try {
    return await sdk.queryDidDoc(did, { sdk });
  } catch (e: any) {
    if (isConnectionError(e)) throw new ModuleError(502, 'LEDGER_UNAVAILABLE', e.message);
    if (/not found/i.test(e?.message ?? '')) return null;
    throw e;
  }
}

/**
 * Gửi giao dịch với chữ ký tạo sẵn (SignInfo) => Client-managed Secret.
 * Thứ tự tham số theo @cheqd/sdk 5.5.1:
 *   (signInputs, didPayload, address, fee, memo, versionId, feeOptions, context)
 */
export async function broadcast(
  operation: Operation,
  didPayload: any,
  versionId: string,
  signatures: { verificationMethodId: string; signature: Uint8Array }[],
) {
  const { sdk, feePayer } = await getConnection();
  const fee = { amount: [{ denom: 'ncheq', amount: config.fees[operation] }], gas: config.gas, payer: feePayer };
  const fn = {
    create: 'createDidDocTx',
    update: 'updateDidDocTx',
    deactivate: 'deactivateDidDocTx',
  }[operation];
  try {
    return await sdk[fn](signatures, didPayload, feePayer, fee, undefined, versionId, undefined, { sdk });
  } catch (e: any) {
    if (isConnectionError(e)) throw new ModuleError(502, 'LEDGER_UNAVAILABLE', e.message);
    // SDK tự kiểm tra trước khi gửi (đặc tả, đủ chữ ký...) và ném lỗi
    throw new ModuleError(422, 'SDK_REJECTED', e?.message ?? String(e));
  }
}

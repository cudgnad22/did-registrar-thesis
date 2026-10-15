/**
 * Cấu hình của module, đọc từ biến môi trường.
 * Tương đương application.yml bên Java.
 */
export const config = {
  port: Number(process.env.PORT ?? 3000),
  rpcUrl: process.env.RPC_URL ?? 'http://127.0.0.1:27157',
  feePayerMnemonic: process.env.FEE_PAYER_MNEMONIC ?? '',
  gas: process.env.GAS ?? '400000',
  fees: {
    create: process.env.CREATE_DID_FEE ?? '50000000000', // ncheq
    update: process.env.UPDATE_DID_FEE ?? '25000000000',
    deactivate: process.env.DEACTIVATE_DID_FEE ?? '10000000000',
  },
};

export type Operation = 'create' | 'update' | 'deactivate';

/**
 * Lỗi xảy ra TRƯỚC khi gửi giao dịch lên mạng (dữ liệu sai, chữ ký sai, DID không tồn tại...).
 * status: mã HTTP trả về cho Java; code: mã lỗi để Java ánh xạ sang trạng thái thao tác.
 */
export class ModuleError extends Error {
  constructor(public status: number, public code: string, message: string) {
    super(message);
  }
}

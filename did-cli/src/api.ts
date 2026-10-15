/**
 * Bộ ký chỉ gọi Registrar để ĐỌC: tra cứu DID Document hiện hành và trạng thái thao tác,
 * phục vụ việc đối chiếu kho khóa với mạng. Các lần gọi create/update/deactivate do giao diện
 * của Registrar (hoặc người dùng qua Swagger UI) thực hiện.
 */
export const API_URL = process.env.DID_API_URL ?? 'http://localhost:8085';

export class ApiError extends Error {
  status: number;
  code: string;
  constructor(status: number, code: string, message: string) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

async function get(path: string): Promise<any> {
  let res: Response;
  try {
    res = await fetch(`${API_URL}${path}`, { headers: { Accept: 'application/json' } });
  } catch (e: any) {
    throw new ApiError(0, 'CONNECTION_FAILED', `Không kết nối được tới ${API_URL} (${e?.cause?.code ?? e.message}). Kiểm tra DID_API_URL.`);
  }
  const text = await res.text();
  let json: any = null;
  try { json = text ? JSON.parse(text) : null; } catch { json = { raw: text }; }
  if (res.status >= 400) throw new ApiError(res.status, json?.error?.code ?? 'HTTP_ERROR', json?.error?.message ?? text);
  return json;
}

const enc = encodeURIComponent;

export const api = {
  resolve: (did: string) => get(`/api/v1/dids/${enc(did)}`),
  getOperation: (jobId: string) => get(`/api/v1/did-operations/${enc(jobId)}`),
};

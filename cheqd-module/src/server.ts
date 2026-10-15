/**
 * HTTP server của module did:cheqd. Tương đương @RestController bên Java.
 * Chỉ dành cho phần điều phối (Java) gọi nội bộ, không mở ra Internet.
 */
import express, { Request, Response, NextFunction } from 'express';
import { config, ModuleError } from './config.js';
import { getConnection } from './cheqd-client.js';
import { prepare, submit, resolve } from './service.js';

const app = express();
app.use(express.json({ limit: '1mb' }));

// Bọc hàm async để lỗi được chuyển tới error handler bên dưới
const handle = (fn: (req: Request) => Promise<any>) =>
  (req: Request, res: Response, next: NextFunction) => fn(req).then((body) => res.json(body)).catch(next);

// Kiểm tra module còn sống và kết nối được tới mạng
app.get('/health', handle(async () => {
  const { feePayer } = await getConnection();
  return { status: 'ok', rpcUrl: config.rpcUrl, feePayer };
}));

app.post('/internal/cheqd/prepare', handle(async (req) => {
  console.log(`[prepare] ${req.body?.operation} ${req.body?.did}`);
  return prepare(req.body);
}));

app.post('/internal/cheqd/submit', handle(async (req) => {
  console.log(`[submit] ${req.body?.operation} ${req.body?.did} versionId=${req.body?.versionId}`);
  const result = await submit(req.body);
  console.log(`[submit] kết quả code=${result.code} height=${result.height}`);
  return result;
}));

app.get('/internal/cheqd/dids/:did', handle(async (req) => resolve(req.params.did)));

// Error handler: lỗi nghiệp vụ -> mã HTTP tương ứng; lỗi khác -> 500
app.use((err: any, _req: Request, res: Response, _next: NextFunction) => {
  if (err instanceof ModuleError) {
    console.warn(`[lỗi] ${err.code}: ${err.message}`);
    return res.status(err.status).json({ error: { code: err.code, message: err.message } });
  }
  if (err?.type === 'entity.parse.failed') {
    return res.status(400).json({ error: { code: 'INVALID_JSON', message: 'Body không phải JSON hợp lệ' } });
  }
  console.error('[lỗi không xác định]', err);
  res.status(500).json({ error: { code: 'INTERNAL_ERROR', message: err?.message ?? String(err) } });
});

app.listen(config.port, '0.0.0.0', () => {
  console.log(`Module did:cheqd lắng nghe tại cổng ${config.port}, RPC: ${config.rpcUrl}`);
});

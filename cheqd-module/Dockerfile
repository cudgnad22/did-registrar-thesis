# Module did:cheqd - chạy TypeScript trực tiếp bằng tsx trên Node.js 22
FROM node:22-alpine
WORKDIR /app

# Cài thư viện trước để tận dụng cache của Docker
COPY package.json package-lock.json ./
RUN npm ci --omit=dev

COPY src ./src

ENV NODE_ENV=production \
    PORT=3000
# Chạy bằng user không phải root
USER node
EXPOSE 3000
CMD ["node", "--import", "tsx", "src/server.ts"]

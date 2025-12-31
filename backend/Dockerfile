# ✅ Corrected Dockerfile
FROM node:18.20.0-alpine

RUN addgroup -g 1001 -S nodejs && \
    adduser -u 1001 -S nodejs -G nodejs

WORKDIR /app

# ✅ Copy from backend/ subfolder
COPY backend/package*.json ./

RUN npm ci --only=production --no-audit --no-fund && \
    mkdir -p /app/uploads && \
    chown -R nodejs:nodejs /app

# ✅ Copy entire backend code
COPY backend/ .

USER nodejs

EXPOSE 10000

CMD ["npm", "start"]

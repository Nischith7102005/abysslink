FROM node:18.20.0-alpine

RUN addgroup -g 1001 -S nodejs && \
    adduser -u 1001 -S nodejs -G nodejs

WORKDIR /app

# Copy package files first (for better layer caching)
COPY package*.json ./

RUN npm ci --only=production --no-audit --no-fund && \
    mkdir -p /app/uploads && \
    chown -R nodejs:nodejs /app

# Copy application code
COPY . .

USER nodejs

EXPOSE 10000

CMD ["npm", "start"]

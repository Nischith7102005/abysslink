FROM node:18.20.0-alpine

RUN addgroup -g 1001 -S nodejs && \
    adduser -u 1001 -S nodejs -G nodejs

WORKDIR /app

# Copy package files first
COPY package*.json ./

# Use 'npm install' instead of 'npm ci' to resolve lockfile sync issues
RUN npm install --only=production --no-audit --no-fund && \
    mkdir -p /app/uploads && \
    chown -R nodejs:nodejs /app

# Copy application code
COPY . .

USER nodejs

EXPOSE 10000

CMD ["npm", "start"]

# Use specific Node version
FROM node:18.20.0-alpine

# Create non-root user
RUN addgroup -g 1001 -S nodejs && \
    adduser -u 1001 -S nodejs -G nodejs

WORKDIR /app

# Install deps
COPY package*.json ./
RUN npm ci --only=production --no-audit --no-fund && \
    mkdir -p /app/uploads && \
    chown -R nodejs:nodejs /app

# Copy code
COPY --chown=nodejs:nodejs . .

# Non-root user
USER nodejs

EXPOSE 10000

# Use npm start to respect "type": "module"
CMD ["npm", "start"]

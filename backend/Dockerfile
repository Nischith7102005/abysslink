# Use a specific, pinned version for reproducibility
FROM node:18.20.0-alpine

# Create non-root user
RUN addgroup -g 1001 -S nodejs && \
    adduser -u 1001 -S nodejs -G nodejs

# Set working directory
WORKDIR /app

# Copy package files and install deps
COPY package*.json ./
RUN npm ci --only=production --no-audit --no-fund && \
    mkdir -p /app/uploads && \
    chown -R nodejs:nodejs /app

# Switch to non-root user
USER nodejs

# Copy app code
COPY --chown=nodejs:nodejs . .

# Expose port
EXPOSE 10000

# Run via npm start (respects "type": "module")
CMD ["npm", "start"]

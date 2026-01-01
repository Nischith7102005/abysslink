FROM node:20-alpine AS builder
RUN addgroup -g 1001 -S app && adduser -u 1001 -S app -G app
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production --no-audit --no-fund --no-optional && \
    npm cache clean --force

FROM node:20-alpine
RUN apk --no-cache upgrade && \
    apk add --no-cache dumb-init libseccomp wget ca-certificates && \
    rm -rf /var/cache/apk/*
RUN echo 'kernel.dmesg_restrict=1' >> /etc/sysctl.conf && \
    echo 'fs.protected_regular=2' >> /etc/sysctl.conf

RUN addgroup -g 1001 -S app && adduser -u 1001 -S app -G app
WORKDIR /app
COPY --from=builder --chown=app:app /app/node_modules ./node_modules
COPY --from=builder --chown=app:app /app/server.js .
COPY --from=builder --chown=app:app /app/package*.json .

RUN mkdir -p /app/uploads && chown app:app /app/uploads && chmod 700 /app/uploads

USER app
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
  CMD wget --quiet --tries=1 --spider http://localhost:10000/api/health || exit 1
EXPOSE 10000

ENV NODE_OPTIONS="--frozen-intrinsics --secure-heap=1024 --no-addons --no-global-search-paths"
ENTRYPOINT ["dumb-init", "--"]
CMD ["node", "--no-expose-gc", "server.js"]

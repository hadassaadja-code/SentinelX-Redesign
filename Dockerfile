# SentinelX — image unique (API + worker) basée sur l'image Playwright (navigateurs inclus).
# Étape 1 : compilation du frontend
FROM node:22-bookworm-slim AS web
WORKDIR /web
COPY web/package*.json ./
RUN npm ci
COPY web/ ./
RUN npm run build

# Étape 2 : serveur avec navigateurs Playwright (Chromium, Firefox, WebKit)
FROM mcr.microsoft.com/playwright:v1.65.1-noble AS server
ENV NODE_ENV=production \
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright \
    DATA_DIR=/data \
    HOST=0.0.0.0 \
    PORT=3000
WORKDIR /app/server
COPY server/package*.json ./
RUN npm ci --omit=dev && npm cache clean --force
COPY server/ ./
# Schéma PostgreSQL généré à partir du schéma de référence, client Prisma compilé pour PostgreSQL
RUN node scripts/make-postgres-schema.mjs && npx prisma generate --schema prisma/schema.postgresql.prisma
COPY --from=web /web/dist /app/web/dist
RUN mkdir -p /data && chown -R pwuser:pwuser /data /app
USER pwuser
EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=5s --retries=3 CMD node -e "fetch('http://127.0.0.1:3000/api/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
# Applique le schéma puis démarre (API + worker selon PROCESS_ROLE)
CMD ["sh", "-c", "npx prisma db push --schema prisma/schema.postgresql.prisma --skip-generate --accept-data-loss && npx tsx src/index.ts"]

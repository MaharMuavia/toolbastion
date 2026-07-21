FROM node:22-bookworm-slim@sha256:6c74791e557ce11fc957704f6d4fe134a7bc8d6f5ca4403205b2966bd488f6b3 AS builder
WORKDIR /app
COPY package.json package-lock.json ./
COPY apps ./apps
COPY packages ./packages
COPY examples ./examples
RUN npm ci --no-fund --no-audit
COPY . .
RUN npm run artifact:prepare && npm run build:standalone && npm prune --omit=dev

FROM node:22-bookworm-slim@sha256:6c74791e557ce11fc957704f6d4fe134a7bc8d6f5ca4403205b2966bd488f6b3 AS runtime
ENV NODE_ENV=production TOOLBASTION_API_HOST=0.0.0.0
WORKDIR /app
COPY --from=builder --chown=node:node /app/package.json /app/package-lock.json ./
COPY --from=builder --chown=node:node /app/node_modules ./node_modules
COPY --from=builder --chown=node:node /app/dist/standalone ./dist/standalone
COPY --from=builder --chown=node:node /app/apps/dashboard/dist ./apps/dashboard/dist
COPY --from=builder --chown=node:node /app/examples/benign-server/dist ./examples/benign-server/dist
COPY --from=builder --chown=node:node /app/examples/vulnerable-server/dist ./examples/vulnerable-server/dist
COPY --from=builder --chown=node:node /app/fixtures ./fixtures
COPY --from=builder --chown=node:node /app/schemas ./schemas
COPY --from=builder --chown=node:node /app/toolbastion.config.example.yaml ./toolbastion.config.example.yaml
COPY --from=builder --chown=node:node /app/LICENSE ./LICENSE
USER node
EXPOSE 4782
HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=3 CMD ["node", "-e", "fetch('http://127.0.0.1:4782/api/health').then(r=>{if(!r.ok)process.exit(1)}).catch(()=>process.exit(1))"]
CMD ["node", "dist/standalone/index.js", "dashboard", "--config", "toolbastion.config.example.yaml", "--port", "4782", "--expose"]

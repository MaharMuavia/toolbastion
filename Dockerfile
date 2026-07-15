FROM node:22-bookworm-slim AS builder
WORKDIR /app
COPY package.json package-lock.json ./
COPY apps ./apps
COPY packages ./packages
COPY examples ./examples
RUN npm ci --no-fund --no-audit
COPY . .
RUN npm run build && npm run evaluate && npm run snapshot && npm prune --omit=dev

FROM node:22-bookworm-slim AS runtime
ENV NODE_ENV=production WARDEN_API_HOST=0.0.0.0
WORKDIR /app
COPY --from=builder --chown=node:node /app /app
USER node
EXPOSE 4782
HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=3 CMD ["node", "-e", "fetch('http://127.0.0.1:4782/api/health').then(r=>{if(!r.ok)process.exit(1)}).catch(()=>process.exit(1))"]
CMD ["node", "apps/cli/dist/index.js", "dashboard", "--config", "warden.config.example.yaml", "--port", "4782"]

FROM node:24-alpine@sha256:d32cdf619f63fe0471182d08996dd516c6275bb5fd31ae06e55a570bd9e1ad43

ENV NODE_ENV=production PORT=8080 KEYLESS_CHECKPOINT_PATH=docs/evidence/K0_CHECKPOINT_2026-08-13.json
WORKDIR /app
COPY package.json ./
COPY src ./src
COPY console ./console
COPY docs/evidence/K0_CHECKPOINT_2026-08-13.json ./docs/evidence/K0_CHECKPOINT_2026-08-13.json
RUN rm -rf -- \
  /usr/local/lib/node_modules/npm \
  /usr/local/lib/node_modules/corepack \
  /usr/local/bin/npm \
  /usr/local/bin/npx \
  /usr/local/bin/corepack \
  /usr/local/bin/yarn \
  /usr/local/bin/yarnpkg
USER node
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:8080/healthz').then((r)=>process.exit(r.status===204?0:1)).catch(()=>process.exit(1))"
CMD ["node", "console/server.mjs"]

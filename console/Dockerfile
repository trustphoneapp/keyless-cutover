FROM node:24-alpine@sha256:d32cdf619f63fe0471182d08996dd516c6275bb5fd31ae06e55a570bd9e1ad43

ENV NODE_ENV=production PORT=8080 KEYLESS_CHECKPOINT_PATH=docs/evidence/K0_CHECKPOINT_2026-08-13.json
WORKDIR /app
COPY package.json ./
COPY src ./src
COPY console ./console
COPY docs/evidence/K0_CHECKPOINT_2026-08-13.json ./docs/evidence/K0_CHECKPOINT_2026-08-13.json
USER node
CMD ["node", "console/server.mjs"]


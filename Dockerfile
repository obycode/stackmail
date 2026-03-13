FROM node:20-slim AS build
WORKDIR /app
COPY package.json ./
COPY packages/crypto/package.json ./packages/crypto/
COPY packages/server/package.json ./packages/server/
COPY packages/client/package.json ./packages/client/
COPY packages/web/package.json ./packages/web/
RUN npm install --workspaces
COPY tsconfig.json ./
COPY packages/crypto ./packages/crypto
COPY packages/server ./packages/server
COPY packages/client ./packages/client
COPY packages/web ./packages/web
RUN npm run build --workspace=packages/crypto
RUN npm run build --workspace=packages/server
RUN npm run build --workspace=packages/client
RUN npm run build --workspace=packages/web

FROM node:20-slim AS runtime
WORKDIR /app
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/packages/crypto/dist ./packages/crypto/dist
COPY --from=build /app/packages/crypto/package.json ./packages/crypto/
COPY --from=build /app/packages/server/dist ./packages/server/dist
COPY --from=build /app/packages/server/web ./packages/server/web
COPY --from=build /app/packages/server/package.json ./packages/server/
COPY --from=build /app/packages/client/dist ./packages/client/dist
COPY --from=build /app/packages/client/package.json ./packages/client/
COPY package.json ./
VOLUME ["/data"]
ENV MAILSLOT_DB_FILE=/data/mailslot.db
ENV MAILSLOT_HOST=0.0.0.0
ENV MAILSLOT_PORT=8800
EXPOSE 8800
CMD ["node", "packages/server/dist/index.js"]

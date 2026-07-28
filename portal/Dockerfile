FROM node:20-alpine AS builder
WORKDIR /app
COPY package.json ./
RUN npm install
COPY tailwind.config.js ./
COPY public/ ./public/
COPY src/ ./src/
RUN ./node_modules/.bin/tailwindcss -i ./public/css/tailwind-input.css -o ./public/css/tailwind-output.css --minify
RUN npm prune --omit=dev

FROM node:20-alpine AS runtime
WORKDIR /app
RUN apk add --no-cache tini
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/public/css/tailwind-output.css ./public/css/tailwind-output.css
COPY package.json ./
COPY src/ ./src/
COPY public/ ./public/
RUN chown -R node:node /app
USER node
EXPOSE 3000
ENTRYPOINT ["/sbin/tini", "--"]
CMD ["node", "src/app.js"]

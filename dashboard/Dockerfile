# syntax=docker/dockerfile:1.6
FROM node:20-alpine

WORKDIR /app

RUN apk add --no-cache curl

COPY package.json package-lock.json* ./
RUN if [ -f package-lock.json ]; then npm ci; else npm install; fi

COPY . .

EXPOSE 3000

HEALTHCHECK --interval=15s --timeout=5s --start-period=20s --retries=5 \
  CMD curl -fsS http://127.0.0.1:3000/ || exit 1

CMD ["npm", "run", "dev", "--", "--host", "0.0.0.0", "--port", "3000"]

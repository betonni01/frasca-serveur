FROM --platform=linux/amd64 node:22-alpine
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY tsconfig.json ./
COPY src ./src
EXPOSE 10000
CMD ["npx", "tsx", "src/index.ts"]

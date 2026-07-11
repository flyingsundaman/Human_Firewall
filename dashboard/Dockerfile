FROM node:22-alpine

# 'node' user sudah ada di image node:alpine by default
# Tidak perlu addgroup/adduser — langsung pakai

WORKDIR /app

# Install dependencies dengan ownership langsung benar
COPY --chown=node:node package.json package-lock.json ./
RUN npm ci

# Copy source code dengan ownership langsung benar
COPY --chown=node:node . .

# Build the Next.js app (jalan sebagai root, aman untuk build)
RUN npm run build

# Switch ke non-root user — tidak perlu chown -R lagi
USER node

EXPOSE 3000

CMD ["npm", "start"]

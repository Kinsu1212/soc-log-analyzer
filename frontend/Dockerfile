FROM node:20-alpine

WORKDIR /app

COPY package*.json ./
RUN npm ci

COPY . .

ENV NODE_ENV=production
ENV PORT=3000

EXPOSE 3000

# Build Next.js
RUN npm run build

# Run Next.js
CMD ["npm", "run", "start", "--", "-p", "3000"]
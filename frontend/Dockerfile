FROM node:20-alpine

WORKDIR /app

COPY package*.json ./
RUN npm ci

COPY . .

# --- ADD THESE TWO LINES ---
ARG NEXT_PUBLIC_API_BASE_URL
ENV NEXT_PUBLIC_API_BASE_URL=$NEXT_PUBLIC_API_BASE_URL
# ---------------------------

ENV NODE_ENV=production
ENV PORT=3000

EXPOSE 3000

# Build Next.js (It will now see the variable)
RUN npm run build

CMD ["npm", "run", "start", "--", "-p", "3000"]
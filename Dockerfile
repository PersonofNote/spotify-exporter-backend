# syntax=docker/dockerfile:1
FROM node:20.18.0-slim

WORKDIR /app
ENV NODE_ENV=production

COPY package*.json ./
RUN npm ci

COPY . .

# Ensure sessions dir exists
RUN mkdir -p /app/sessions

EXPOSE 3000

CMD ["npm", "run", "start"]


# Multi-stage: build the static bundle, then serve it with nginx.
# Build-time API URL/token can be overridden with --build-arg;
# baked in at build time since this is a static SPA, not SSR.
FROM node:22-slim AS build
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . .
ARG VITE_API_BASE_URL=http://localhost:8000
ARG VITE_API_TOKEN=dev-token-change-me
ENV VITE_API_BASE_URL=$VITE_API_BASE_URL
ENV VITE_API_TOKEN=$VITE_API_TOKEN
RUN npm run build

FROM nginx:alpine
COPY --from=build /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80

# Multi-stage build exercising the collector's edge cases.
FROM node:16-alpine AS build
WORKDIR /app
COPY . .
RUN npm ci && npm run build

# Stage reference — must NOT be treated as a public image.
FROM build AS test
RUN npm test

# Unpinned base image — should be flagged.
FROM nginx
COPY --from=build /app/dist /usr/share/nginx/html

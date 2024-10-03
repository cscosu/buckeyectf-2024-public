FROM golang:1.23-alpine AS backend
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY cmd cmd
COPY internal internal
RUN go build -o main cmd/api/main.go

FROM node:22 AS frontend
WORKDIR /app
RUN npm install -g pnpm
COPY frontend/package.json frontend/pnpm-lock.yaml frontend/svelte.config.js frontend/vite.config.ts ./
RUN pnpm install
COPY frontend .
RUN pnpm build

FROM alpine
WORKDIR /app
ENV PORT=8080
COPY --from=backend /app/main .
COPY --from=frontend /app/build ./frontend/build
CMD ["./main"]

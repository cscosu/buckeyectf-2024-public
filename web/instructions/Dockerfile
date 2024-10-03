FROM rust:1.81.0 AS builder
WORKDIR /app
COPY rust-toolchain.toml .
RUN cargo install --locked trunk
COPY Cargo.toml Cargo.lock index.html .
COPY src src
COPY public public
RUN trunk build --release

FROM nginx
COPY --from=builder /app/dist /usr/share/nginx/html

FROM ubuntu@sha256:075680e983398fda61b1ac59ad733ad81d18df4bc46411666bb8a03fb9ea0195 as app
RUN apt-get update && \
    apt-get install -y \
    build-essential gcc uidmap && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY . ./

RUN make && \
    rm Makefile chall.c && \
    chmod 440 flag.txt && \
    chmod 550 chall

FROM ghcr.io/cscosu/jail:sha-7f273770804b4caac02c629fe196fefe9e949446
COPY --from=app / /srv

WORKDIR /srv

RUN mv /srv/app/chall /srv/app/run && \
    chmod 444 /srv/app/flag.txt && \
    chmod 555 /srv/app/run

# jail configuration
ENV JAIL_TIME=300
ENV JAIL_CPU=100
ENV JAIL_PORT=1024
ENV JAIL_MEM=5M

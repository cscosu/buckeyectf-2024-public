FROM ubuntu@sha256:adbb90115a21969d2fe6fa7f9af4253e16d45f8d4c1e930182610c4731962658 AS app
RUN apt-get update && apt-get install -y gcc make wget libglib2.0-dev

WORKDIR /app
RUN wget https://github.com/riscv-collab/riscv-gnu-toolchain/releases/download/2024.08.06/riscv64-glibc-ubuntu-22.04-gcc-nightly-2024.08.06-nightly.tar.gz && \
    tar -xf riscv64-glibc-ubuntu-22.04-gcc-nightly-2024.08.06-nightly.tar.gz && \
    mv riscv /opt/riscv
COPY Makefile flag.txt spaceman.c run.sh ./
RUN make
RUN rm -rf riscv64-glibc-ubuntu-22.04-gcc-nightly-2024.08.06-nightly.tar.gz

FROM pwn.red/jail
COPY --from=app / /srv
ENV JAIL_TIME=60
RUN mv /srv/app/run.sh /srv/app/run

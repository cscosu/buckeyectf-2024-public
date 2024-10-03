FROM debian:bullseye AS nsjail

# Install nsjail

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get -y update && apt-get install -y \
    autoconf \
    bison \
    flex \
    gcc \
    g++ \
    git \
    libprotobuf-dev \
    libnl-route-3-dev \
    libtool \
    make \
    pkg-config \
    protobuf-compiler \
    uidmap

RUN git clone https://github.com/google/nsjail && \
cd nsjail && \
make -j8 && \
mv nsjail /bin && \
cd / && \
rm -rf nsjail

FROM python:3.13.0rc2-bullseye AS run

ENV DEBIAN_FRONTEND=noninteractive

COPY --from=nsjail /bin/nsjail /usr/bin/

RUN apt-get update && \
    apt-get install -y libprotobuf23 libnl-route-3-200 && \
    rm -rf /var/lib/apt/lists/*

RUN useradd -m ctf && \
    mkdir /chroot/ && \
    chown root:ctf /chroot && \
    chmod 770 /chroot

WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY homecooked ./homecooked
COPY static ./static
COPY templates/ ./templates
COPY main.py chef.py jail.cfg ./
COPY run.sh ./run.sh

USER ctf

ENV PYTHONUNBUFFERED=1

EXPOSE 8001
ENTRYPOINT [ "nsjail", "--config", "/app/jail.cfg", "--", "/bin/bash", "./run.sh" ]
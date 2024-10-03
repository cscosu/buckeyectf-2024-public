FROM python:3-slim

RUN apt-get update && \
apt-get install -y socat

WORKDIR /opt/app
COPY main.py flag.py ./
CMD socat -d -d -s TCP-LISTEN:1024,reuseaddr,fork EXEC:'timeout 120 python -u /opt/app/main.py',stderr

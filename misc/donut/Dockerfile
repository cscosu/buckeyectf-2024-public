FROM python:3.12-alpine3.20

RUN apk add socat

WORKDIR /app
COPY donuts.py flag.txt start_server.sh ./
COPY flag.txt /flag.txt
RUN chmod +x start_server.sh

EXPOSE 5000
ENTRYPOINT ["/app/start_server.sh"]
FROM debian@sha256:4f9b105ea78ff6e98385c617db07c27010f12267a50a90efb7651e9e29621ae4

RUN apt-get update && apt-get install -y socat openjdk-22-jdk

WORKDIR /app

COPY text-adventure.jar ./
COPY flag /flag

CMD socat -d -d -s TCP-LISTEN:5000,reuseaddr,fork EXEC:'timeout 300 java -jar text-adventure.jar',stderr
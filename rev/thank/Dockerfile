FROM ubuntu@sha256:adbb90115a21969d2fe6fa7f9af4253e16d45f8d4c1e930182610c4731962658 AS app
RUN apt-get update && apt-get install -y gcc make

WORKDIR /app
COPY Makefile flag.txt thank.c ./
RUN make thank
RUN rm Makefile thank.c

FROM pwn.red/jail
COPY --from=app / /srv
ENV JAIL_TIME=60
ENV JAIL_TMP_SIZE=16384
RUN mv /srv/app/thank /srv/app/run

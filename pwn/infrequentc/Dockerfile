FROM ubuntu AS app
FROM pwn.red/jail
COPY --from=app / /srv
COPY program/* /srv/app/
COPY flag.txt /srv/app/flag.txt

RUN mv /srv/app/infrequentc /srv/app/run && \
    chmod 444 /srv/app/flag.txt && \
    chmod 555 /srv/app/run

# jail configuration
ENV JAIL_TIME=300
ENV JAIL_CPU=1000
ENV JAIL_PORT=1024
ENV JAIL_MEM=5M

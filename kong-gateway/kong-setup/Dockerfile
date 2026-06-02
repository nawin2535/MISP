FROM kong:3.9
USER root
RUN mkdir -p /var/lib/apt/lists/partial && \
    chown -R _apt:root /var/lib/apt/lists && \
    apt-get update && \
    apt-get install -y postgresql-client telnet netcat-openbsd && \
    rm -rf /var/lib/apt/lists/*
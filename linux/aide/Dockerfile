# syntax=docker/dockerfile:1
ARG repo="docker.io" \
    base_image="alpine:3.22" \
    image_hash="85f2b723e106c34644cd5851d7e81ee87da98ac54672b29947c052a45d31dc2f"

FROM ${repo}/${base_image}@sha256:${image_hash}

RUN apk add --no-cache python3 py3-pip aide rsyslog && \
    pip install --no-cache-dir typing-extensions && \
    mkdir -p /var/backups/aide /etc/aide/aide.conf.d && \
    chown root:root /var/backups/aide /etc/aide /etc/aide/aide.conf.d && \
    chmod 750 /var/backups/aide /etc/aide /etc/aide/aide.conf.d

COPY configure_aide.py /configure_aide.py
COPY aidecheck.service /etc/systemd/system/aidecheck.service
COPY aidecheck.timer /etc/systemd/system/aidecheck.timer

RUN chmod 755 /configure_aide.py && \
    chmod 644 /etc/systemd/system/aidecheck.*

CMD ["python3", "/configure_aide.py", "--json"]
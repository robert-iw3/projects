FROM docker.io/ubuntu:25.10 AS builder
ARG DEBIAN_FRONTEND=noninteractive

RUN \
    apt-get update; \
    apt-get install -y \
        clang \
        llvm \
        libbpf-dev \
        linux-headers-$(uname -r) \
        make \
        linux-tools-common \
        linux-tools-generic; \
    rm -rf /var/lib/apt/lists/*

WORKDIR /build

COPY dev/probes /build/probes

RUN cd probes && make

# Use the same base as your host system for better compatibility
FROM docker.io/ubuntu:25.10
ARG DEBIAN_FRONTEND=noninteractive

RUN \
    apt-get update; \
    apt-get install -y \
        iproute2 \
        procps \
        auditd \
        curl \
        python3 \
        python3-venv \
        bpfcc-tools \
        python3-bpfcc; \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . /app
COPY --from=builder /build/probes/c2_probe.bpf.o /app/dev/probes/c2_probe.bpf.o

RUN python3 -m venv /app/venv
RUN /app/venv/bin/pip install --no-cache-dir -r requirements.txt
RUN mkdir -p /app/output

USER root
CMD ["/app/venv/bin/python", "dev/run_full_stack.py"]
FROM golang:1.23-alpine AS builder
RUN apk add --no-cache clang llvm libbpf-dev
WORKDIR /src
COPY . .
RUN ./scripts/generate-bpf.sh
RUN CGO_ENABLED=0 GOOS=linux go build -o /honeybr ./cmd/honeybr

FROM alpine:latest
RUN apk add --no-cache libbpf
COPY --from=builder /honeybr /usr/bin/honeybr
COPY rules.yaml /etc/honeybr/rules.yaml
CMD ["honeybr", "--rules=/etc/honeybr/rules.yaml"]
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    curl \
    gnupg \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN apt-get update && apt-get install -y \
    bpfcc-tools \
    libbpfcc \
    python3-bpfcc \
    linux-headers-generic \
    && rm -rf /var/lib/apt/lists/*

COPY ebpf_security_monitor.py /app/
WORKDIR /app

RUN chmod +x /app/ebpf_security_monitor.py

CMD ["python3", "/app/ebpf_security_monitor.py"]

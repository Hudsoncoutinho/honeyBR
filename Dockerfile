FROM golang:1.24-alpine AS builder
RUN apk add --no-cache clang llvm libbpf-dev linux-headers
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN go install github.com/cilium/ebpf/cmd/bpf2go@latest
RUN ./scripts/generate-bpf.sh
RUN CGO_ENABLED=0 GOOS=linux go build -o /honeybr ./cmd/honeybr

FROM alpine:3.20
RUN apk add --no-cache ca-certificates
COPY --from=builder /honeybr /usr/bin/honeybr
COPY rules.yaml /etc/honeybr/rules.yaml
EXPOSE 8080
CMD ["honeybr", "--rules=/etc/honeybr/rules.yaml", "--addr=:8080"]

#!/bin/sh
set -e

# -go-package is the Go package *name* (identifier), not the module import path.
bpf2go -go-package ebpf -output-dir internal/ebpf \
  -cc clang -target bpf honeybr bpf/honeybr.bpf.c -- \
  -I/usr/include/bpf \
  -O2 -g -Wall

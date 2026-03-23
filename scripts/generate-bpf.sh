#!/bin/sh
set -e

bpf2go -go-package github.com/hudsoncoutinho/honeybr/internal/ebpf \
  -cc clang -target bpf honeybr bpf/honeybr.bpf.c -- \
  -I/usr/include/bpf \
  -O2 -g -Wall

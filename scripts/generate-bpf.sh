#!/bin/sh
set -e

bpf2go -cc clang -target bpf honeybr bpf/honeybr.bpf.c -- \
  -I/usr/include/bpf \
  -O2 -g -Wall

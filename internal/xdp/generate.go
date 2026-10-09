// Package xdp loads and manages the Sentinel Shield XDP filter.
//
// The compiled BPF object is committed (filter_bpfel.o), so building the agent needs no
// clang. Regenerate it after editing bpf/filter.c with: go generate ./internal/xdp
package xdp

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -I/usr/include/x86_64-linux-gnu" -target bpfel -type src_stats -type block_val Filter bpf/filter.c -- -I bpf/headers

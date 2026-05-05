# hft_project
An experimental XDP layer with DPDK awareness order book# hft_project

A low-latency market data feed handler and order book engine, 
built to explore kernel-bypass networking techniques used in 
high-frequency trading infrastructure.

## Architecture

[Exchange Simulator] → UDP (port 9000)
↓
[XDP Feed Handler]     # kernel-space, bypasses network stack
↓ ring buffer (zero-copy)
[C++ Feed Loader]      # userspace, nanosecond timestamps
↓
[Lock-Free Order Book] # in progress
↓
[Strategy Layer]       # planned 


## Components

### XDP Feed Handler (C)
- Attaches to NIC at driver level via XDP hook
- Parses Ethernet → IP → UDP → market message
- Filters by exchange feed port (9000)
- Timestamps packets using kernel nanosecond clock
- Pushes parsed messages to userspace via lock-free ring buffer
- Zero-copy: kernel stack never touches feed packets

### Userspace Feed Loader (C++)
- Consumes messages from BPF ring buffer
- Measures kernel→userspace latency per message
- Designed to feed directly into order book

### Lock-Free Order Book (C++) — in progress
- L2/L3 limit order book
- Cache-aligned price level arrays
- No dynamic allocation in hot path
- Benchmarked with rdtsc

## Stack
- Kernel: Linux 6.14, XDP/eBPF
- Userspace: C++17, libbpf
- Compiler: Clang 18 (BPF), GCC 13 (userspace)
- Hardware: AMD Ryzen 7 7730U, commodity WiFi NIC

## Build

```bash
# XDP program (kernel space)
clang -O2 -g -target bpf \
    -D__TARGET_ARCH_x86 \
    -I/usr/include/bpf \
    -I/usr/include/x86_64-linux-gnu \
    -c xdp/xdp_feed_handler.c -o xdp/xdp_feed_handler.o

# Load onto interface
sudo ip link set dev <iface> xdp obj xdp/xdp_feed_handler.o sec xdp

# Userspace loader (C++)
g++ -O2 -std=c++17 -I/usr/include/bpf \
    xdp/feed_loader.cpp -o xdp/feed_loader -lbpf

sudo ./xdp/feed_loader
```

## Status
- [x] XDP feed handler — live packet interception
- [x] Ring buffer — zero-copy kernel→userspace
- [x] Feed loader — message decoding + latency measurement
- [ ] Lock-free order book
- [ ] Exchange simulator (ITCH 5.0 format)
- [ ] rdtsc latency benchmarking
- [ ] DPDK software mode layer

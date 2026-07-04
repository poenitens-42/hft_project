# HFT_Experimental
XDP/eBPF feed handler in SKB mode

A low-latency market data feed handler, with a planned lock-free
order book, built to explore kernel-bypass networking techniques
used in high-frequency trading infrastructure.

## Architecture

[Exchange Simulator] → UDP (port 9000)
↓
[XDP Feed Handler]     # kernel-space, bypasses network stack
↓ ring buffer (zero-copy)
[C++ Feed Loader]      # userspace, nanosecond timestamps, latency measurement
↓
[Order Book]           # not yet started
↓
[Strategy Layer]       # planned 


## Components

### XDP Feed Handler (C)
- Attaches to NIC via XDP hook in SKB (generic) mode
- Parses Ethernet → IP → UDP → market message
- Filters by exchange feed port (9000)
- Timestamps packets using kernel nanosecond clock
- Pushes parsed messages to userspace via lock-free ring buffer
- Zero-copy: kernel stack never touches feed packets

### Userspace Feed Loader (C++)
- Consumes messages from BPF ring buffer
- Measures kernel→userspace latency per message
- Currently prints each parsed message; order book integration not yet implemented

### Order Book (C++) — not yet started
Planned:
- L2/L3 limit order book, cache-aligned price level arrays
- No dynamic allocation in hot path
- Single-writer/single-reader design with a seqlock for lock-free snapshot reads
- Benchmarked with rdtsc once implemented

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

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
- Currently returns XDP_PASS in generic mode, so packets still traverse the kernel stack and each message is copied into the ring buffer; this is NOT zero-copy bypass yet (that needs AF_XDP + native driver support)

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

## Build and run

```bash
make                      # builds xdp/xdp_feed_handler.o, xdp/feed_loader, tools/feed_sim
                          # needs clang, g++, libbpf-dev

# terminal 1 (root): attach to an interface, e.g. loopback
sudo ./xdp/feed_loader lo
# terminal 2: send 100k messages at 10k msg/s (pps=0 for max rate)
./tools/feed_sim 127.0.0.1 100000 10000
# Ctrl-C terminal 1 to print latency percentiles and XDP counters
```

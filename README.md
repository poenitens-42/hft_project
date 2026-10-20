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
- Loads and attaches the XDP object itself (no hardcoded map ids); busy-polls the ring buffer
- Reports p50/p90/p99/p99.9/max of XDP-stamp→userspace latency (both sides use CLOCK_MONOTONIC) plus XDP counters on exit; `-v` prints each message
- Order book integration is a separate project and not part of this repo yet

### Order Book (C++) — separate project, not in this repo
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

Wire format (`xdp/feed_proto.h`): 14-byte big-endian message per UDP datagram, one message per packet.
Latency here is measured from an XDP-time stamp, not NIC arrival, and in generic mode that is already after the kernel allocated the packet.

## Veth test bed and AF_XDP receiver

Loopback makes the sender run the whole receive path on its own core, so it is a poor test bed. `tools/veth_setup.sh` builds a virtual cable between the root namespace (`vtx`, 10.99.0.1) and a namespace `xdprx` (`vrx`, 10.99.0.2):

```bash
sudo tools/veth_setup.sh up
make xsk                                   # needs libxdp-dev; builds xdp/xsk_redirect.o and xdp/feed_xsk

# receiver, AF_XDP (parses packets straight out of user-space memory):
sudo ip netns exec xdprx ./xdp/feed_xsk vrx
# or the ring-buffer receiver on the same cable, for comparison:
sudo ip netns exec xdprx ./xdp/feed_loader vrx

# sender (root namespace). Args: dest count pps(0=max) batch ts(0|1)
./tools/feed_sim 10.99.0.2 50000 10000 1 1   # paced, 1 per call, with sender timestamp (latency test)
./tools/feed_sim 10.99.0.2 1000000 0 32 0    # max rate

sudo tools/veth_setup.sh down
```

`ts=1` appends an 8-byte sender timestamp (CLOCK_MONOTONIC) after the 14-byte message. Both receivers use it to report sender-to-userspace latency, the only metric that is comparable between the two paths. Use batch=1 for latency runs, because the stamp is taken when a batch is built.

`feed_xsk` runs in copy mode by default (`-z` asks for zero-copy, which needs driver support) and generic XDP (`-n` for native). Only UDP port 9000 is redirected; ARP and other traffic still reach the kernel.

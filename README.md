# HFT_Experimental

A learning project for kernel-bypass market data ingest on Linux: an XDP/eBPF feed handler,
a ring-buffer receiver and an AF_XDP receiver, with a UDP exchange simulator, a virtual-cable
test bed and latency measurement. The limit order book is a separate project; this repo
covers the path from the wire to normalized messages.

Everything here runs on a laptop without a bypass-capable NIC, so it demonstrates the
mechanisms and measures them honestly. It does **not** demonstrate production kernel-bypass
latency (see [Limitations](#limitations)).

## Architecture

```
[feed_sim]  UDP :9000, 14-byte message (+ optional 8-byte sender timestamp)
     |
     v   (loopback, or a veth pair between two network namespaces)
     |
     +--> Path 1: XDP program ---- ring buffer ----> feed_loader (C++)
     |            parses + validates in the kernel, copies each message into a BPF ring buffer,
     |            returns XDP_PASS (the packet also continues up the normal kernel stack)
     |
     +--> Path 2: XDP redirect --- AF_XDP socket --> feed_xsk (C++)
                  xsk_redirect.c sends port-9000 UDP into user-space memory (UMEM);
                  feed_xsk parses the packet in place. Other traffic goes to the kernel stack.

[Order book]  separate project, not in this repo
```

## Components

| File | What it does |
|---|---|
| `xdp/feed_proto.h` | Shared wire format, ring-buffer event and counters (used by C and C++) |
| `xdp/xdp_feed_handler.c` | Path 1 kernel program: Ethernet, IPv4 (real header length), UDP, port 9000, rejects fragments and short datagrams, counts malformed packets and ring-buffer overflow, stamps `bpf_ktime_get_ns()` |
| `xdp/feed_loader.cpp` | Path 1 receiver: loads and attaches the program itself, busy-polls the ring buffer, prints latency percentiles and XDP counters on exit (`-v` prints every message, `-n` native mode, `-e` epoll) |
| `xdp/xsk_redirect.c` | Path 2 kernel program: redirects UDP port 9000 to the AF_XDP socket, passes everything else |
| `xdp/feed_xsk.cpp` | Path 2 receiver: UMEM + fill/rx rings, parses Ethernet/IPv4/UDP by hand with bounds checks, busy-polls, reports rate, latency percentiles and kernel socket drop counters (`-z` zero-copy, `-n` native) |
| `tools/feed_sim.cpp` | Exchange simulator: batched `sendmmsg`, paced or max rate, reports achieved rate, optional sender timestamp |
| `tools/veth_setup.sh` | Creates/removes a veth cable: `vtx` 10.99.0.1 (root namespace) <-> `vrx` 10.99.0.2 (namespace `xdprx`) |
| `xdp/xdp_counter.c` | Early packet/byte counter experiment, not part of the pipeline |

Wire format: one message per UDP datagram, big-endian: type (1), order id (4), side (1),
price x 10000 (4), quantity (4) = 14 bytes. With `ts=1` the simulator appends the sender's
`CLOCK_MONOTONIC` time (8 bytes, host order), which both receivers use to report
sender-to-userspace latency. That clock is shared by processes and namespaces on one machine,
so this only works with sender and receiver on the same host.

## Build

```bash
sudo apt install clang g++ libbpf-dev libxdp-dev iproute2
make          # xdp_feed_handler.o, feed_loader, feed_sim
make xsk      # xsk_redirect.o, feed_xsk (needs libxdp-dev)
```

## Run

Simple (loopback, ring-buffer path):
```bash
sudo ./xdp/feed_loader lo                    # terminal 1
./tools/feed_sim 127.0.0.1 100000 10000      # terminal 2: dest count pps(0=max) [batch] [ts]
# Ctrl-C terminal 1 for percentiles and counters
```

Veth test bed (separates sender and receiver; use one receiver at a time):
```bash
sudo tools/veth_setup.sh up
sudo ip netns exec xdprx ./xdp/feed_xsk vrx       # or: ./xdp/feed_loader vrx
./tools/feed_sim 10.99.0.2 50000 10000 1 1        # paced, batch 1, with sender timestamp
./tools/feed_sim 10.99.0.2 1000000 0 32 0         # max rate
sudo tools/veth_setup.sh down
```
Stop a receiver with Ctrl-C and let it exit before starting the other; it detaches its XDP
program on exit. Use batch 1 for latency runs (the sender stamp is taken when a batch is built).

## Results so far

Measured on the development laptop (below), generic XDP mode, copy mode for AF_XDP.
These are single runs; treat differences under about 20% as noise.

| Test | Result |
|---|---|
| Loopback, ring-buffer path, 1M msgs, loader pinned to its own core | 1,000,000 / 1,000,000 received, no overflow; XDP stamp -> userspace p50 80 ns, p99 130 ns, p99.9 651 ns |
| Veth, paced 10k msg/s, 50k msgs, sender stamp -> userspace | AF_XDP p50 2.3 and 2.7 us (two runs), p99 3.5 to 4.6 us; ring buffer p50 2.6 us, p99 4.5 us. No drops on either |
| Veth, ring-buffer path, 1M msgs max rate | 1,000,000 / 1,000,000 received; sender reached about 174k msg/s |
| Veth, AF_XDP max rate | not yet measured on this laptop |

Interpretation: the ring-buffer receiver's own stamp shows only about 80 ns between the XDP
program and userspace, while sender-to-userspace is about 2.6 us, so almost all of the latency
happens before XDP runs (sender system call, veth, kernel receive path). In generic mode no
receive method can remove that part, which is why the two paths look the same here.

## Limitations

- **Not real kernel bypass yet.** Generic (SKB) mode runs XDP after the kernel has allocated the packet. Path 1 also returns `XDP_PASS`, so the full stack still processes each packet, and each message is copied into the ring buffer.
- **No zero-copy.** AF_XDP zero-copy needs native driver support. As far as I checked in the kernel source (master, not this exact kernel), neither the laptop's wired NIC (Realtek RTL8111, `r8169`) nor its WiFi (MediaTek MT7921) has native XDP, so real bypass latency needs another NIC or a cloud machine.
- Path 1 and path 2 are not yet compared at equal load: path 1 sends every packet through the kernel stack as well, which slows the sender. An `XDP_DROP` option is planned for a fair comparison.
- One message per UDP datagram; no MoldUDP64/ITCH framing, sequence numbers or gap detection.
- IP options and fragment handling are implemented but not exercised by tests. There is no automated test suite yet.
- Single queue, single thread.

## Stack and hardware

- Development machine: Lenovo ThinkBook 15 G5 ABP, AMD Ryzen 7 7730U, 16 GiB, Ubuntu 24.04, Linux 7.0.0-31
- Wired NIC: Realtek RTL8111 (`r8169`); WiFi: MediaTek MT7921 (`mt7921e`)
- Userspace: C++17, libbpf, libxdp. Compilers: Clang 18 (BPF target), GCC 13

## Roadmap

1. Fair comparison: `XDP_DROP` option for path 1, AF_XDP max-rate run
2. MoldUDP64/ITCH 5.0 framing, several messages per packet, sequence-gap detection
3. Hand-off to the order book project: fixed message struct and a single-producer single-consumer ring
4. Multi-queue AF_XDP and zero-copy testing on a supported NIC
5. Automated tests (malformed, fragmented and IP-options packets)

/* Shared by the XDP program (C, BPF target), the loader and the simulator (C++). */
#ifndef FEED_PROTO_H
#define FEED_PROTO_H

#include <linux/types.h>

#define FEED_PORT 9000 /* simulated exchange UDP port */

/* What the exchange (or feed_sim) puts on the wire after the UDP header.
 * All multi-byte fields are big-endian (network order). No timestamp here:
 * the receiving side stamps arrival time itself. */
struct wire_msg {
    __u8  msg_type; /* 'A'=add 'C'=cancel 'T'=trade */
    __u32 order_id;
    __u8  side;     /* 'B'=bid 'S'=ask */
    __u32 price;    /* price * 10000 (fixed point) */
    __u32 quantity;
} __attribute__((packed));

/* Optional trailer right after wire_msg: the sender's CLOCK_MONOTONIC time in
 * ns, host byte order. Only meaningful when sender and receiver are on the
 * same machine (the simulator). A datagram without it is still valid. */
struct wire_trailer {
    __u64 send_ns;
} __attribute__((packed));

/* What the XDP program pushes to userspace via the ring buffer.
 * Host byte order; timestamp is bpf_ktime_get_ns() (CLOCK_MONOTONIC). */
struct feed_event {
    __u8  msg_type;
    __u32 order_id;
    __u8  side;
    __u32 price;
    __u32 quantity;
    __u64 timestamp;
    __u64 send_ns;  /* from wire_trailer, 0 if the packet had none */
} __attribute__((packed));

/* Per-CPU counters kept by the XDP program. */
struct feed_stats {
    __u64 udp_packets;     /* IPv4 UDP packets seen (any port)           */
    __u64 feed_packets;    /* UDP packets on FEED_PORT                   */
    __u64 bytes_processed; /* frame bytes of feed packets                */
    __u64 dropped;         /* malformed feed packets (counted, not eaten) */
    __u64 ringbuf_full;    /* ringbuf_reserve failed: event lost         */
};

#endif


#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <bpf/bpf_endian.h>
#include <linux/in.h>
#include "feed_proto.h"

#define IP_MF_OR_OFFSET 0x3fff /* more-fragments flag | fragment offset */

/* Default flags=0 is the kernel's adaptive wakeup. Build with -DRB_NO_WAKEUP
 * only if the consumer busy-polls (ring_buffer__consume) instead of epolling. */
#ifdef RB_NO_WAKEUP
#define RB_FLAGS BPF_RB_NO_WAKEUP
#else
#define RB_FLAGS 0
#endif

/* ── Stats map (per CPU, no contention) ──────────────*/
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct feed_stats);
} feed_stats_map SEC(".maps");

/* ── Ring buffer for userspace ───────────────────────*/
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20); /* 1MB ring buffer */
} feed_ringbuf SEC(".maps");

SEC("xdp")
int xdp_feed_handler(struct xdp_md *ctx)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    __u32 key = 0;
    struct feed_stats *stats = bpf_map_lookup_elem(&feed_stats_map, &key);
    if (!stats)
        return XDP_PASS;

    /* ── Layer 2: Ethernet (IPv4 only) ─────────────── */
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    /* ── Layer 3: IPv4 (header length is variable) ─── */
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;
    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    __u32 ihl = ip->ihl * 4;
    if (ihl < sizeof(*ip))
        return XDP_PASS;

    stats->udp_packets++;

    /* ── Layer 4: UDP ──────────────────────────────── */
    struct udphdr *udp = (void *)ip + ihl;
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;
    if (udp->dest != bpf_htons(FEED_PORT))
        return XDP_PASS;

    stats->feed_packets++;

    /* A fragment's payload isn't a whole message: don't parse it. */
    if (ip->frag_off & bpf_htons(IP_MF_OR_OFFSET)) {
        stats->dropped++;
        return XDP_PASS;
    }

    /* Use the UDP length, not just the frame size: the frame can carry
     * Ethernet padding past the datagram. */
    __u16 udp_len = bpf_ntohs(udp->len);
    struct wire_msg *msg = (void *)(udp + 1);
    if (udp_len < sizeof(*udp) + sizeof(*msg) ||
        (void *)(msg + 1) > data_end) {
        stats->dropped++;
        return XDP_PASS;
    }

    /* Optional sender timestamp trailer (see wire_trailer). */
    __u64 send_ns = 0;
    if (udp_len >= sizeof(*udp) + sizeof(*msg) + sizeof(struct wire_trailer)) {
        struct wire_trailer *tr = (void *)(msg + 1);
        if ((void *)(tr + 1) <= data_end)
            send_ns = tr->send_ns;
    }

    stats->bytes_processed += (data_end - data);

    /* ── Send to userspace via ring buffer ─────────── */
    struct feed_event *ev = bpf_ringbuf_reserve(&feed_ringbuf, sizeof(*ev), 0);
    if (!ev) {
        stats->ringbuf_full++;
        return XDP_PASS;
    }
    ev->msg_type  = msg->msg_type;
    ev->order_id  = bpf_ntohl(msg->order_id);
    ev->side      = msg->side;
    ev->price     = bpf_ntohl(msg->price);
    ev->quantity  = bpf_ntohl(msg->quantity);
    ev->timestamp = bpf_ktime_get_ns(); /* CLOCK_MONOTONIC */
    ev->send_ns   = send_ns;
    bpf_ringbuf_submit(ev, RB_FLAGS);

    /*
     * XDP_PASS: the packet also continues up the kernel stack (dev mode).
     * XDP_DROP would stop it here, but then userspace only has the copy in
     * the ring buffer. True zero-copy needs AF_XDP + native driver support.
     */
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";

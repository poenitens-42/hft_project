#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <bpf/bpf_endian.h>
#include <linux/in.h>
/* ── Exchange feed config ─────────────────────────── */
#define FEED_PORT     9000   /* simulated exchange UDP port */
#define MAX_MSG_SIZE  64     /* ITCH message max size       */

/* ── Stats map (per CPU, no contention) ──────────────*/
struct feed_stats {
    __u64 udp_packets;      /* total UDP packets seen      */
    __u64 feed_packets;     /* packets on our feed port    */
    __u64 bytes_processed;  /* total bytes on feed port    */
    __u64 dropped;          /* malformed packets dropped   */
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct feed_stats);
} feed_stats_map SEC(".maps");

/* ── Ring buffer for userspace (order book layer) ────*/
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20); /* 1MB ring buffer        */
} feed_ringbuf SEC(".maps");

/* ── Market data message (simplified ITCH-style) ─────*/
struct market_msg {
    __u8  msg_type;     /* 'A'=add 'C'=cancel 'T'=trade  */
    __u32 order_id;
    __u8  side;         /* 'B'=bid 'S'=ask               */
    __u32 price;        /* price * 10000 (fixed point)   */
    __u32 quantity;
    __u64 timestamp;    /* kernel timestamp (ns)         */
} __attribute__((packed));

SEC("xdp")
int xdp_feed_handler(struct xdp_md *ctx)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    /* ── Stats lookup ──────────────────────────────── */
    __u32 key = 0;
    struct feed_stats *stats = bpf_map_lookup_elem(&feed_stats_map, &key);
    if (!stats)
        return XDP_PASS;

    /* ── Layer 2: Ethernet ─────────────────────────── */
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    /* Only process IPv4 */
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    /* ── Layer 3: IP ───────────────────────────────── */
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    /* Only process UDP */
    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    stats->udp_packets++;

    /* ── Layer 4: UDP ──────────────────────────────── */
    struct udphdr *udp = (void *)(ip + 1);
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;

    /* Filter: only our exchange feed port */
    if (udp->dest != bpf_htons(FEED_PORT))
        return XDP_PASS;

    stats->feed_packets++;

    /* ── Payload: market data message ─────────────── */
    struct market_msg *msg = (void *)(udp + 1);
    if ((void *)(msg + 1) > data_end) {
        stats->dropped++;
        return XDP_PASS;
    }

    stats->bytes_processed += (data_end - data);

    /* ── Send to userspace via ring buffer ─────────── */
    struct market_msg *ringbuf_msg = bpf_ringbuf_reserve(
        &feed_ringbuf, sizeof(struct market_msg), 0);

    if (ringbuf_msg) {
        ringbuf_msg->msg_type  = msg->msg_type;
        ringbuf_msg->order_id  = bpf_ntohl(msg->order_id);
        ringbuf_msg->side      = msg->side;
        ringbuf_msg->price     = bpf_ntohl(msg->price);
        ringbuf_msg->quantity  = bpf_ntohl(msg->quantity);
        ringbuf_msg->timestamp = bpf_ktime_get_ns(); /* kernel ns clock */
        bpf_ringbuf_submit(ringbuf_msg, 0);
    }

    /* 
     * XDP_PASS  = forward to kernel (use during dev)
     * XDP_DROP  = drop after parsing (use in production)
     *             production feed handler owns the packet,
     *             kernel stack never sees it = zero copy
     */
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";

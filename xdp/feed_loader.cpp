#include <algorithm>
#include <cerrno>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <time.h>
#include <net/if.h>
#include <vector>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/if_link.h>

#include "feed_proto.h"

static volatile sig_atomic_t running = 1;
static void sig_handler(int) { running = 0; }

static inline uint64_t now_ns()
{
    /* Same clock as bpf_ktime_get_ns() in the XDP program. */
    timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

struct Ctx {
    std::vector<uint64_t> lat;
    size_t cap = 0;
    uint64_t count = 0;
    bool verbose = false;
};

static int handle_event(void *vctx, void *data, size_t size)
{
    auto *c = static_cast<Ctx *>(vctx);
    if (size < sizeof(feed_event)) return 0;
    auto *ev = static_cast<const feed_event *>(data);

    uint64_t t = now_ns();
    uint64_t lat = t >= ev->timestamp ? t - ev->timestamp : 0;
    c->count++;
    if (c->lat.size() < c->cap) c->lat.push_back(lat);

    if (c->verbose)
        printf("MSG type=%c order=%u side=%c price=%.4f qty=%u latency=%luns\n",
               ev->msg_type, ev->order_id, ev->side, ev->price / 10000.0,
               ev->quantity, (unsigned long)lat);
    return 0;
}

static void print_percentiles(std::vector<uint64_t> &v)
{
    if (v.empty()) { puts("no samples"); return; }
    std::sort(v.begin(), v.end());
    auto pct = [&](double p) { return v[std::min(v.size() - 1, (size_t)(p * v.size()))]; };
    printf("latency XDP stamp -> userspace (ns), n=%zu\n", v.size());
    printf("  p50=%lu p90=%lu p99=%lu p99.9=%lu max=%lu\n",
           (unsigned long)pct(0.50), (unsigned long)pct(0.90),
           (unsigned long)pct(0.99), (unsigned long)pct(0.999),
           (unsigned long)v.back());
}

static void print_stats(int stats_fd)
{
    int ncpu = libbpf_num_possible_cpus();
    if (ncpu <= 0) return;
    std::vector<feed_stats> per(ncpu);
    __u32 key = 0;
    if (bpf_map_lookup_elem(stats_fd, &key, per.data()) != 0) return;
    feed_stats s{};
    for (auto &p : per) {
        s.udp_packets += p.udp_packets;
        s.feed_packets += p.feed_packets;
        s.bytes_processed += p.bytes_processed;
        s.dropped += p.dropped;
        s.ringbuf_full += p.ringbuf_full;
    }
    printf("xdp stats: udp=%lu feed=%lu bytes=%lu malformed=%lu ringbuf_full=%lu\n",
           (unsigned long)s.udp_packets, (unsigned long)s.feed_packets,
           (unsigned long)s.bytes_processed, (unsigned long)s.dropped,
           (unsigned long)s.ringbuf_full);
}

static void usage(const char *a0)
{
    fprintf(stderr,
            "usage: %s <iface> [-o xdp_feed_handler.o] [-n] [-v] [-e]\n"
            "  -o  BPF object file (default: xdp/xdp_feed_handler.o)\n"
            "  -n  native (driver) XDP instead of generic/SKB mode\n"
            "  -v  print every message (slow; skews latency)\n"
            "  -e  epoll-wait for events instead of busy-polling\n",
            a0);
}

int main(int argc, char **argv)
{
    const char *iface = nullptr, *obj_path = "xdp/xdp_feed_handler.o";
    bool native = false, epoll_mode = false;
    Ctx ctx;
    ctx.cap = 4u << 20; /* latency samples kept */

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-o") && i + 1 < argc) obj_path = argv[++i];
        else if (!strcmp(argv[i], "-n")) native = true;
        else if (!strcmp(argv[i], "-v")) ctx.verbose = true;
        else if (!strcmp(argv[i], "-e")) epoll_mode = true;
        else if (argv[i][0] != '-' && !iface) iface = argv[i];
        else { usage(argv[0]); return 2; }
    }
    if (!iface) { usage(argv[0]); return 2; }
    ctx.lat.reserve(ctx.cap);

    int ifindex = if_nametoindex(iface);
    if (!ifindex) { perror("if_nametoindex"); return 1; }

    bpf_object *obj = bpf_object__open_file(obj_path, nullptr);
    if (!obj) { fprintf(stderr, "open %s failed: %s\n", obj_path, strerror(errno)); return 1; }
    if (bpf_object__load(obj)) { fprintf(stderr, "bpf load failed (root? verifier?)\n"); return 1; }

    bpf_program *prog = bpf_object__find_program_by_name(obj, "xdp_feed_handler");
    int rb_fd = bpf_object__find_map_fd_by_name(obj, "feed_ringbuf");
    int stats_fd = bpf_object__find_map_fd_by_name(obj, "feed_stats_map");
    if (!prog || rb_fd < 0 || stats_fd < 0) { fprintf(stderr, "program/maps not found in object\n"); return 1; }

    __u32 flags = XDP_FLAGS_UPDATE_IF_NOEXIST | (native ? XDP_FLAGS_DRV_MODE : XDP_FLAGS_SKB_MODE);
    if (bpf_xdp_attach(ifindex, bpf_program__fd(prog), flags, nullptr)) {
        fprintf(stderr, "xdp attach to %s (%s mode) failed: %s\n", iface,
                native ? "native" : "generic", strerror(errno));
        return 1;
    }

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    ring_buffer *rb = ring_buffer__new(rb_fd, handle_event, &ctx, nullptr);
    if (!rb) { fprintf(stderr, "ring_buffer__new failed\n"); bpf_xdp_detach(ifindex, flags, nullptr); return 1; }

    printf("attached to %s (%s), listening for UDP port %d, Ctrl-C to stop\n",
           iface, native ? "native" : "generic", FEED_PORT);

    while (running) {
        if (epoll_mode) ring_buffer__poll(rb, 100);
        else            ring_buffer__consume(rb);
    }

    ring_buffer__consume(rb);
    printf("\nmessages received: %lu\n", (unsigned long)ctx.count);
    print_percentiles(ctx.lat);
    print_stats(stats_fd);

    ring_buffer__free(rb);
    bpf_xdp_detach(ifindex, flags, nullptr);
    bpf_object__close(obj);
    return 0;
}


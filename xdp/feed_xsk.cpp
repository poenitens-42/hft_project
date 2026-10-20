/* AF_XDP receiver: the kernel redirects feed packets into a user-space memory
 * area (UMEM) and this program parses them straight out of it, no per-packet
 * system calls and no ring-buffer copy of the payload. Compare with feed_loader.
 *
 * Needs libxdp-dev (the AF_XDP helpers moved out of libbpf). Run as root. */
#include <algorithm>
#include <cerrno>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <time.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/if_link.h>
#include <linux/if_xdp.h>
#include <xdp/xsk.h>

#include "feed_proto.h"

#ifndef SOL_XDP
#define SOL_XDP 283
#endif

static const uint32_t NUM_FRAMES = 4096;
static const uint32_t FRAME_SIZE = XSK_UMEM__DEFAULT_FRAME_SIZE; /* 4096 */
static const uint32_t FILL_PREFILL = XSK_RING_PROD__DEFAULT_NUM_DESCS; /* 2048 */
static const uint32_t BATCH = 64;

static volatile sig_atomic_t running = 1;
static void sig_handler(int) { running = 0; }

static inline uint64_t now_ns()
{
    timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

enum ParseResult { P_OK, P_MALFORMED, P_IGNORE };

/* Parse Ethernet/IPv4/UDP by hand. Every read is bounds-checked against len. */
static inline ParseResult parse_pkt(const uint8_t *p, uint32_t len, wire_msg *msg, uint64_t *send_ns)
{
    if (len < 14 + 20) return P_IGNORE;
    if (p[12] != 0x08 || p[13] != 0x00) return P_IGNORE; /* not IPv4 */
    const uint8_t *ip = p + 14;
    if ((ip[0] >> 4) != 4) return P_IGNORE;
    uint32_t ihl = (ip[0] & 0x0f) * 4u;
    if (ihl < 20) return P_IGNORE;
    if (ip[9] != 17) return P_IGNORE; /* not UDP */
    if (len < 14 + ihl + 8) return P_IGNORE;
    const uint8_t *udp = ip + ihl;
    if (((udp[2] << 8) | udp[3]) != FEED_PORT) return P_IGNORE;

    if ((((ip[6] << 8) | ip[7]) & 0x3fff) != 0) return P_MALFORMED; /* fragment */
    uint32_t udp_len = (udp[4] << 8) | udp[5];
    if (udp_len < 8 + sizeof(wire_msg)) return P_MALFORMED;
    if (14 + ihl + 8 + sizeof(wire_msg) > len) return P_MALFORMED;

    memcpy(msg, udp + 8, sizeof(wire_msg));
    *send_ns = 0;
    if (udp_len >= 8 + sizeof(wire_msg) + sizeof(wire_trailer) &&
        14 + ihl + udp_len <= len)
        memcpy(send_ns, udp + 8 + sizeof(wire_msg), sizeof(uint64_t));
    return P_OK;
}

static void print_percentiles(const char *what, std::vector<uint64_t> &v)
{
    if (v.empty()) { printf("%s: no samples\n", what); return; }
    std::sort(v.begin(), v.end());
    auto pct = [&](double p) { return v[std::min(v.size() - 1, (size_t)(p * v.size()))]; };
    printf("%s (ns), n=%zu\n", what, v.size());
    printf("  p50=%lu p90=%lu p99=%lu p99.9=%lu max=%lu\n",
           (unsigned long)pct(0.50), (unsigned long)pct(0.90),
           (unsigned long)pct(0.99), (unsigned long)pct(0.999),
           (unsigned long)v.back());
}

static void usage(const char *a0)
{
    fprintf(stderr,
            "usage: %s <iface> [-o xsk_redirect.o] [-q queue] [-n] [-z] [-v]\n"
            "  -o  BPF object (default: xdp/xsk_redirect.o)\n"
            "  -q  RX queue id (default 0)\n"
            "  -n  native (driver) XDP instead of generic/SKB\n"
            "  -z  request zero-copy (needs driver support; default is copy mode)\n"
            "  -v  print every message (slow)\n",
            a0);
}

int main(int argc, char **argv)
{
    const char *iface = nullptr, *obj_path = "xdp/xsk_redirect.o";
    uint32_t queue = 0;
    bool native = false, zerocopy = false, verbose = false;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-o") && i + 1 < argc) obj_path = argv[++i];
        else if (!strcmp(argv[i], "-q") && i + 1 < argc) queue = (uint32_t)atoi(argv[++i]);
        else if (!strcmp(argv[i], "-n")) native = true;
        else if (!strcmp(argv[i], "-z")) zerocopy = true;
        else if (!strcmp(argv[i], "-v")) verbose = true;
        else if (argv[i][0] != '-' && !iface) iface = argv[i];
        else { usage(argv[0]); return 2; }
    }
    if (!iface) { usage(argv[0]); return 2; }

    int ifindex = if_nametoindex(iface);
    if (!ifindex) { perror("if_nametoindex"); return 1; }

    /* 1. Load the redirect program and attach it. */
    bpf_object *obj = bpf_object__open_file(obj_path, nullptr);
    if (!obj) { fprintf(stderr, "open %s failed: %s\n", obj_path, strerror(errno)); return 1; }
    if (bpf_object__load(obj)) { fprintf(stderr, "bpf load failed (root? verifier?)\n"); return 1; }
    bpf_program *prog = bpf_object__find_program_by_name(obj, "xsk_redirect");
    int xsks_map_fd = bpf_object__find_map_fd_by_name(obj, "xsks_map");
    if (!prog || xsks_map_fd < 0) { fprintf(stderr, "program/map not found in object\n"); return 1; }
    __u32 xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST | (native ? XDP_FLAGS_DRV_MODE : XDP_FLAGS_SKB_MODE);
    if (bpf_xdp_attach(ifindex, bpf_program__fd(prog), xdp_flags, nullptr)) {
        fprintf(stderr, "xdp attach to %s failed: %s\n", iface, strerror(errno));
        return 1;
    }

    /* 2. UMEM: one big page-aligned block cut into fixed-size frames. */
    size_t umem_size = (size_t)NUM_FRAMES * FRAME_SIZE;
    void *umem_area = mmap(nullptr, umem_size, PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (umem_area == MAP_FAILED) { perror("mmap umem"); bpf_xdp_detach(ifindex, xdp_flags, nullptr); return 1; }

    xsk_umem *umem = nullptr;
    xsk_ring_prod fq;
    xsk_ring_cons cq;
    int r = xsk_umem__create(&umem, umem_area, umem_size, &fq, &cq, nullptr);
    if (r) { fprintf(stderr, "xsk_umem__create: %s\n", strerror(-r)); bpf_xdp_detach(ifindex, xdp_flags, nullptr); return 1; }

    /* 3. AF_XDP socket on one RX queue. We never transmit, but the API wants a tx ring. */
    xsk_socket_config cfg{};
    cfg.rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS;
    cfg.tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS;
    cfg.libxdp_flags = XSK_LIBXDP_FLAGS__INHIBIT_PROG_LOAD; /* we attached our own program */
    cfg.xdp_flags = xdp_flags;
    cfg.bind_flags = XDP_USE_NEED_WAKEUP | (zerocopy ? XDP_ZEROCOPY : XDP_COPY);

    xsk_socket *xsk = nullptr;
    xsk_ring_cons rx;
    xsk_ring_prod tx;
    r = xsk_socket__create(&xsk, iface, queue, umem, &rx, &tx, &cfg);
    if (r) {
        fprintf(stderr, "xsk_socket__create on %s queue %u (%s): %s\n", iface, queue,
                zerocopy ? "zero-copy" : "copy", strerror(-r));
        xsk_umem__delete(umem);
        bpf_xdp_detach(ifindex, xdp_flags, nullptr);
        return 1;
    }
    if (xsk_socket__update_xskmap(xsk, xsks_map_fd)) {
        fprintf(stderr, "update xskmap failed\n");
        xsk_socket__delete(xsk); xsk_umem__delete(umem);
        bpf_xdp_detach(ifindex, xdp_flags, nullptr);
        return 1;
    }
    int xsk_fd = xsk_socket__fd(xsk);

    /* 4. Give the kernel empty frames to receive into via the fill ring. */
    uint32_t idx;
    if (xsk_ring_prod__reserve(&fq, FILL_PREFILL, &idx) != FILL_PREFILL) {
        fprintf(stderr, "fill ring reserve failed\n");
        return 1;
    }
    for (uint32_t i = 0; i < FILL_PREFILL; i++)
        *xsk_ring_prod__fill_addr(&fq, idx + i) = (uint64_t)i * FRAME_SIZE;
    xsk_ring_prod__submit(&fq, FILL_PREFILL);

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    printf("AF_XDP on %s queue %u (%s, %s), listening for UDP port %d, Ctrl-C to stop\n",
           iface, queue, native ? "native" : "generic", zerocopy ? "zero-copy" : "copy", FEED_PORT);

    const size_t cap = 4u << 20;
    std::vector<uint64_t> e2e;
    e2e.reserve(cap);
    uint64_t pkts = 0, msgs = 0, malformed = 0, ignored = 0, first_ns = 0, last_ns = 0;
    volatile uint64_t sink = 0; /* consume fields so the parse can't be optimized away */

    /* 5. Busy-poll loop: peek rx ring, parse in place, hand frames back via fill ring. */
    uint64_t addrs[BATCH];
    while (running) {
        uint32_t rx_idx = 0;
        uint32_t n = xsk_ring_cons__peek(&rx, BATCH, &rx_idx);
        if (!n) {
            if (xsk_ring_prod__needs_wakeup(&fq))
                recvfrom(xsk_fd, nullptr, 0, MSG_DONTWAIT, nullptr, nullptr);
            continue;
        }
        for (uint32_t i = 0; i < n; i++) {
            const xdp_desc *d = xsk_ring_cons__rx_desc(&rx, rx_idx + i);
            addrs[i] = d->addr & ~(uint64_t)(FRAME_SIZE - 1); /* frame base for refill */
            const uint8_t *pkt = (const uint8_t *)xsk_umem__get_data(umem_area, d->addr);
            uint64_t t = now_ns();
            pkts++;
            wire_msg m;
            uint64_t send_ns;
            switch (parse_pkt(pkt, d->len, &m, &send_ns)) {
            case P_OK:
                msgs++;
                if (!first_ns) first_ns = t;
                last_ns = t;
                sink += ntohl(m.order_id) ^ ntohl(m.price) ^ ntohl(m.quantity) ^ m.msg_type ^ m.side;
                if (send_ns && t >= send_ns && e2e.size() < cap) e2e.push_back(t - send_ns);
                if (verbose)
                    printf("MSG type=%c order=%u side=%c price=%.4f qty=%u\n", m.msg_type,
                           ntohl(m.order_id), m.side, ntohl(m.price) / 10000.0, ntohl(m.quantity));
                break;
            case P_MALFORMED: malformed++; break;
            case P_IGNORE: ignored++; break;
            }
        }
        xsk_ring_cons__release(&rx, n);

        /* Return the frames to the fill ring (same frames, reused). */
        uint32_t fidx = 0;
        while (xsk_ring_prod__reserve(&fq, n, &fidx) != n) {
            if (xsk_ring_prod__needs_wakeup(&fq))
                recvfrom(xsk_fd, nullptr, 0, MSG_DONTWAIT, nullptr, nullptr);
            if (!running) break;
        }
        if (!running) break;
        for (uint32_t i = 0; i < n; i++)
            *xsk_ring_prod__fill_addr(&fq, fidx + i) = addrs[i];
        xsk_ring_prod__submit(&fq, n);
    }

    printf("\npackets seen: %lu, feed messages: %lu, malformed: %lu, ignored: %lu\n",
           (unsigned long)pkts, (unsigned long)msgs, (unsigned long)malformed, (unsigned long)ignored);
    if (msgs > 1 && last_ns > first_ns)
        printf("receive rate over the run: %.0f msg/s\n", (double)msgs / ((last_ns - first_ns) / 1e9));
    if (!e2e.empty()) print_percentiles("latency sender stamp -> userspace", e2e);
    else puts("no sender timestamps (run feed_sim with ts=1 for latency)");

    xdp_statistics st{};
    socklen_t sl = sizeof(st);
    if (getsockopt(xsk_fd, SOL_XDP, XDP_STATISTICS, &st, &sl) == 0)
        printf("kernel socket stats: rx_dropped=%llu rx_invalid_descs=%llu rx_ring_full=%llu fill_ring_empty=%llu\n",
               (unsigned long long)st.rx_dropped, (unsigned long long)st.rx_invalid_descs,
               (unsigned long long)st.rx_ring_full, (unsigned long long)st.rx_fill_ring_empty_descs);

    xsk_socket__delete(xsk);
    xsk_umem__delete(umem);
    bpf_xdp_detach(ifindex, xdp_flags, nullptr);
    bpf_object__close(obj);
    (void)sink;
    return 0;
}

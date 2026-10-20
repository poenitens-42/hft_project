/* Minimal exchange simulator: sends wire_msg datagrams over UDP, batched with sendmmsg.
 * One datagram per message (the receiver parses one message per packet). */
#include <arpa/inet.h>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <time.h>
#include <sys/socket.h>
#include <unistd.h>

#include "../xdp/feed_proto.h"

static uint64_t now_ns()
{
    timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

static const int MAX_BATCH = 1024;

int main(int argc, char **argv)
{
    const char *ip = argc > 1 ? argv[1] : "127.0.0.1";
    long count = argc > 2 ? atol(argv[2]) : 100000;
    long pps   = argc > 3 ? atol(argv[3]) : 10000; /* 0 = as fast as possible */
    int batch  = argc > 4 ? atoi(argv[4]) : 32;    /* datagrams per sendmmsg call */
    if (argc > 5 || (argc > 1 && !strcmp(argv[1], "-h")) || count <= 0 || pps < 0 ||
        batch < 1 || batch > MAX_BATCH) {
        fprintf(stderr, "usage: %s [dest_ip=127.0.0.1] [count=100000] [pps=10000, 0=max] [batch=32, 1..%d]\n",
                argv[0], MAX_BATCH);
        return 2;
    }

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) { perror("socket"); return 1; }
    sockaddr_in dst{};
    dst.sin_family = AF_INET;
    dst.sin_port = htons(FEED_PORT);
    if (inet_pton(AF_INET, ip, &dst.sin_addr) != 1) { fprintf(stderr, "bad ip\n"); return 2; }

    static wire_msg msgs[MAX_BATCH];
    static iovec iov[MAX_BATCH];
    static mmsghdr hdr[MAX_BATCH];
    for (int j = 0; j < batch; j++) {
        iov[j].iov_base = &msgs[j];
        iov[j].iov_len = sizeof(wire_msg);
        hdr[j].msg_hdr = {};
        hdr[j].msg_hdr.msg_name = &dst;
        hdr[j].msg_hdr.msg_namelen = sizeof(dst);
        hdr[j].msg_hdr.msg_iov = &iov[j];
        hdr[j].msg_hdr.msg_iovlen = 1;
    }

    /* Pacing is per batch: pps msgs/s => one batch every batch/pps seconds. */
    uint64_t gap = pps > 0 ? 1000000000ull * (uint64_t)batch / (uint64_t)pps : 0;
    uint64_t start = now_ns();
    uint64_t next = start;
    uint32_t seed = 12345;
    long sent = 0, calls = 0;

    while (sent < count) {
        int n = (int)((count - sent) < batch ? (count - sent) : batch);
        for (int j = 0; j < n; j++) {
            seed = seed * 1664525u + 1013904223u; /* deterministic LCG */
            msgs[j].msg_type = "ACT"[seed % 3];
            msgs[j].order_id = htonl((uint32_t)(sent + j) + 1);
            msgs[j].side     = (seed >> 8) & 1 ? 'B' : 'S';
            msgs[j].price    = htonl(1000000 + (seed >> 12) % 200); /* 100.0000 + 0..199 ticks */
            msgs[j].quantity = htonl(1 + (seed >> 20) % 1000);
        }
        int done = 0; /* sendmmsg may send fewer than asked; resend the rest */
        while (done < n) {
            int r = sendmmsg(fd, hdr + done, n - done, 0);
            calls++;
            if (r < 0) { perror("sendmmsg"); return 1; }
            done += r;
        }
        sent += n;
        if (gap) { next += gap; while (now_ns() < next) {} }
    }

    double secs = (double)(now_ns() - start) / 1e9;
    printf("sent %ld messages (%zu bytes each) to %s:%d in %.3f s\n", sent, sizeof(wire_msg), ip, FEED_PORT, secs);
    printf("achieved %.0f msg/s (target %s), batch=%d, %ld sendmmsg calls\n",
           secs > 0 ? (double)sent / secs : 0.0, pps ? "paced" : "max", batch, calls);
    return 0;
}


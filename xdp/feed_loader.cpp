#include <iostream>
#include <csignal>
#include <cstdint>
#include <chrono>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

struct market_msg {
    uint8_t  msg_type;
    uint32_t order_id;
    uint8_t  side;
    uint32_t price;
    uint32_t quantity;
    uint64_t timestamp;
} __attribute__((packed));

static volatile bool running = true;
void sig_handler(int) { running = false; }

static int handle_market_msg(void *ctx, void *data, size_t size)
{
    if (size < sizeof(market_msg)) return 0;

    auto *msg = static_cast<market_msg*>(data);

    auto now = std::chrono::high_resolution_clock::now();
    auto ns  = std::chrono::duration_cast<std::chrono::nanoseconds>(
                   now.time_since_epoch()).count();

    uint64_t latency_ns = (uint64_t)ns - msg->timestamp;

    std::cout
        << "MSG"
        << " type="    << (char)msg->msg_type
        << " order="   << msg->order_id
        << " side="    << (char)msg->side
        << " price="   << msg->price / 10000.0
        << " qty="     << msg->quantity
        << " latency=" << latency_ns << "ns"
        << "\n";

    return 0;
}

int main(int argc, char **argv)
{
    signal(SIGINT,  sig_handler);
    signal(SIGTERM, sig_handler);

    /* Connect directly to running kernel map by id */
    int map_fd = bpf_map_get_fd_by_id(14);  /* feed_ringbuf id */
    if (map_fd < 0) {
        std::cerr << "Failed to get map fd — are you root?\n";
        return 1;
    }

    struct ring_buffer *rb = ring_buffer__new(
        map_fd, handle_market_msg, nullptr, nullptr);
    if (!rb) {
        std::cerr << "Failed to create ring buffer\n";
        return 1;
    }

    std::cout << "Connected to live feed_ringbuf (id=14)\n";
    std::cout << "Waiting for market data on port 9000...\n\n";

    while (running) {
        ring_buffer__poll(rb, 100);
    }

    ring_buffer__free(rb);
    return 0;
}

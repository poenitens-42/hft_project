CLANG ?= clang
CXX   ?= g++

BPF_CFLAGS := -O2 -g -target bpf -D__TARGET_ARCH_x86 -I/usr/include/x86_64-linux-gnu
CXXFLAGS   ?= -O2 -std=c++17 -Wall -Wextra

all: xdp/xdp_feed_handler.o xdp/feed_loader tools/feed_sim

xdp/xdp_feed_handler.o: xdp/xdp_feed_handler.c xdp/feed_proto.h
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

xdp/feed_loader: xdp/feed_loader.cpp xdp/feed_proto.h
	$(CXX) $(CXXFLAGS) $< -o $@ -lbpf

tools/feed_sim: tools/feed_sim.cpp xdp/feed_proto.h
	$(CXX) $(CXXFLAGS) $< -o $@

clean:
	rm -f xdp/*.o xdp/feed_loader tools/feed_sim

.PHONY: all clean


#!/usr/bin/env bash
# Two network endpoints joined by a virtual cable, so traffic really crosses an
# interface instead of the loopback shortcut.
#
#   root namespace:  vtx 10.99.0.1  <--- veth cable --->  vrx 10.99.0.2 in namespace xdprx
#
#   sudo tools/veth_setup.sh up      create it
#   sudo tools/veth_setup.sh down    remove it
#
# Run the receiver inside the namespace:   sudo ip netns exec xdprx ./xdp/feed_xsk vrx
# Run the sender in the normal namespace:  ./tools/feed_sim 10.99.0.2 1000000 0
set -euo pipefail

NS=xdprx; TX=vtx; RX=vrx

down() {
    ip netns del "$NS" 2>/dev/null || true   # deleting the namespace also removes vrx and its peer vtx
    ip link del "$TX" 2>/dev/null || true
}

case "${1:-}" in
up)
    down
    ip netns add "$NS"
    ip link add "$TX" type veth peer name "$RX"
    ip link set "$RX" netns "$NS"
    ip addr add 10.99.0.1/24 dev "$TX"
    ip link set "$TX" up
    ip netns exec "$NS" ip addr add 10.99.0.2/24 dev "$RX"
    ip netns exec "$NS" ip link set "$RX" up
    ip netns exec "$NS" ip link set lo up
    echo "veth up: $TX (10.99.0.1) <-> $RX (10.99.0.2, namespace $NS)"
    ;;
down)
    down
    echo "veth removed"
    ;;
*)
    echo "usage: $0 up|down" >&2
    exit 2
    ;;
esac


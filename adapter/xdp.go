package adapter

import (
	"net/netip"
	"time"
)

type XDPBlocker interface {
	BlockIP(ip netip.Addr, duration time.Duration) error
	UnblockIP(ip netip.Addr) error
	IsBlocked(ip netip.Addr) bool
	BlockedCount() int
}

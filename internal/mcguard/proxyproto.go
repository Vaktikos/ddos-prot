package mcguard

import (
	"encoding/binary"
	"net/netip"
)

// proxyV2Signature starts every PROXY protocol version 2 header.
var proxyV2Signature = []byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A}

// ProxyHeaderV2 builds a PROXY protocol v2 header for a TCP connection from src to dst, so the
// game server sees the player's real address instead of the guard's.
func ProxyHeaderV2(src, dst netip.AddrPort) []byte {
	h := append([]byte(nil), proxyV2Signature...)
	h = append(h, 0x21) // version 2, command PROXY
	if src.Addr().Is4() && dst.Addr().Is4() {
		h = append(h, 0x11, 0, 12) // AF_INET, STREAM, 12 bytes of addresses
		s, d := src.Addr().As4(), dst.Addr().As4()
		h = append(h, s[:]...)
		h = append(h, d[:]...)
	} else {
		h = append(h, 0x21, 0, 36) // AF_INET6, STREAM, 36 bytes
		s, d := src.Addr().As16(), dst.Addr().As16()
		h = append(h, s[:]...)
		h = append(h, d[:]...)
	}
	h = binary.BigEndian.AppendUint16(h, src.Port())
	h = binary.BigEndian.AppendUint16(h, dst.Port())
	return h
}

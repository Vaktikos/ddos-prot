// Package mcguard is a Minecraft Java protection proxy. It sits in front of the game
// server, validates the protocol handshake before any byte reaches the server, limits
// abusive sources and can pass the real player address on with the PROXY protocol.
package mcguard

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"
)

// Limits taken from the protocol: a handshake is tiny. Anything larger is not a client.
const (
	maxHandshakeLen = 1200 // length of id+payload; real ones are below 300 bytes
	maxHostBytes    = 767 + 16
	maxVarIntBytes  = 5
)

// Next-state values of the handshake packet.
const (
	StateStatus   = 1
	StateLogin    = 2
	StateTransfer = 3 // 1.20.5 and later
)

// Handshake is the parsed first packet of a Minecraft Java connection.
type Handshake struct {
	Protocol int32
	Host     string // without the Forge marker
	Port     uint16
	State    int
	Legacy   bool   // pre-1.7 server list ping (first byte 0xFE)
	Raw      []byte // exact bytes consumed, to be forwarded to the server
}

// ErrInvalidHandshake wraps every reason a client is rejected.
var ErrInvalidHandshake = errors.New("ungültiger minecraft-handshake")

func invalid(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidHandshake, fmt.Sprintf(format, a...))
}

// capture reads from br and remembers every byte, so the handshake can be forwarded unchanged.
type capture struct {
	br  *bufio.Reader
	raw []byte
}

func (c *capture) ReadByte() (byte, error) {
	b, err := c.br.ReadByte()
	if err == nil {
		c.raw = append(c.raw, b)
	}
	return b, err
}

func (c *capture) readN(n int) ([]byte, error) {
	buf := make([]byte, n)
	if _, err := io.ReadFull(c.br, buf); err != nil {
		return nil, err
	}
	c.raw = append(c.raw, buf...)
	return buf, nil
}

func (c *capture) varInt() (int32, error) {
	var value uint32
	for i := 0; i < maxVarIntBytes; i++ {
		b, err := c.ReadByte()
		if err != nil {
			return 0, err
		}
		value |= uint32(b&0x7f) << (7 * i)
		if b&0x80 == 0 {
			return int32(value), nil
		}
	}
	return 0, invalid("VarInt länger als %d Byte", maxVarIntBytes)
}

// ReadHandshake parses the first packet. It reads at most maxHandshakeLen bytes plus the
// length prefix and never allocates based on an unchecked client value.
func ReadHandshake(br *bufio.Reader) (*Handshake, error) {
	first, err := br.Peek(1)
	if err != nil {
		return nil, err
	}
	if first[0] == 0xFE { // legacy server list ping: one fixed, tiny packet
		raw := make([]byte, 0, 64)
		for len(raw) < 64 {
			b, err := br.ReadByte()
			if err != nil {
				break
			}
			raw = append(raw, b)
			if br.Buffered() == 0 {
				break
			}
		}
		return &Handshake{Legacy: true, State: StateStatus, Raw: raw}, nil
	}

	c := &capture{br: br}
	length, err := c.varInt()
	if err != nil {
		return nil, err
	}
	if length < 3 || length > maxHandshakeLen {
		return nil, invalid("Paketlänge %d außerhalb 3..%d", length, maxHandshakeLen)
	}
	payload, err := c.readN(int(length))
	if err != nil {
		return nil, err
	}
	// The payload is parsed from the captured slice, so a lying length cannot over-read.
	pr := bufio.NewReader(strings.NewReader(string(payload)))
	p := &capture{br: pr}
	id, err := p.varInt()
	if err != nil {
		return nil, err
	}
	if id != 0 {
		return nil, invalid("Paket-ID %d statt 0", id)
	}
	proto, err := p.varInt()
	if err != nil {
		return nil, err
	}
	if proto < 1 || proto > 1<<20 {
		return nil, invalid("Protokollversion %d unplausibel", proto)
	}
	hostLen, err := p.varInt()
	if err != nil {
		return nil, err
	}
	if hostLen < 1 || int(hostLen) > maxHostBytes {
		return nil, invalid("Hostname-Länge %d außerhalb 1..%d", hostLen, maxHostBytes)
	}
	hostRaw, err := p.readN(int(hostLen))
	if err != nil {
		return nil, invalid("Hostname abgeschnitten")
	}
	if !utf8.Valid(hostRaw) {
		return nil, invalid("Hostname ist kein gültiges UTF-8")
	}
	portRaw, err := p.readN(2)
	if err != nil {
		return nil, invalid("Port fehlt")
	}
	state, err := p.varInt()
	if err != nil {
		return nil, invalid("Zielstatus fehlt")
	}
	if state != StateStatus && state != StateLogin && state != StateTransfer {
		return nil, invalid("Zielstatus %d unbekannt", state)
	}
	if extra, _ := pr.Peek(1); len(extra) > 0 {
		return nil, invalid("überzählige Bytes im Handshake")
	}
	host := string(hostRaw)
	if i := strings.IndexByte(host, 0); i >= 0 { // Forge and others append "\0FML\0" and similar
		host = host[:i]
	}
	if host == "" || strings.ContainsAny(host, "\r\n\t ") {
		return nil, invalid("Hostname enthält unzulässige Zeichen")
	}
	return &Handshake{
		Protocol: proto, Host: strings.ToLower(strings.TrimSuffix(host, ".")),
		Port: uint16(portRaw[0])<<8 | uint16(portRaw[1]), State: int(state), Raw: c.raw,
	}, nil
}

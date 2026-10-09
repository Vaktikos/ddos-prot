package mcguard

import (
	"bufio"
	"bytes"
	"errors"
	"strings"
	"testing"
)

func varInt(v int) []byte {
	var out []byte
	u := uint32(v)
	for {
		b := byte(u & 0x7f)
		u >>= 7
		if u != 0 {
			out = append(out, b|0x80)
		} else {
			return append(out, b)
		}
	}
}

// handshake builds a real handshake packet like the Java client sends it.
func handshake(proto int, host string, port uint16, state int) []byte {
	var p []byte
	p = append(p, varInt(0)...)
	p = append(p, varInt(proto)...)
	p = append(p, varInt(len(host))...)
	p = append(p, host...)
	p = append(p, byte(port>>8), byte(port))
	p = append(p, varInt(state)...)
	return append(varInt(len(p)), p...)
}

func parse(b []byte) (*Handshake, error) { return ReadHandshake(bufio.NewReader(bytes.NewReader(b))) }

func TestValidHandshakes(t *testing.T) {
	for name, tc := range map[string]struct {
		pkt   []byte
		host  string
		state int
	}{
		"1.20.4 login":    {handshake(765, "mc.example.net", 25565, StateLogin), "mc.example.net", StateLogin},
		"1.8 status":      {handshake(47, "MC.Example.Net.", 25565, StateStatus), "mc.example.net", StateStatus},
		"forge marker":    {handshake(340, "mc.example.net\x00FML\x00", 25565, StateLogin), "mc.example.net", StateLogin},
		"transfer 1.20.5": {handshake(766, "mc.example.net", 25565, StateTransfer), "mc.example.net", StateTransfer},
		"ip address host": {handshake(765, "203.0.113.9", 25565, StateStatus), "203.0.113.9", StateStatus},
	} {
		hs, err := parse(tc.pkt)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if hs.Host != tc.host || hs.State != tc.state || hs.Port != 25565 {
			t.Errorf("%s: %+v", name, hs)
		}
		if !bytes.Equal(hs.Raw, tc.pkt) {
			t.Errorf("%s: Raw muss das Paket unverändert enthalten", name)
		}
	}
}

func TestLegacyPing(t *testing.T) {
	hs, err := parse([]byte{0xFE, 0x01, 0xFA})
	if err != nil || !hs.Legacy || hs.State != StateStatus || len(hs.Raw) == 0 {
		t.Fatalf("Legacy-Ping: %+v %v", hs, err)
	}
}

func TestInvalidHandshakesAreRejected(t *testing.T) {
	long := strings.Repeat("a", 900)
	cases := map[string][]byte{
		"HTTP-Anfrage":           []byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"),
		"riesige Länge":          append(varInt(5000), bytes.Repeat([]byte{1}, 20)...),
		"Länge 0":                {0x00},
		"Paket-ID 1":             func() []byte { b := handshake(765, "h", 25565, 1); b[1] = 1; return b }(),
		"Zielstatus 9":           handshake(765, "mc.example.net", 25565, 9),
		"Protokoll 0":            handshake(0, "mc.example.net", 25565, 2),
		"Protokoll riesig":       handshake(1<<25, "mc.example.net", 25565, 2),
		"leerer Host":            handshake(765, "", 25565, 2),
		"Host mit Leerzeichen":   handshake(765, "a b", 25565, 2),
		"Host zu lang":           handshake(765, long+long, 25565, 2),
		"kein UTF-8":             handshake(765, "\xff\xfe\xfd", 25565, 2),
		"abgeschnitten":          handshake(765, "mc.example.net", 25565, 2)[:8],
		"leer":                   {},
		"VarInt zu lang":         {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01},
		"überzählige Bytes":      func() []byte { b := handshake(765, "h", 25565, 1); b[0]++; return append(b, 0x09) }(),
		"Länge größer als Daten": func() []byte { b := handshake(765, "h", 25565, 1); b[0] += 20; return b }(),
	}
	for name, b := range cases {
		if hs, err := parse(b); err == nil {
			t.Errorf("%s: wurde akzeptiert: %+v", name, hs)
		}
	}
}

func TestInvalidErrorsAreClassified(t *testing.T) {
	_, err := parse(handshake(765, "mc.example.net", 25565, 9))
	if !errors.Is(err, ErrInvalidHandshake) {
		t.Fatalf("Fehler muss ErrInvalidHandshake sein: %v", err)
	}
}

// FuzzReadHandshake must never panic and never hand back more bytes than it was given.
func FuzzReadHandshake(f *testing.F) {
	f.Add(handshake(765, "mc.example.net", 25565, 2))
	f.Add([]byte{0xFE, 0x01})
	f.Add([]byte("GET / HTTP/1.1\r\n"))
	f.Add([]byte{0xff, 0xff, 0xff, 0xff, 0x0f})
	f.Fuzz(func(t *testing.T, data []byte) {
		hs, err := ReadHandshake(bufio.NewReader(bytes.NewReader(data)))
		if err == nil && len(hs.Raw) > len(data) {
			t.Fatalf("Raw (%d) länger als die Eingabe (%d)", len(hs.Raw), len(data))
		}
	})
}

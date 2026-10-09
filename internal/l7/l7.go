// Package l7 reads the reject log of a reverse proxy (nginx) and turns it into per-source
// request rates. The agent works on packets and cannot see HTTP; the proxy decides which
// requests are rejected (limit_req / limit_conn), and this package only counts them.
package l7

import (
	"bytes"
	"io"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"
)

// Entry is one rejected request from the ss_reject log format
// (deploy/l7/nginx-ratelimit.conf): `$remote_addr [$time_iso8601] "$request" $status limit=... ua="..."`.
type Entry struct {
	Addr   netip.Addr
	Status int
}

// ParseLine parses one log line. Lines in any other format are rejected, never guessed at.
func ParseLine(line string) (Entry, bool) {
	sp := strings.IndexByte(line, ' ')
	if sp <= 0 {
		return Entry{}, false
	}
	addr, err := netip.ParseAddr(line[:sp])
	if err != nil {
		return Entry{}, false
	}
	rest := line[sp+1:]
	if !strings.HasPrefix(rest, "[") {
		return Entry{}, false
	}
	end := strings.Index(rest, "] \"")
	if end < 0 {
		return Entry{}, false
	}
	rest = rest[end+3:] // after the opening quote of the request
	q := strings.Index(rest, "\" ")
	if q < 0 {
		return Entry{}, false
	}
	rest = rest[q+2:]
	codeEnd := strings.IndexByte(rest, ' ')
	if codeEnd < 0 {
		codeEnd = len(rest)
	}
	status, err := strconv.Atoi(rest[:codeEnd])
	if err != nil || status < 100 || status > 599 {
		return Entry{}, false
	}
	return Entry{Addr: addr.Unmap(), Status: status}, true
}

const (
	// MaxReadPerPoll bounds the bytes read in one poll. When a flood writes more, the tailer
	// skips ahead to the newest data and counts what it skipped.
	MaxReadPerPoll = 4 << 20
	maxLineBytes   = 16 << 10
)

// Tailer follows a growing log file. It starts at the current end, so old log content is
// never replayed, and it follows rotation (new inode or truncation).
type Tailer struct {
	path     string
	f        *os.File
	ino      uint64
	off      int64
	partial  []byte
	started  bool
	appeared bool   // the file was missing at some point, so a new one is read from its start
	Skipped  uint64 // bytes skipped because the log grew faster than it could be read
}

func NewTailer(path string) *Tailer { return &Tailer{path: path} }

func (t *Tailer) Close() {
	if t.f != nil {
		t.f.Close()
		t.f = nil
	}
}

// Poll returns the complete lines written since the last call.
func (t *Tailer) Poll() ([]string, error) {
	fi, err := os.Stat(t.path)
	if err != nil {
		t.Close()
		t.appeared = true
		return nil, err
	}
	ino := inode(fi)
	if t.f == nil || ino != t.ino {
		t.Close()
		f, err := os.Open(t.path)
		if err != nil {
			return nil, err
		}
		t.f, t.ino, t.partial = f, ino, nil
		if !t.started && !t.appeared {
			t.off = fi.Size() // first open: only new lines
		} else {
			t.off = 0 // rotated: the new file is entirely new
		}
		t.started, t.appeared = true, false
	}
	if fi.Size() < t.off { // truncated in place
		t.off, t.partial = 0, nil
	}
	pending := fi.Size() - t.off
	if pending <= 0 {
		return nil, nil
	}
	if pending > MaxReadPerPoll {
		t.Skipped += uint64(pending - MaxReadPerPoll)
		t.off = fi.Size() - MaxReadPerPoll
		t.partial = nil
		pending = MaxReadPerPoll
	}
	buf := make([]byte, pending)
	n, err := t.f.ReadAt(buf, t.off)
	if err != nil && err != io.EOF {
		return nil, err
	}
	t.off += int64(n)
	data := append(t.partial, buf[:n]...)
	t.partial = nil
	var lines []string
	for {
		i := bytes.IndexByte(data, '\n')
		if i < 0 {
			break
		}
		if i <= maxLineBytes {
			lines = append(lines, string(data[:i]))
		}
		data = data[i+1:]
	}
	if len(data) <= maxLineBytes {
		t.partial = append([]byte(nil), data...)
	}
	return lines, nil
}

// Window counts requests per source over the last Seconds seconds.
type Window struct {
	secs    int
	stamp   []int64
	buckets []map[netip.Addr]uint32
	totals  []uint64
	// Overflow counts requests from sources beyond MaxSources in one second; they count toward
	// the total but cannot be attributed to a source.
	Overflow uint64
}

// MaxSources bounds the distinct sources tracked per second.
const MaxSources = 20000

func NewWindow(seconds int) *Window {
	if seconds < 1 {
		seconds = 10
	}
	return &Window{secs: seconds, stamp: make([]int64, seconds),
		buckets: make([]map[netip.Addr]uint32, seconds), totals: make([]uint64, seconds)}
}

func (w *Window) slot(at time.Time) int {
	sec := at.Unix()
	i := int(sec % int64(w.secs))
	if w.stamp[i] != sec {
		w.stamp[i], w.buckets[i], w.totals[i] = sec, map[netip.Addr]uint32{}, 0
	}
	return i
}

// Add records n requests from addr at the given time.
func (w *Window) Add(at time.Time, addr netip.Addr, n uint32) {
	i := w.slot(at)
	w.totals[i] += uint64(n)
	b := w.buckets[i]
	if _, ok := b[addr]; !ok && len(b) >= MaxSources {
		w.Overflow += uint64(n)
		return
	}
	b[addr] += n
}

// Rates returns the total and per-source requests per second over the window ending at now.
func (w *Window) Rates(now time.Time) (total float64, per map[netip.Addr]float64) {
	per = map[netip.Addr]float64{}
	oldest := now.Unix() - int64(w.secs) + 1
	var sum uint64
	for i := range w.buckets {
		if w.stamp[i] < oldest || w.stamp[i] > now.Unix() {
			continue
		}
		sum += w.totals[i]
		for a, c := range w.buckets[i] {
			per[a] += float64(c)
		}
	}
	f := float64(w.secs)
	for a := range per {
		per[a] /= f
	}
	return float64(sum) / f, per
}

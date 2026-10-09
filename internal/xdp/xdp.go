package xdp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

// Attach modes.
const (
	ModeAuto    = "auto"    // native if the driver supports it, otherwise generic
	ModeNative  = "native"  // driver mode only
	ModeGeneric = "generic" // works on every interface, slower
)

// Block owners. Manual blocks come from operator rules in the policy; automatic blocks
// come from incident-driven source blocking. Each is cleared independently.
const (
	OwnerManual = "manual"
	OwnerAuto   = "auto"
)

type blockEntry struct {
	until time.Time
	owner string
}

// SourceRate is the measured rate of one source toward protected destinations.
type SourceRate struct {
	Addr   netip.Addr
	PPS    float64
	BPS    float64
	SYNPPS float64
}

// Manager owns the loaded program, its maps and the attached links.
type Manager struct {
	mu     sync.Mutex
	objs   FilterObjects
	links  []link.Link
	pinned bool

	allow, protect map[netip.Prefix]bool
	blocks         map[netip.Prefix]blockEntry

	prev4  map[uint32]FilterSrcStats
	prev6  map[[16]byte]FilterSrcStats
	prevAt time.Time
}

// Load loads the BPF object into the kernel without attaching it.
func Load() (*Manager, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("memlock-limit: %w", err)
	}
	m := &Manager{
		allow: map[netip.Prefix]bool{}, protect: map[netip.Prefix]bool{}, blocks: map[netip.Prefix]blockEntry{},
		prev4: map[uint32]FilterSrcStats{}, prev6: map[[16]byte]FilterSrcStats{},
	}
	if err := LoadFilterObjects(&m.objs, nil); err != nil {
		return nil, fmt.Errorf("xdp-programm laden: %w", err)
	}
	return m, nil
}

// Attach hooks the program onto interfaces. If a pinned link from an earlier run exists
// under pinDir, its program is replaced in place, so there is no unprotected gap and the
// filter keeps running when the agent restarts or crashes. Without pinDir (no bpffs) the
// filter ends with the process; the returned bool tells whether it is pinned.
func (m *Manager) Attach(ifaces []string, mode, pinDir string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if mode == "" {
		mode = ModeAuto
	}
	pinnedAll := pinDir != ""
	for _, name := range ifaces {
		ifc, err := net.InterfaceByName(name)
		if err != nil {
			return false, fmt.Errorf("interface %s: %w", name, err)
		}
		pin := ""
		if pinDir != "" {
			pin = filepath.Join(pinDir, "xdp-"+name)
		}
		if pin != "" {
			if l, err := link.LoadPinnedLink(pin, nil); err == nil {
				if err := l.Update(m.objs.SentinelFilter); err == nil {
					m.links = append(m.links, l)
					continue
				}
				_ = l.Close()
				_ = unpin(pin)
			}
		}
		l, err := attachOne(m.objs.SentinelFilter, ifc.Index, mode)
		if err != nil {
			return false, fmt.Errorf("xdp an %s anhängen: %w", name, err)
		}
		if pin != "" {
			if err := l.Pin(pin); err != nil {
				pinnedAll = false
			}
		}
		m.links = append(m.links, l)
	}
	m.pinned = pinnedAll
	return pinnedAll, nil
}

func attachOne(prog *ebpf.Program, ifindex int, mode string) (link.Link, error) {
	try := func(flags link.XDPAttachFlags) (link.Link, error) {
		return link.AttachXDP(link.XDPOptions{Program: prog, Interface: ifindex, Flags: flags})
	}
	switch mode {
	case ModeNative:
		return try(link.XDPDriverMode)
	case ModeGeneric:
		return try(link.XDPGenericMode)
	case ModeAuto:
		if l, err := try(link.XDPDriverMode); err == nil {
			return l, nil
		}
		return try(link.XDPGenericMode)
	}
	return nil, fmt.Errorf("unbekannter xdp-modus %q", mode)
}

func unpin(path string) error { return unixUnlink(path) }

// Close releases the process's handles. Pinned links stay attached.
func (m *Manager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	var errs []error
	for _, l := range m.links {
		errs = append(errs, l.Close())
	}
	m.links = nil
	errs = append(errs, m.objs.Close())
	return errors.Join(errs...)
}

// Detach removes the filter from all interfaces, including pinned links.
func (m *Manager) Detach(pinDir string, ifaces []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	var errs []error
	for _, l := range m.links {
		errs = append(errs, l.Unpin(), l.Close())
	}
	m.links = nil
	for _, name := range ifaces {
		if pinDir != "" {
			if l, err := link.LoadPinnedLink(filepath.Join(pinDir, "xdp-"+name), nil); err == nil {
				errs = append(errs, l.Unpin(), l.Close())
			}
		}
	}
	return errors.Join(errs...)
}

// SetAllow replaces the set of sources that are never filtered (trusted and management networks).
func (m *Manager) SetAllow(want []netip.Prefix) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return syncSet(m.allow, want, m.objs.Allow4, m.objs.Allow6)
}

// SetProtected replaces the set of destinations whose inbound sources are counted.
func (m *Manager) SetProtected(want []netip.Prefix) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return syncSet(m.protect, want, m.objs.Protect4, m.objs.Protect6)
}

func syncSet(have map[netip.Prefix]bool, want []netip.Prefix, m4, m6 *ebpf.Map) error {
	wantSet := map[netip.Prefix]bool{}
	for _, p := range want {
		wantSet[p] = true
		if !have[p] {
			if err := putPrefix(m4, m6, p, uint8(1)); err != nil {
				return err
			}
			have[p] = true
		}
	}
	for p := range have {
		if !wantSet[p] {
			if err := delPrefix(m4, m6, p); err != nil {
				return err
			}
			delete(have, p)
		}
	}
	return nil
}

func key4(p netip.Prefix) FilterLpm4Key {
	a := p.Addr().As4()
	return FilterLpm4Key{Prefixlen: uint32(p.Bits()), Addr: binary.NativeEndian.Uint32(a[:])}
}

func key6(p netip.Prefix) FilterLpm6Key {
	return FilterLpm6Key{Prefixlen: uint32(p.Bits()), Addr: p.Addr().As16()}
}

func putPrefix(m4, m6 *ebpf.Map, p netip.Prefix, val any) error {
	if p.Addr().Is4() {
		return m4.Put(key4(p), val)
	}
	return m6.Put(key6(p), val)
}

func delPrefix(m4, m6 *ebpf.Map, p netip.Prefix) error {
	var err error
	if p.Addr().Is4() {
		err = m4.Delete(key4(p))
	} else {
		err = m6.Delete(key6(p))
	}
	if errors.Is(err, ebpf.ErrKeyNotExist) {
		return nil
	}
	return err
}

// monotonicNS returns CLOCK_MONOTONIC, the clock the BPF program compares expiry against.
func monotonicNS() uint64 {
	var ts unix.Timespec
	_ = unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts)
	return uint64(ts.Sec)*1_000_000_000 + uint64(ts.Nsec)
}

// Block drops packets from prefix until the given time. The expiry is stored in the kernel
// entry itself, so the block ends on time even if the agent is gone.
func (m *Manager) Block(p netip.Prefix, until time.Time, owner string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.blockLocked(p, until, owner)
}

func (m *Manager) blockLocked(p netip.Prefix, until time.Time, owner string) error {
	remaining := time.Until(until)
	if remaining <= 0 {
		return nil
	}
	if cur, ok := m.blocks[p]; ok && cur.until.After(until) {
		until = cur.until // never shorten an existing block
		remaining = time.Until(until)
	}
	val := FilterBlockVal{ExpiresNs: monotonicNS() + uint64(remaining.Nanoseconds())}
	if err := putPrefix(m.objs.Block4, m.objs.Block6, p, val); err != nil {
		return err
	}
	m.blocks[p] = blockEntry{until: until, owner: owner}
	return nil
}

// SetBlocks replaces all blocks of one owner with the wanted set and removes expired ones.
func (m *Manager) SetBlocks(owner string, want map[netip.Prefix]time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for p, e := range m.blocks {
		if e.owner == owner {
			if until, ok := want[p]; !ok || !until.After(time.Now()) {
				if err := delPrefix(m.objs.Block4, m.objs.Block6, p); err != nil {
					return err
				}
				delete(m.blocks, p)
			}
		}
	}
	for p, until := range want {
		if err := m.blockLocked(p, until, owner); err != nil {
			return err
		}
	}
	return nil
}

// Unblock removes a block regardless of owner.
func (m *Manager) Unblock(p netip.Prefix) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.blocks, p)
	return delPrefix(m.objs.Block4, m.objs.Block6, p)
}

// Expire removes blocks whose time has passed. The kernel already ignores them; this frees map space.
func (m *Manager) Expire(now time.Time) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for p, e := range m.blocks {
		if !e.until.After(now) {
			_ = delPrefix(m.objs.Block4, m.objs.Block6, p)
			delete(m.blocks, p)
			n++
		}
	}
	return n
}

// BlockCount returns the number of active (unexpired) blocks.
func (m *Manager) BlockCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.blocks)
}

// Stats are cumulative counters summed over all CPUs.
type Stats struct {
	DroppedPackets, DroppedBytes, PassedPackets uint64
}

// Stats reads the kernel counters.
func (m *Manager) Stats() (Stats, error) {
	var out Stats
	for i, dst := range []*uint64{&out.DroppedPackets, &out.DroppedBytes, &out.PassedPackets} {
		var perCPU []uint64
		if err := m.objs.Stats.Lookup(uint32(i), &perCPU); err != nil {
			return out, err
		}
		for _, v := range perCPU {
			*dst += v
		}
	}
	return out, nil
}

// Sample returns sources whose rate since the previous call is at least minPPS, strongest
// first, at most limit entries. The first call only establishes the baseline.
func (m *Manager) Sample(now time.Time, minPPS float64, limit int) []SourceRate {
	m.mu.Lock()
	defer m.mu.Unlock()
	dt := now.Sub(m.prevAt).Seconds()
	first := m.prevAt.IsZero() || dt <= 0
	next4 := map[uint32]FilterSrcStats{}
	next6 := map[[16]byte]FilterSrcStats{}
	var out []SourceRate

	add := func(addr netip.Addr, cur, prev FilterSrcStats) {
		if first {
			return
		}
		d := func(c, p uint64) float64 {
			if c < p { // entry was evicted and recreated
				return float64(c)
			}
			return float64(c - p)
		}
		pps := d(cur.Packets, prev.Packets) / dt
		if pps >= minPPS {
			out = append(out, SourceRate{Addr: addr, PPS: pps, BPS: d(cur.Bytes, prev.Bytes) * 8 / dt, SYNPPS: d(cur.Syn, prev.Syn) / dt})
		}
	}

	forEach(m.objs.Src4, func(k uint32, v FilterSrcStats) {
		next4[k] = v
		var b [4]byte
		binary.NativeEndian.PutUint32(b[:], k)
		add(netip.AddrFrom4(b), v, m.prev4[k])
	})
	forEach(m.objs.Src6, func(k [16]byte, v FilterSrcStats) {
		next6[k] = v
		add(netip.AddrFrom16(k), v, m.prev6[k])
	})
	m.prev4, m.prev6, m.prevAt = next4, next6, now
	sort.Slice(out, func(i, j int) bool { return out[i].PPS > out[j].PPS })
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

// ResetBaseline makes the next Sample call a fresh baseline. Call it when source
// blocking starts, so rates are not computed over a long idle gap.
func (m *Manager) ResetBaseline() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.prevAt = time.Time{}
}

// forEach walks a map in batches, which needs far fewer system calls than key-by-key
// iteration on a map with many entries; it falls back to iteration if batching is unsupported.
func forEach[K comparable](m *ebpf.Map, fn func(K, FilterSrcStats)) {
	const batch = 1024
	keys := make([]K, batch)
	vals := make([]FilterSrcStats, batch)
	var cursor ebpf.MapBatchCursor
	for {
		n, err := m.BatchLookup(&cursor, keys, vals, nil)
		for i := 0; i < n; i++ {
			fn(keys[i], vals[i])
		}
		if err == nil {
			continue
		}
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return // end of map
		}
		if errors.Is(err, ebpf.ErrNotSupported) {
			var k K
			var v FilterSrcStats
			it := m.Iterate()
			for it.Next(&k, &v) {
				fn(k, v)
			}
		}
		return
	}
}

// EnsureBPFFS makes sure the BPF filesystem is mounted at dir, which is required to keep
// links pinned across agent restarts. It reports whether pinning is possible.
func EnsureBPFFS(dir string) bool {
	var st unix.Statfs_t
	if err := unix.Statfs(dir, &st); err == nil && st.Type == unix.BPF_FS_MAGIC {
		return true
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return false
	}
	return unix.Mount("bpf", dir, "bpf", 0, "") == nil
}

package metrics

import (
	"os"
	"strings"
	"testing"
)

const netDevFixture = `Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo:  100       10    0    0    0     0          0         0      100      10    0    0    0     0       0          0
  eth0: 5000000   4000    0    7    0     0          0         0  9000000   6000    0    3    0     0       0          0
`

func TestReadNetDevExcludesLoopback(t *testing.T) {
	m, err := ReadNetDev(strings.NewReader(netDevFixture))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := m["lo"]; ok {
		t.Fatal("lo darf nicht erfasst werden")
	}
	eth := m["eth0"]
	if eth.RxBytes != 5000000 || eth.RxPackets != 4000 || eth.RxDrops != 7 {
		t.Fatalf("rx falsch: %+v", eth)
	}
	if eth.TxBytes != 9000000 || eth.TxPackets != 6000 || eth.TxDrops != 3 {
		t.Fatalf("tx falsch: %+v", eth)
	}
}

func TestReadNetDevRejectsTruncatedLine(t *testing.T) {
	if _, err := ReadNetDev(strings.NewReader("  eth0: 1 2 3\n")); err == nil {
		t.Fatal("abgeschnittene Zeile muss einen Fehler liefern")
	}
}

func TestCPUPercent(t *testing.T) {
	a := CPUTimes{Total: 1000, Idle: 800}
	b := CPUTimes{Total: 1200, Idle: 830} // 200 ticks elapsed, 30 idle -> 85% busy
	if got := CPUPercent(a, b); got < 84.9 || got > 85.1 {
		t.Fatalf("CPUPercent = %.2f, want 85", got)
	}
	if CPUPercent(a, a) != 0 {
		t.Fatal("keine vergangenen Ticks ergeben 0%")
	}
}

func TestReadCPUAndMem(t *testing.T) {
	c, err := ReadCPU(strings.NewReader("cpu  100 0 50 800 50 0 0 0 0 0\ncpu0 1 2 3 4\n"))
	if err != nil {
		t.Fatal(err)
	}
	if c.Idle != 850 || c.Total != 1000 {
		t.Fatalf("cpu = %+v", c)
	}
	m, err := ReadMem(strings.NewReader("MemTotal:  1000 kB\nMemFree: 1 kB\nMemAvailable:   250 kB\n"))
	if err != nil {
		t.Fatal(err)
	}
	if got := m.MemUsedPercent(); got < 74.9 || got > 75.1 {
		t.Fatalf("MemUsedPercent = %.2f", got)
	}
	if _, err := ReadMem(strings.NewReader("MemTotal: 1 kB\n")); err == nil {
		t.Fatal("fehlendes MemAvailable muss Fehler liefern")
	}
}

// TestLiveProcfs checks the real kernel files on Linux hosts.
func TestLiveProcfs(t *testing.T) {
	if _, err := os.Stat(ProcNetDev); err != nil {
		t.Skip("kein procfs")
	}
	if _, err := ReadFile(ProcNetDev, ReadNetDev); err != nil {
		t.Fatalf("/proc/net/dev: %v", err)
	}
	if _, err := ReadFile(ProcStat, ReadCPU); err != nil {
		t.Fatalf("/proc/stat: %v", err)
	}
	if _, err := ReadFile(ProcMem, ReadMem); err != nil {
		t.Fatalf("/proc/meminfo: %v", err)
	}
}

func TestConntrackParsing(t *testing.T) {
	n, err := ReadUint(strings.NewReader("12345\n"))
	if err != nil || n != 12345 {
		t.Fatalf("ReadUint = %d, %v", n, err)
	}
	if _, err := ReadUint(strings.NewReader("abc")); err == nil {
		t.Fatal("ungültiger Wert muss Fehler liefern")
	}
	if got := ConntrackPercent(850, 1000); got != 85 {
		t.Fatalf("ConntrackPercent = %v", got)
	}
	if ConntrackPercent(5, 0) != 0 {
		t.Fatal("ohne Maximum keine Aussage")
	}
}

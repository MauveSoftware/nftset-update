//go:build integration

// Integration tests against the kernel. They create a private network
// namespace, so they never touch the host ruleset. Run them as root or inside
// a user namespace: unshare -rn go test -tags integration ./...
package nftset_test

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os/exec"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/nftables"
	"golang.org/x/sys/unix"

	"github.com/MauveSoftware/nftset-update/internal/interval"
	"github.com/MauveSoftware/nftset-update/internal/nftset"
	"github.com/MauveSoftware/nftset-update/internal/update"
)

const (
	tableName = "filter"
	setV4     = "blocklist-v4"
	setV6     = "blocklist-v6"
)

var updateConfig = update.Config{BatchSize: 10000, MaxRemoveFraction: 1, GuardMinElements: 1000, AllowEmpty: true}

type env struct {
	t     *testing.T
	nsFd  int
	conn  *nftables.Conn
	table *nftables.Table
}

func newEnv(t *testing.T) *env {
	t.Helper()
	nsFd := newNetNS(t)
	conn, err := nftset.Dial(nsFd)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.CloseLasting() })

	e := &env{t: t, nsFd: nsFd, conn: conn}
	e.table = conn.AddTable(&nftables.Table{Name: tableName, Family: nftables.TableFamilyINet})
	e.createSet(setV4, nftables.TypeIPAddr)
	e.createSet(setV6, nftables.TypeIP6Addr)
	return e
}

// newNetNS creates a network namespace and returns a file descriptor for it,
// leaving the namespace of the test process unchanged.
func newNetNS(t *testing.T) int {
	t.Helper()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	orig, err := unix.Open("/proc/thread-self/ns/net", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("open current netns: %v", err)
	}
	defer unix.Close(orig)

	if err := unix.Unshare(unix.CLONE_NEWNET); err != nil {
		t.Skipf("cannot create network namespace (run as root or via unshare -rn): %v", err)
	}
	nsFd, err := unix.Open("/proc/thread-self/ns/net", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("open new netns: %v", err)
	}
	if err := unix.Setns(orig, unix.CLONE_NEWNET); err != nil {
		t.Fatalf("restore netns: %v", err)
	}
	t.Cleanup(func() { unix.Close(nsFd) })
	return nsFd
}

func (e *env) createSet(name string, keyType nftables.SetDatatype) {
	e.t.Helper()
	set := &nftables.Set{Table: e.table, Name: name, KeyType: keyType, Interval: true, HasTimeout: true}
	if err := e.conn.AddSet(set, nil); err != nil {
		e.t.Fatalf("AddSet %s: %v", name, err)
	}
	if err := e.conn.Flush(); err != nil {
		e.t.Fatalf("Flush AddSet %s: %v", name, err)
	}
}

func (e *env) deleteSet(name string) {
	e.t.Helper()
	e.conn.DelSet(&nftables.Set{Table: e.table, Name: name})
	if err := e.conn.Flush(); err != nil {
		e.t.Fatalf("DelSet %s: %v", name, err)
	}
}

func (e *env) open(name string) *nftset.Set {
	e.t.Helper()
	set, err := nftset.Open(e.conn, nftables.TableFamilyINet, tableName, name)
	if err != nil {
		e.t.Fatalf("Open %s: %v", name, err)
	}
	return set
}

// sync runs one update like the command does and verifies the kernel state.
func (e *env) sync(name string, desired []interval.Interval) update.Result {
	e.t.Helper()
	set := e.open(name)
	current, err := set.Read()
	if err != nil {
		e.t.Fatalf("Read: %v", err)
	}
	plan := update.NewPlan(desired, current, updateConfig)
	res, err := update.Apply(context.Background(), set, current, plan, updateConfig.BatchSize)
	if err != nil {
		e.t.Fatalf("Apply: %v", err)
	}
	e.assertContent(name, desired)
	return res
}

func (e *env) assertContent(name string, want []interval.Interval) {
	e.t.Helper()
	got, err := e.open(name).Read()
	if err != nil {
		e.t.Fatalf("Read: %v", err)
	}
	if !slices.Equal(got, want) {
		e.t.Fatalf("set %s holds %d intervals, want %d (first difference: %s)",
			name, len(got), len(want), firstDifference(got, want))
	}
}

// nft runs the nft CLI inside the test namespace, if available.
func (e *env) nft(args ...string) (string, bool) {
	e.t.Helper()
	path, err := exec.LookPath("nft")
	if err != nil {
		return "", false
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	orig, err := unix.Open("/proc/thread-self/ns/net", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		e.t.Fatalf("open current netns: %v", err)
	}
	defer unix.Close(orig)
	if err := unix.Setns(e.nsFd, unix.CLONE_NEWNET); err != nil {
		e.t.Fatalf("enter test netns: %v", err)
	}
	// The child is forked from this locked thread and inherits its netns.
	out, runErr := exec.Command(path, args...).CombinedOutput()
	if err := unix.Setns(orig, unix.CLONE_NEWNET); err != nil {
		e.t.Fatalf("restore netns: %v", err)
	}
	if runErr != nil {
		e.t.Fatalf("nft %s: %v: %s", strings.Join(args, " "), runErr, out)
	}
	return string(out), true
}

func firstDifference(got, want []interval.Interval) string {
	for i := range min(len(got), len(want)) {
		if got[i] != want[i] {
			return fmt.Sprintf("index %d: got %s, want %s", i, got[i], want[i])
		}
	}
	return "length"
}

// hostsV4 returns n non-adjacent single addresses starting at offset*2 within 10.0.0.0/8.
func hostsV4(n, offset int) []interval.Interval {
	result := make([]interval.Interval, 0, n)
	for i := offset; i < offset+n; i++ {
		v := uint32(10)<<24 | uint32(i*2)
		addr := netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
		result = append(result, interval.Interval{From: addr, To: addr})
	}
	return result
}

func parse(t *testing.T, ss ...string) []interval.Interval {
	t.Helper()
	result := make([]interval.Interval, 0, len(ss))
	for _, s := range ss {
		iv, err := interval.Parse(s)
		if err != nil {
			t.Fatalf("Parse(%q): %v", s, err)
		}
		result = append(result, iv)
	}
	interval.Sort(result)
	return result
}

func TestFullLoadDeltaAndRotation(t *testing.T) {
	e := newEnv(t)

	initial := hostsV4(200000, 0)
	started := time.Now()
	res := e.sync(setV4, initial)
	t.Logf("full load of %d intervals: %s, %d transactions", len(initial), time.Since(started), res.Transactions)
	if elapsed := time.Since(started); elapsed > 30*time.Second {
		t.Errorf("full load took %s, want < 30s", elapsed)
	}

	readStarted := time.Now()
	if _, err := e.open(setV4).Read(); err != nil {
		t.Fatalf("Read: %v", err)
	}
	t.Logf("reading %d intervals: %s", len(initial), time.Since(readStarted))

	delta := slices.Clone(initial[1:])
	delta = append(delta, hostsV4(3, 300000)...)
	started = time.Now()
	res = e.sync(setV4, delta)
	t.Logf("delta (+3/-1): %s", time.Since(started))
	if res.Added != 3 || res.Removed != 1 || res.Transactions != 2 {
		t.Errorf("delta added=%d removed=%d transactions=%d, want 3/1/2", res.Added, res.Removed, res.Transactions)
	}

	// Rotation: drop 28k, add 35k.
	rotated := slices.Clone(delta[28000:])
	rotated = append(rotated, hostsV4(35000, 400000)...)
	started = time.Now()
	res = e.sync(setV4, rotated)
	t.Logf("rotation (+%d/-%d): %s", res.Added, res.Removed, time.Since(started))
	if res.Added != 35000 || res.Removed != 28000 {
		t.Errorf("rotation added=%d removed=%d, want 35000/28000", res.Added, res.Removed)
	}
	if elapsed := time.Since(started); elapsed > 30*time.Second {
		t.Errorf("rotation took %s, want < 30s", elapsed)
	}
}

func TestReshaping(t *testing.T) {
	e := newEnv(t)
	e.sync(setV4, parse(t, "10.0.0.1", "10.0.0.2", "10.0.1.5"))

	res := e.sync(setV4, parse(t, "10.0.0.0-10.0.0.3", "10.0.1.0-10.0.1.255"))
	if res.Added != 2 || res.Removed != 3 {
		t.Errorf("reshaping added=%d removed=%d, want 2/3", res.Added, res.Removed)
	}
}

func TestAdjacentAndEdgeIntervals(t *testing.T) {
	e := newEnv(t)
	e.sync(setV4, parse(t, "0.0.0.0", "10.0.0.1", "10.0.0.2", "10.0.0.4-10.0.0.7", "255.255.255.0-255.255.255.255"))
	e.sync(setV4, parse(t, "10.0.0.2", "10.0.0.3", "255.255.255.255"))
	e.sync(setV6, parse(t, "::", "2001:db8::-2001:db8::ff", "2001:db8::100", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"))
	e.sync(setV6, nil)
}

func TestManualChangesAreReverted(t *testing.T) {
	e := newEnv(t)
	desired := parse(t, "10.0.0.1", "10.0.0.5", "10.0.1.0-10.0.1.255")
	e.sync(setV4, desired)

	set := e.open(setV4)
	manual := parse(t, "10.0.0.3-10.0.0.4", "10.0.2.0-10.0.2.17")
	if err := set.Add(manual); err != nil {
		t.Fatalf("manual add: %v", err)
	}
	if err := set.Delete(parse(t, "10.0.0.5")); err != nil {
		t.Fatalf("manual delete: %v", err)
	}

	res := e.sync(setV4, desired)
	if res.Added != 1 || res.Removed != 2 {
		t.Errorf("revert added=%d removed=%d, want 1/2", res.Added, res.Removed)
	}
}

func TestRecreatedSetIsRefilled(t *testing.T) {
	e := newEnv(t)
	desired := hostsV4(1000, 0)
	e.sync(setV4, desired)

	e.deleteSet(setV4)
	e.createSet(setV4, nftables.TypeIPAddr)

	res := e.sync(setV4, desired)
	if res.Added != 1000 {
		t.Errorf("refill added=%d, want 1000", res.Added)
	}
}

func TestMissingSet(t *testing.T) {
	e := newEnv(t)
	_, err := nftset.Open(e.conn, nftables.TableFamilyINet, tableName, "does-not-exist")
	if !errors.Is(err, nftset.ErrNotFound) {
		t.Errorf("missing set: got %v, want ErrNotFound", err)
	}
	_, err = nftset.Open(e.conn, nftables.TableFamilyINet, "no-table", setV4)
	if !errors.Is(err, nftset.ErrNotFound) {
		t.Errorf("missing table: got %v, want ErrNotFound", err)
	}
}

func TestCompatibilityWithNftCLI(t *testing.T) {
	e := newEnv(t)
	if _, ok := e.nft("add", "element", "inet", tableName, setV4,
		"{ 10.0.0.1, 10.0.0.2, 10.0.1.0/24, 255.255.255.255 }"); !ok {
		t.Skip("nft binary not available")
	}

	written := parse(t, "10.0.0.1", "10.0.0.2", "10.0.1.0-10.0.1.255", "255.255.255.255")
	e.assertContent(setV4, written)

	desired := parse(t, "10.0.0.2", "10.0.2.0-10.0.2.127", "255.255.255.255")
	res := e.sync(setV4, desired)
	if res.Added != 1 || res.Removed != 2 {
		t.Errorf("update of CLI-written set added=%d removed=%d, want 1/2", res.Added, res.Removed)
	}

	out, _ := e.nft("list", "set", "inet", tableName, setV4)
	for _, want := range []string{"10.0.0.2", "10.0.2.0/25", "255.255.255.255"} {
		if !strings.Contains(out, want) {
			t.Errorf("nft list set output does not contain %s:\n%s", want, out)
		}
	}
	if strings.Contains(out, "10.0.0.1,") || strings.Contains(out, "10.0.1.0/24") {
		t.Errorf("nft list set output still contains removed elements:\n%s", out)
	}
}

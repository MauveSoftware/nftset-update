package report

import (
	"bytes"
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/MauveSoftware/nftset-update/internal/interval"
	"github.com/MauveSoftware/nftset-update/internal/update"
)

func TestWriteContainsAllFields(t *testing.T) {
	var buf bytes.Buffer
	if err := (&Report{}).Write(&buf); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if !strings.HasSuffix(buf.String(), "\n") {
		t.Errorf("report does not end with newline")
	}

	var fields map[string]any
	if err := json.Unmarshal(buf.Bytes(), &fields); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	for _, key := range []string{
		"table", "set", "afi", "present", "success", "exit_code", "input_intervals",
		"intervals_before", "intervals_after", "added", "removed", "pending_adds",
		"pending_removes", "guard_tripped", "transactions", "read_seconds",
		"apply_seconds", "duration_seconds", "content_hash", "error",
	} {
		if _, found := fields[key]; !found {
			t.Errorf("field %q missing in report", key)
		}
	}
}

func TestSetResult(t *testing.T) {
	state := []interval.Interval{
		{From: mustAddr(t, "10.0.0.1"), To: mustAddr(t, "10.0.0.1")},
		{From: mustAddr(t, "10.0.0.2"), To: mustAddr(t, "10.0.0.2")},
	}
	r := &Report{}
	r.SetResult(update.Result{
		Added: 2, Removed: 1, PendingAdds: 3, PendingRemoves: 4,
		Transactions: 5, GuardTripped: true, State: state,
	})

	if r.Added != 2 || r.Removed != 1 || r.PendingAdds != 3 || r.PendingRemoves != 4 || r.Transactions != 5 {
		t.Errorf("counts not copied: %+v", r)
	}
	if !r.GuardTripped {
		t.Errorf("guard_tripped not copied")
	}
	if r.IntervalsAfter != 2 {
		t.Errorf("intervals_after = %d, want 2", r.IntervalsAfter)
	}
	if r.ContentHash != interval.Hash(state) {
		t.Errorf("content_hash = %d, want %d", r.ContentHash, interval.Hash(state))
	}
}

func TestSeconds(t *testing.T) {
	if got := Seconds(1234567 * time.Microsecond); got != 1.235 {
		t.Errorf("Seconds = %v, want 1.235", got)
	}
}

func mustAddr(t *testing.T, s string) netip.Addr {
	t.Helper()
	addr, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatalf("ParseAddr(%q): %v", s, err)
	}
	return addr
}

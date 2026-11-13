package update

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/MauveSoftware/nftset-update/internal/interval"
)

func ivs(t *testing.T, ss ...string) []interval.Interval {
	t.Helper()
	result := make([]interval.Interval, 0, len(ss))
	for _, s := range ss {
		iv, err := interval.Parse(s)
		if err != nil {
			t.Fatalf("Parse(%q): %v", s, err)
		}
		result = append(result, iv)
	}
	return result
}

// hosts returns n consecutive single-address intervals starting at 10.<base>.0.0.
func hosts(n int, base int) []interval.Interval {
	result := make([]interval.Interval, 0, n)
	for i := range n {
		iv, _ := interval.Parse(fmt.Sprintf("10.%d.%d.%d", base, i/256, i%256))
		result = append(result, iv)
	}
	return result
}

type call struct {
	op  string
	ivs []interval.Interval
}

type fakeTarget struct {
	calls  []call
	failAt int // 1-based transaction number that fails, 0 = never
}

func (f *fakeTarget) record(op string, list []interval.Interval) error {
	f.calls = append(f.calls, call{op: op, ivs: slices.Clone(list)})
	if f.failAt == len(f.calls) {
		return errors.New("transaction rejected")
	}
	return nil
}

func (f *fakeTarget) Add(list []interval.Interval) error    { return f.record("add", list) }
func (f *fakeTarget) Delete(list []interval.Interval) error { return f.record("delete", list) }

func (f *fakeTarget) ops() string {
	ops := make([]string, 0, len(f.calls))
	for _, c := range f.calls {
		ops = append(ops, fmt.Sprintf("%s(%d)", c.op, len(c.ivs)))
	}
	return strings.Join(ops, " ")
}

var defaultConfig = Config{BatchSize: 10000, MaxRemoveFraction: 0.5, GuardMinElements: 1000}

func TestNewPlanOrdering(t *testing.T) {
	current := ivs(t, "10.0.0.1", "10.0.0.2", "10.0.1.5")
	desired := ivs(t, "10.0.0.1", "10.0.1.0-10.0.1.255", "10.0.2.1")

	plan := NewPlan(desired, current, defaultConfig)

	if want := ivs(t, "10.0.2.1"); !slices.Equal(plan.Early, want) {
		t.Errorf("Early = %v, want %v (adds not overlapping removes)", plan.Early, want)
	}
	if want := ivs(t, "10.0.0.2", "10.0.1.5"); !slices.Equal(plan.Removes, want) {
		t.Errorf("Removes = %v, want %v", plan.Removes, want)
	}
	if want := ivs(t, "10.0.1.0-10.0.1.255"); !slices.Equal(plan.Late, want) {
		t.Errorf("Late = %v, want %v (adds overlapping removes)", plan.Late, want)
	}
	if plan.GuardTripped {
		t.Errorf("guard tripped unexpectedly: %s", plan.GuardReason)
	}
}

func TestNewPlanAdjacentAddIsEarly(t *testing.T) {
	plan := NewPlan(ivs(t, "10.0.0.2"), ivs(t, "10.0.0.1"), defaultConfig)
	if want := ivs(t, "10.0.0.2"); !slices.Equal(plan.Early, want) {
		t.Errorf("Early = %v, want %v (adjacent is not overlapping)", plan.Early, want)
	}
}

func TestNewPlanGuard(t *testing.T) {
	tests := []struct {
		name        string
		desired     []interval.Interval
		current     []interval.Interval
		cfg         Config
		wantTripped bool
	}{
		{
			name:    "initial load",
			desired: hosts(5000, 0),
			current: nil,
			cfg:     defaultConfig,
		},
		{
			name:        "more than half removed",
			desired:     hosts(900, 0),
			current:     hosts(2000, 0),
			cfg:         defaultConfig,
			wantTripped: true,
		},
		{
			name:    "exactly half removed",
			desired: hosts(1000, 0),
			current: hosts(2000, 0),
			cfg:     defaultConfig,
		},
		{
			name:    "small set below guard minimum",
			desired: hosts(10, 0),
			current: hosts(1000, 0),
			cfg:     defaultConfig,
		},
		{
			name:    "fraction 1 disables the fraction check",
			desired: hosts(1, 0),
			current: hosts(2000, 0),
			cfg:     Config{BatchSize: 10000, MaxRemoveFraction: 1, GuardMinElements: 1000},
		},
		{
			name:        "empty input on small set",
			desired:     nil,
			current:     hosts(3, 0),
			cfg:         defaultConfig,
			wantTripped: true,
		},
		{
			name:        "empty input with fraction check disabled",
			desired:     nil,
			current:     hosts(3, 0),
			cfg:         Config{BatchSize: 10000, MaxRemoveFraction: 1, GuardMinElements: 1000},
			wantTripped: true,
		},
		{
			name:    "empty input allowed",
			desired: nil,
			current: hosts(3, 0),
			cfg:     Config{BatchSize: 10000, MaxRemoveFraction: 0.5, GuardMinElements: 1000, AllowEmpty: true},
		},
		{
			name:    "empty input on empty set",
			desired: nil,
			current: nil,
			cfg:     defaultConfig,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			plan := NewPlan(tt.desired, tt.current, tt.cfg)
			if plan.GuardTripped != tt.wantTripped {
				t.Errorf("GuardTripped = %v, want %v (reason %q)", plan.GuardTripped, tt.wantTripped, plan.GuardReason)
			}
			if plan.GuardTripped && plan.GuardReason == "" {
				t.Errorf("guard tripped without reason")
			}
		})
	}
}

func TestApplyOrderAndBatching(t *testing.T) {
	current := append(hosts(5, 1), ivs(t, "10.9.0.5")...)
	desired := append(hosts(25, 0), ivs(t, "10.9.0.0-10.9.0.255")...)
	cfg := Config{BatchSize: 10, MaxRemoveFraction: 1, GuardMinElements: 1000}
	plan := NewPlan(desired, current, cfg)
	target := &fakeTarget{}

	res, err := Apply(context.Background(), target, current, plan, cfg.BatchSize)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if want := "add(10) add(10) add(5) delete(6) add(1)"; target.ops() != want {
		t.Errorf("transactions = %s, want %s", target.ops(), want)
	}
	if res.Added != 26 || res.Removed != 6 || res.Transactions != 5 {
		t.Errorf("result added=%d removed=%d transactions=%d, want 26/6/5", res.Added, res.Removed, res.Transactions)
	}
	if res.PendingAdds != 0 || res.PendingRemoves != 0 {
		t.Errorf("pending adds=%d removes=%d, want 0/0", res.PendingAdds, res.PendingRemoves)
	}
	if !slices.Equal(res.State, desired) {
		t.Errorf("state after apply differs from desired")
	}
}

func TestApplyGuardTrippedAppliesOnlyEarlyAdds(t *testing.T) {
	current := hosts(2000, 1)
	desired := append(hosts(3, 0), ivs(t, "10.1.0.0-10.1.0.255")...)
	plan := NewPlan(desired, current, defaultConfig)
	if !plan.GuardTripped {
		t.Fatalf("guard expected to trip")
	}
	target := &fakeTarget{}

	res, err := Apply(context.Background(), target, current, plan, defaultConfig.BatchSize)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if want := "add(3)"; target.ops() != want {
		t.Errorf("transactions = %s, want %s", target.ops(), want)
	}
	if !res.GuardTripped || res.Added != 3 || res.Removed != 0 {
		t.Errorf("result guard=%v added=%d removed=%d, want true/3/0", res.GuardTripped, res.Added, res.Removed)
	}
	if res.PendingRemoves != 2000 || res.PendingAdds != 1 {
		t.Errorf("pending removes=%d adds=%d, want 2000/1", res.PendingRemoves, res.PendingAdds)
	}
	if len(res.State) != 2003 {
		t.Errorf("state has %d intervals, want 2003", len(res.State))
	}
}

func TestApplyStopsOnTransactionError(t *testing.T) {
	current := hosts(3, 1)
	desired := hosts(25, 0)
	cfg := Config{BatchSize: 10, MaxRemoveFraction: 1, GuardMinElements: 1000}
	plan := NewPlan(desired, current, cfg)
	target := &fakeTarget{failAt: 2}

	res, err := Apply(context.Background(), target, current, plan, cfg.BatchSize)

	var txErr *TransactionError
	if !errors.As(err, &txErr) {
		t.Fatalf("expected TransactionError, got %v", err)
	}
	if txErr.Phase != PhaseAdd || txErr.Batch != 2 || txErr.First.String() != "10.0.0.10" || txErr.Last.String() != "10.0.0.19" {
		t.Errorf("error context = %+v", txErr)
	}
	if target.ops() != "add(10) add(10)" {
		t.Errorf("transactions = %s, want add(10) add(10)", target.ops())
	}
	if res.Added != 10 || res.PendingAdds != 15 || res.PendingRemoves != 3 || res.Transactions != 1 {
		t.Errorf("result added=%d pendingAdds=%d pendingRemoves=%d tx=%d, want 10/15/3/1",
			res.Added, res.PendingAdds, res.PendingRemoves, res.Transactions)
	}
	if len(res.State) != 13 {
		t.Errorf("state has %d intervals, want 13 (3 current + 10 committed)", len(res.State))
	}
}

func TestApplyStopsWhenContextCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	plan := NewPlan(hosts(5, 0), nil, defaultConfig)
	target := &fakeTarget{}

	res, err := Apply(ctx, target, nil, plan, defaultConfig.BatchSize)

	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled, got %v", err)
	}
	if len(target.calls) != 0 || res.PendingAdds != 5 {
		t.Errorf("calls=%d pendingAdds=%d, want 0/5", len(target.calls), res.PendingAdds)
	}
}

func TestApplyNoChanges(t *testing.T) {
	current := hosts(3, 0)
	plan := NewPlan(current, current, defaultConfig)
	target := &fakeTarget{}

	res, err := Apply(context.Background(), target, current, plan, defaultConfig.BatchSize)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(target.calls) != 0 || res.Transactions != 0 {
		t.Errorf("expected no transactions, got %s", target.ops())
	}
}

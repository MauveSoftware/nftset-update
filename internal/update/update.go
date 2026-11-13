// Package update plans and applies the changes that make a set equal to the
// desired intervals: new bans first, then removals, then the adds that
// overlap removed intervals.
package update

import (
	"context"
	"errors"
	"fmt"
	"sort"

	"github.com/MauveSoftware/nftset-update/internal/interval"
)

// Phase names the step of an update.
type Phase string

const (
	// PhaseAdd adds intervals not overlapping any removed interval.
	PhaseAdd Phase = "add"
	// PhaseRemove removes intervals no longer desired.
	PhaseRemove Phase = "remove"
	// PhaseAddAfterRemove adds intervals overlapping a removed interval.
	PhaseAddAfterRemove Phase = "add-after-remove"
)

// Target applies one atomic transaction per call.
type Target interface {
	Add(ivs []interval.Interval) error
	Delete(ivs []interval.Interval) error
}

// ErrInvalidBatchSize is returned by Apply if the plan's batch size is below 1.
var ErrInvalidBatchSize = errors.New("batch size must be at least 1")

// Config controls batching and the mass-removal guard.
type Config struct {
	BatchSize         int
	MaxRemoveFraction float64
	GuardMinElements  int
	AllowEmpty        bool
}

// Plan lists the changes per phase. If GuardTripped is set, only Early is
// applied. BatchSize is the maximum number of intervals per transaction.
type Plan struct {
	Early        []interval.Interval
	Removes      []interval.Interval
	Late         []interval.Interval
	BatchSize    int
	GuardTripped bool
	GuardReason  string
}

// NewPlan computes the changes from current to desired and evaluates the
// mass-removal guard.
func NewPlan(desired, current []interval.Interval, cfg Config) Plan {
	adds, removes := interval.Diff(desired, current)
	plan := Plan{Removes: removes, BatchSize: cfg.BatchSize}
	for _, add := range adds {
		if overlapsAny(add, removes) {
			plan.Late = append(plan.Late, add)
		} else {
			plan.Early = append(plan.Early, add)
		}
	}

	switch {
	case len(desired) == 0 && len(current) > 0 && !cfg.AllowEmpty:
		plan.GuardTripped = true
		plan.GuardReason = fmt.Sprintf("empty input would remove all %d intervals", len(current))
	case len(current) > cfg.GuardMinElements &&
		float64(len(removes))/float64(len(current)) > cfg.MaxRemoveFraction:
		plan.GuardTripped = true
		plan.GuardReason = fmt.Sprintf("%d of %d intervals would be removed (max fraction %g)",
			len(removes), len(current), cfg.MaxRemoveFraction)
	}
	return plan
}

// overlapsAny reports whether iv overlaps an interval of the sorted,
// non-overlapping list.
func overlapsAny(iv interval.Interval, sorted []interval.Interval) bool {
	// First interval ending at or after iv.From; only it can overlap.
	i := sort.Search(len(sorted), func(i int) bool {
		return sorted[i].To.Compare(iv.From) >= 0
	})
	return i < len(sorted) && sorted[i].Overlaps(iv)
}

// Result describes what was committed.
type Result struct {
	Added          int
	Removed        int
	PendingAdds    int
	PendingRemoves int
	Transactions   int
	GuardTripped   bool
	// State is the set content after all committed transactions.
	State []interval.Interval
}

// TransactionError describes a failed transaction.
type TransactionError struct {
	Phase Phase
	Batch int
	First interval.Interval
	Last  interval.Interval
	Err   error
}

func (e *TransactionError) Error() string {
	return fmt.Sprintf("phase %s, batch %d (%s .. %s): %v", e.Phase, e.Batch, e.First, e.Last, e.Err)
}

func (e *TransactionError) Unwrap() error {
	return e.Err
}

// Apply executes the plan in batches of at most plan.BatchSize intervals per
// transaction. It stops at the first failed transaction or when ctx is
// cancelled; the result then reflects the committed transactions only.
func Apply(ctx context.Context, target Target, current []interval.Interval, plan Plan) (Result, error) {
	a := applier{ctx: ctx, target: target, batchSize: plan.BatchSize}
	res := Result{GuardTripped: plan.GuardTripped}

	err := a.run(PhaseAdd, plan.Early, target.Add)
	if err == nil && !plan.GuardTripped {
		err = a.run(PhaseRemove, plan.Removes, target.Delete)
		if err == nil {
			err = a.run(PhaseAddAfterRemove, plan.Late, target.Add)
		}
	}

	res.Added = len(a.added)
	res.Removed = len(a.removed)
	res.PendingAdds = len(plan.Early) + len(plan.Late) - res.Added
	res.PendingRemoves = len(plan.Removes) - res.Removed
	res.Transactions = a.transactions
	res.State = interval.Apply(current, a.added, a.removed)
	return res, err
}

type applier struct {
	ctx          context.Context
	target       Target
	batchSize    int
	transactions int
	added        []interval.Interval
	removed      []interval.Interval
}

func (a *applier) run(phase Phase, ivs []interval.Interval, transaction func([]interval.Interval) error) error {
	// Checked here rather than once in Apply so every phase is covered; a
	// batch size below 1 would never advance the loop.
	if a.batchSize < 1 {
		return fmt.Errorf("%w, got %d", ErrInvalidBatchSize, a.batchSize)
	}
	for batch, start := 1, 0; start < len(ivs); batch, start = batch+1, start+a.batchSize {
		if err := a.ctx.Err(); err != nil {
			return err
		}
		chunk := ivs[start:min(start+a.batchSize, len(ivs))]
		if err := transaction(chunk); err != nil {
			return &TransactionError{Phase: phase, Batch: batch, First: chunk[0], Last: chunk[len(chunk)-1], Err: err}
		}
		a.transactions++
		if phase == PhaseRemove {
			a.removed = append(a.removed, chunk...)
		} else {
			a.added = append(a.added, chunk...)
		}
	}
	return nil
}

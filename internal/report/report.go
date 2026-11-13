// Package report defines the JSON result written to stdout, which callers use
// to produce metrics.
package report

import (
	"encoding/json"
	"io"
	"math"
	"time"

	"github.com/MauveSoftware/nftset-update/internal/interval"
	"github.com/MauveSoftware/nftset-update/internal/update"
)

// Report is the machine-readable result of a run. Fields unknown at the time
// of a failure keep their zero value.
type Report struct {
	Table           string  `json:"table"`
	Set             string  `json:"set"`
	AFI             string  `json:"afi"`
	Present         bool    `json:"present"`
	Success         bool    `json:"success"`
	ExitCode        int     `json:"exit_code"`
	InputIntervals  int     `json:"input_intervals"`
	IntervalsBefore int     `json:"intervals_before"`
	IntervalsAfter  int     `json:"intervals_after"`
	Added           int     `json:"added"`
	Removed         int     `json:"removed"`
	PendingAdds     int     `json:"pending_adds"`
	PendingRemoves  int     `json:"pending_removes"`
	GuardTripped    bool    `json:"guard_tripped"`
	Transactions    int     `json:"transactions"`
	ReadSeconds     float64 `json:"read_seconds"`
	ApplySeconds    float64 `json:"apply_seconds"`
	DurationSeconds float64 `json:"duration_seconds"`
	// ContentHash is interval.Hash of the committed set content.
	ContentHash uint32 `json:"content_hash"`
	Error       string `json:"error"`
}

// SetResult copies the outcome of an update into the report.
func (r *Report) SetResult(res update.Result) {
	r.Added = res.Added
	r.Removed = res.Removed
	r.PendingAdds = res.PendingAdds
	r.PendingRemoves = res.PendingRemoves
	r.Transactions = res.Transactions
	r.GuardTripped = res.GuardTripped
	r.IntervalsAfter = len(res.State)
	r.ContentHash = interval.Hash(res.State)
}

// Write writes the report as one JSON line.
func (r *Report) Write(w io.Writer) error {
	return json.NewEncoder(w).Encode(r)
}

// Seconds converts a duration to seconds rounded to milliseconds.
func Seconds(d time.Duration) float64 {
	return math.Round(d.Seconds()*1000) / 1000
}

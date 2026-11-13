// Command nftset-update makes the elements of an existing nftables interval
// set equal to a list of addresses and prefixes. Logs go to stderr, a JSON
// report goes to stdout.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/google/nftables"

	"github.com/MauveSoftware/nftset-update/internal/interval"
	"github.com/MauveSoftware/nftset-update/internal/nftset"
	"github.com/MauveSoftware/nftset-update/internal/prefixlist"
	"github.com/MauveSoftware/nftset-update/internal/report"
	"github.com/MauveSoftware/nftset-update/internal/update"
)

var version = "dev"

// Exit codes, see spec §6.
const (
	exitOK           = 0
	exitApplyError   = 1
	exitInputError   = 2
	exitGuardTripped = 3
	exitSetMissing   = 4
)

const maxBatchSize = 100000

var tableFamilies = map[string]nftables.TableFamily{
	"inet": nftables.TableFamilyINet,
	"ip":   nftables.TableFamilyIPv4,
	"ip6":  nftables.TableFamilyIPv6,
}

type config struct {
	set        string
	input      string
	table      string
	familyName string
	family     nftables.TableFamily
	debug      bool
	update     update.Config
}

func main() {
	cfg, err := parseConfig(os.Args[1:], os.Stderr)
	if errors.Is(err, flag.ErrHelp) {
		os.Exit(exitOK)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "nftset-update: %v\n", err)
		os.Exit(exitInputError)
	}

	level := slog.LevelInfo
	if cfg.debug {
		level = slog.LevelDebug
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	os.Exit(run(ctx, cfg, os.Stdout, logger))
}

func parseConfig(args []string, output io.Writer) (config, error) {
	cfg := config{}
	fs := flag.NewFlagSet("nftset-update", flag.ContinueOnError)
	fs.SetOutput(output)
	fs.StringVar(&cfg.set, "set", "", "name of the set (required)")
	fs.StringVar(&cfg.input, "input", "", "path of the prefix list (required)")
	fs.StringVar(&cfg.table, "table", "filter", "table name")
	fs.StringVar(&cfg.familyName, "table-family", "inet", "table family: inet, ip or ip6")
	fs.IntVar(&cfg.update.BatchSize, "batch-size", 10000, "max. intervals per netlink transaction")
	fs.Float64Var(&cfg.update.MaxRemoveFraction, "max-remove-fraction", 0.5, "mass-removal guard; 1 disables the fraction check")
	fs.IntVar(&cfg.update.GuardMinElements, "guard-min-elements", 1000, "guard only applies above this set size")
	fs.BoolVar(&cfg.update.AllowEmpty, "allow-empty", false, "allow an empty input to clear a non-empty set")
	fs.BoolVar(&cfg.debug, "debug", false, "log at DEBUG level")
	showVersion := fs.Bool("version", false, "print version and exit")

	if err := fs.Parse(args); err != nil {
		return cfg, err
	}
	if *showVersion {
		if _, err := fmt.Fprintln(output, version); err != nil {
			return cfg, err
		}
		return cfg, flag.ErrHelp
	}

	var found bool
	cfg.family, found = tableFamilies[cfg.familyName]
	switch {
	case fs.NArg() > 0:
		return cfg, fmt.Errorf("unexpected argument %q", fs.Arg(0))
	case cfg.set == "":
		return cfg, errors.New("-set is required")
	case cfg.input == "":
		return cfg, errors.New("-input is required")
	case !found:
		return cfg, fmt.Errorf("-table-family: unsupported family %q", cfg.familyName)
	case cfg.update.BatchSize < 1 || cfg.update.BatchSize > maxBatchSize:
		return cfg, fmt.Errorf("-batch-size must be between 1 and %d", maxBatchSize)
	case cfg.update.MaxRemoveFraction < 0 || cfg.update.MaxRemoveFraction > 1:
		return cfg, errors.New("-max-remove-fraction must be between 0 and 1")
	case cfg.update.GuardMinElements < 0:
		return cfg, errors.New("-guard-min-elements must not be negative")
	}
	return cfg, nil
}

// run executes the update and always writes the report to stdout.
func run(ctx context.Context, cfg config, stdout io.Writer, logger *slog.Logger) int {
	started := time.Now()
	rep := &report.Report{Table: cfg.familyName + " " + cfg.table, Set: cfg.set}
	logger = logger.With("table", rep.Table, "set", cfg.set)

	code, err := execute(ctx, cfg, rep, logger)
	if err != nil {
		rep.Error = err.Error()
		if code == exitGuardTripped {
			logger.Warn("mass-removal guard tripped, removals skipped", "reason", err)
		} else {
			logger.Error("update failed", "error", err)
		}
	}

	rep.ExitCode = code
	rep.Success = code == exitOK
	rep.DurationSeconds = report.Seconds(time.Since(started))
	if err := rep.Write(stdout); err != nil {
		logger.Error("writing report failed", "error", err)
	}
	return code
}

func execute(ctx context.Context, cfg config, rep *report.Report, logger *slog.Logger) (int, error) {
	conn, err := nftset.Dial(0)
	if err != nil {
		return exitApplyError, fmt.Errorf("opening netlink connection: %w", err)
	}
	defer func() { _ = conn.CloseLasting() }()

	set, err := nftset.Open(conn, cfg.family, cfg.table, cfg.set)
	if errors.Is(err, nftset.ErrNotFound) {
		return exitSetMissing, err
	}
	if err != nil {
		return exitApplyError, err
	}
	rep.Present = true
	rep.AFI = "v4"
	if set.Is6() {
		rep.AFI = "v6"
	}

	desired, err := readInput(cfg.input, set.Is6())
	if err != nil {
		return exitInputError, err
	}
	rep.InputIntervals = len(desired)

	readStarted := time.Now()
	current, err := set.Read()
	if err != nil {
		return exitApplyError, err
	}
	rep.ReadSeconds = report.Seconds(time.Since(readStarted))
	rep.IntervalsBefore = len(current)
	rep.SetResult(update.Result{State: current})

	plan := update.NewPlan(desired, current, cfg.update)
	applyStarted := time.Now()
	res, err := update.Apply(ctx, set, current, plan, cfg.update.BatchSize)
	rep.ApplySeconds = report.Seconds(time.Since(applyStarted))
	rep.SetResult(res)
	if err != nil {
		return exitApplyError, err
	}

	logChanges(logger, rep)
	if plan.GuardTripped {
		return exitGuardTripped, errors.New(plan.GuardReason)
	}
	return exitOK, nil
}

func readInput(path string, is6 bool) ([]interval.Interval, error) {
	f, err := os.Open(path) // #nosec G304 -- path is the operator-supplied -input flag
	if err != nil {
		return nil, err
	}
	// Read-only file: a close error cannot lose data.
	defer func() { _ = f.Close() }()

	desired, err := prefixlist.Parse(f, is6)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return desired, nil
}

func logChanges(logger *slog.Logger, rep *report.Report) {
	level := slog.LevelInfo
	if rep.Added == 0 && rep.Removed == 0 {
		level = slog.LevelDebug
	}
	logger.Log(context.Background(), level, "set updated",
		"added", rep.Added,
		"removed", rep.Removed,
		"intervals", rep.IntervalsAfter,
		"transactions", rep.Transactions,
		"read_seconds", rep.ReadSeconds,
		"apply_seconds", rep.ApplySeconds)
}

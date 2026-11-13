package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/nftables"

	"github.com/MauveSoftware/nftset-update/internal/interval"
	"github.com/MauveSoftware/nftset-update/internal/nftset"
	"github.com/MauveSoftware/nftset-update/internal/report"
	"github.com/MauveSoftware/nftset-update/internal/update"
)

func TestParseConfigDefaults(t *testing.T) {
	cfg, err := parseConfig([]string{"-set", "blocklist-v4", "-input", "/tmp/list"}, io.Discard)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.table != "filter" || cfg.family != nftables.TableFamilyINet || cfg.familyName != "inet" {
		t.Errorf("table defaults = %q/%v/%q, want filter/inet", cfg.table, cfg.family, cfg.familyName)
	}
	if cfg.update.BatchSize != 10000 || cfg.update.MaxRemoveFraction != 0.5 ||
		cfg.update.GuardMinElements != 1000 || cfg.update.AllowEmpty {
		t.Errorf("update defaults = %+v", cfg.update)
	}
}

func TestParseConfigFamilies(t *testing.T) {
	for name, want := range map[string]nftables.TableFamily{
		"inet": nftables.TableFamilyINet,
		"ip":   nftables.TableFamilyIPv4,
		"ip6":  nftables.TableFamilyIPv6,
	} {
		cfg, err := parseConfig([]string{"-set", "s", "-input", "f", "-table-family", name}, io.Discard)
		if err != nil {
			t.Errorf("family %s: unexpected error: %v", name, err)
			continue
		}
		if cfg.family != want {
			t.Errorf("family %s parsed as %v, want %v", name, cfg.family, want)
		}
	}
}

func TestParseConfigInvalid(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		wantErr string
	}{
		{"missing set", []string{"-input", "f"}, "-set"},
		{"missing input", []string{"-set", "s"}, "-input"},
		{"unknown family", []string{"-set", "s", "-input", "f", "-table-family", "arp"}, "table-family"},
		{"batch size zero", []string{"-set", "s", "-input", "f", "-batch-size", "0"}, "batch-size"},
		{"batch size too large", []string{"-set", "s", "-input", "f", "-batch-size", "100001"}, "batch-size"},
		{"fraction above 1", []string{"-set", "s", "-input", "f", "-max-remove-fraction", "1.5"}, "max-remove-fraction"},
		{"negative fraction", []string{"-set", "s", "-input", "f", "-max-remove-fraction", "-0.1"}, "max-remove-fraction"},
		{"negative guard minimum", []string{"-set", "s", "-input", "f", "-guard-min-elements", "-1"}, "guard-min-elements"},
		{"positional argument", []string{"-set", "s", "-input", "f", "extra"}, "argument"},
		{"unknown flag", []string{"-foo"}, "foo"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseConfig(tt.args, io.Discard)
			if err == nil {
				t.Fatalf("expected error containing %q, got none", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error %q does not contain %q", err, tt.wantErr)
			}
		})
	}
}

type fakeSet struct {
	is6      bool
	current  []interval.Interval
	readErr  error
	applyErr error
	closed   bool
}

func (f *fakeSet) Is6() bool                            { return f.is6 }
func (f *fakeSet) Read() ([]interval.Interval, error)   { return f.current, f.readErr }
func (f *fakeSet) Add(ivs []interval.Interval) error    { return f.applyErr }
func (f *fakeSet) Delete(ivs []interval.Interval) error { return f.applyErr }

func mustParse(t *testing.T, s string) interval.Interval {
	t.Helper()
	iv, err := interval.Parse(s)
	if err != nil {
		t.Fatalf("Parse(%q): %v", s, err)
	}
	return iv
}

func TestRunExitCodesAndReport(t *testing.T) {
	notFound := fmt.Errorf("%w: filter blocklist", nftset.ErrNotFound)
	tests := []struct {
		name        string
		set         *fakeSet // nil: opening fails with openErr
		openErr     error
		input       *string // nil: input file does not exist
		wantCode    int
		wantPresent bool
		wantAFI     string
		wantAdded   int
		wantRemoved int
		wantGuard   bool
		wantErr     string
	}{
		{
			name:        "success",
			set:         &fakeSet{current: []interval.Interval{mustParse(t, "10.0.0.1")}},
			input:       new("10.0.0.2\n"),
			wantCode:    exitOK,
			wantPresent: true,
			wantAFI:     "v4",
			wantAdded:   1,
			wantRemoved: 1,
		},
		{
			name:     "set missing",
			openErr:  notFound,
			input:    new("10.0.0.2\n"),
			wantCode: exitSetMissing,
			wantErr:  "not found",
		},
		{
			name:     "open fails",
			openErr:  errors.New("netlink down"),
			input:    new("10.0.0.2\n"),
			wantCode: exitApplyError,
			wantErr:  "netlink down",
		},
		{
			name:        "invalid input",
			set:         &fakeSet{},
			input:       new("not-an-address\n"),
			wantCode:    exitInputError,
			wantPresent: true,
			wantAFI:     "v4",
			wantErr:     "line 1",
		},
		{
			name:        "input family mismatch",
			set:         &fakeSet{is6: true},
			input:       new("10.0.0.2\n"),
			wantCode:    exitInputError,
			wantPresent: true,
			wantAFI:     "v6",
			wantErr:     "address family",
		},
		{
			name:        "input file missing",
			set:         &fakeSet{},
			wantCode:    exitInputError,
			wantPresent: true,
			wantAFI:     "v4",
			wantErr:     "no such file",
		},
		{
			name:        "read fails",
			set:         &fakeSet{readErr: errors.New("dump failed")},
			input:       new("10.0.0.2\n"),
			wantCode:    exitApplyError,
			wantPresent: true,
			wantAFI:     "v4",
			wantErr:     "dump failed",
		},
		{
			name:        "transaction fails",
			set:         &fakeSet{applyErr: errors.New("transaction rejected")},
			input:       new("10.0.0.2\n"),
			wantCode:    exitApplyError,
			wantPresent: true,
			wantAFI:     "v4",
			wantErr:     "transaction rejected",
		},
		{
			name:        "guard tripped by empty input",
			set:         &fakeSet{current: []interval.Interval{mustParse(t, "10.0.0.1")}},
			input:       new("# nothing\n"),
			wantCode:    exitGuardTripped,
			wantPresent: true,
			wantAFI:     "v4",
			wantGuard:   true,
			wantErr:     "empty input",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := testConfig(t, tt.input)
			open := func(family nftables.TableFamily, table, name string) (targetSet, func(), error) {
				if family != cfg.family || table != cfg.table || name != cfg.set {
					t.Errorf("opened %v %s %s, want %v %s %s", family, table, name, cfg.family, cfg.table, cfg.set)
				}
				if tt.set == nil {
					return nil, nil, tt.openErr
				}
				return tt.set, func() { tt.set.closed = true }, nil
			}
			var stdout bytes.Buffer
			logger := slog.New(slog.NewTextHandler(io.Discard, nil))

			code := run(context.Background(), cfg, open, &stdout, logger)

			var rep report.Report
			if err := json.Unmarshal(stdout.Bytes(), &rep); err != nil {
				t.Fatalf("report is not valid JSON: %v\n%s", err, stdout.String())
			}
			if code != tt.wantCode || rep.ExitCode != tt.wantCode {
				t.Errorf("exit code = %d, report exit_code = %d, want %d", code, rep.ExitCode, tt.wantCode)
			}
			if rep.Success != (tt.wantCode == exitOK) {
				t.Errorf("report success = %v for exit code %d", rep.Success, tt.wantCode)
			}
			if rep.Present != tt.wantPresent || rep.AFI != tt.wantAFI {
				t.Errorf("report present/afi = %v/%q, want %v/%q", rep.Present, rep.AFI, tt.wantPresent, tt.wantAFI)
			}
			if rep.Added != tt.wantAdded || rep.Removed != tt.wantRemoved || rep.GuardTripped != tt.wantGuard {
				t.Errorf("report added/removed/guard = %d/%d/%v, want %d/%d/%v",
					rep.Added, rep.Removed, rep.GuardTripped, tt.wantAdded, tt.wantRemoved, tt.wantGuard)
			}
			if tt.wantErr == "" && rep.Error != "" {
				t.Errorf("unexpected report error %q", rep.Error)
			}
			if !strings.Contains(rep.Error, tt.wantErr) {
				t.Errorf("report error %q does not contain %q", rep.Error, tt.wantErr)
			}
			if rep.Table != "inet filter" || rep.Set != "blocklist" {
				t.Errorf("report table/set = %q/%q, want \"inet filter\"/\"blocklist\"", rep.Table, rep.Set)
			}
			if tt.set != nil && !tt.set.closed {
				t.Errorf("set connection was not closed")
			}
		})
	}
}

func testConfig(t *testing.T, input *string) config {
	t.Helper()
	path := filepath.Join(t.TempDir(), "list")
	if input != nil {
		if err := os.WriteFile(path, []byte(*input), 0o600); err != nil {
			t.Fatalf("writing input: %v", err)
		}
	}
	return config{
		set:        "blocklist",
		input:      path,
		table:      "filter",
		familyName: "inet",
		family:     nftables.TableFamilyINet,
		update:     update.Config{BatchSize: 10, MaxRemoveFraction: 1},
	}
}

func TestRunReportsCommittedState(t *testing.T) {
	set := &fakeSet{current: []interval.Interval{mustParse(t, "10.0.0.1"), mustParse(t, "10.0.0.3")}}
	cfg := testConfig(t, new("10.0.0.2\n10.0.0.3\n"))
	open := func(nftables.TableFamily, string, string) (targetSet, func(), error) {
		return set, func() {}, nil
	}
	var stdout bytes.Buffer

	if code := run(context.Background(), cfg, open, &stdout, slog.New(slog.NewTextHandler(io.Discard, nil))); code != exitOK {
		t.Fatalf("exit code = %d, want %d\n%s", code, exitOK, stdout.String())
	}

	var rep report.Report
	if err := json.Unmarshal(stdout.Bytes(), &rep); err != nil {
		t.Fatalf("report is not valid JSON: %v", err)
	}
	want := []interval.Interval{mustParse(t, "10.0.0.2"), mustParse(t, "10.0.0.3")}
	if rep.IntervalsBefore != 2 || rep.IntervalsAfter != 2 || rep.InputIntervals != 2 {
		t.Errorf("report intervals before/after/input = %d/%d/%d, want 2/2/2",
			rep.IntervalsBefore, rep.IntervalsAfter, rep.InputIntervals)
	}
	if rep.ContentHash != interval.Hash(want) {
		t.Errorf("report content_hash = %d, want hash of committed state %d", rep.ContentHash, interval.Hash(want))
	}
}

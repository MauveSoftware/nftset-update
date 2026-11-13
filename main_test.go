package main

import (
	"io"
	"strings"
	"testing"

	"github.com/google/nftables"
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

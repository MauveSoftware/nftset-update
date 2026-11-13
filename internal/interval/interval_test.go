package interval

import (
	"net/netip"
	"slices"
	"testing"
)

func mustParse(t *testing.T, s string) Interval {
	t.Helper()
	iv, err := Parse(s)
	if err != nil {
		t.Fatalf("Parse(%q): %v", s, err)
	}
	return iv
}

func mustParseAll(t *testing.T, ss ...string) []Interval {
	t.Helper()
	ivs := make([]Interval, 0, len(ss))
	for _, s := range ss {
		ivs = append(ivs, mustParse(t, s))
	}
	return ivs
}

func TestFromPrefix(t *testing.T) {
	tests := []struct {
		prefix string
		want   string
	}{
		{"10.0.0.1/32", "10.0.0.1"},
		{"10.0.0.0/24", "10.0.0.0-10.0.0.255"},
		{"0.0.0.0/0", "0.0.0.0-255.255.255.255"},
		{"2001:db8::/126", "2001:db8::-2001:db8::3"},
		{"ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"},
	}
	for _, tt := range tests {
		got := FromPrefix(netip.MustParsePrefix(tt.prefix)).String()
		if got != tt.want {
			t.Errorf("FromPrefix(%s) = %s, want %s", tt.prefix, got, tt.want)
		}
	}
}

func TestParseRejectsInvalid(t *testing.T) {
	for _, s := range []string{"", "x", "10.0.0.2-10.0.0.1", "10.0.0.1-::1", "10.0.0.1-", "fe80::1%eth0", "fe80::1-fe80::2%eth0"} {
		if _, err := Parse(s); err == nil {
			t.Errorf("Parse(%q) succeeded, want error", s)
		}
	}
}

func TestOverlaps(t *testing.T) {
	tests := []struct {
		a, b string
		want bool
	}{
		{"10.0.0.0-10.0.0.9", "10.0.0.9-10.0.0.20", true},
		{"10.0.0.0-10.0.0.9", "10.0.0.10-10.0.0.20", false},
		{"10.0.0.5", "10.0.0.0-10.0.0.255", true},
		{"10.0.0.0-10.0.0.255", "10.0.0.5", true},
		{"10.0.0.5", "10.0.0.6", false},
	}
	for _, tt := range tests {
		a, b := mustParse(t, tt.a), mustParse(t, tt.b)
		if got := a.Overlaps(b); got != tt.want {
			t.Errorf("%s.Overlaps(%s) = %v, want %v", tt.a, tt.b, got, tt.want)
		}
	}
}

func TestDiff(t *testing.T) {
	desired := mustParseAll(t, "10.0.0.1", "10.0.0.2", "10.1.0.0-10.1.0.255")
	current := mustParseAll(t, "10.0.0.2", "10.0.0.3", "10.1.0.0-10.1.0.127")

	adds, removes := Diff(desired, current)

	wantAdds := mustParseAll(t, "10.0.0.1", "10.1.0.0-10.1.0.255")
	wantRemoves := mustParseAll(t, "10.0.0.3", "10.1.0.0-10.1.0.127")
	if !slices.Equal(adds, wantAdds) {
		t.Errorf("adds = %v, want %v", adds, wantAdds)
	}
	if !slices.Equal(removes, wantRemoves) {
		t.Errorf("removes = %v, want %v", removes, wantRemoves)
	}
}

func TestDiffIdentical(t *testing.T) {
	ivs := mustParseAll(t, "10.0.0.1", "10.0.0.2")
	adds, removes := Diff(ivs, ivs)
	if len(adds) != 0 || len(removes) != 0 {
		t.Errorf("Diff of identical lists: adds=%v removes=%v, want none", adds, removes)
	}
}

func TestApply(t *testing.T) {
	current := mustParseAll(t, "10.0.0.3", "10.0.0.2")
	got := Apply(current, mustParseAll(t, "10.0.0.1"), mustParseAll(t, "10.0.0.3"))
	want := mustParseAll(t, "10.0.0.1", "10.0.0.2")
	if !slices.Equal(got, want) {
		t.Errorf("Apply = %v, want %v", got, want)
	}
}

func TestHashIsOrderIndependentAndContentSensitive(t *testing.T) {
	a := Hash(mustParseAll(t, "10.0.0.1", "10.0.0.2"))
	b := Hash(mustParseAll(t, "10.0.0.2", "10.0.0.1"))
	c := Hash(mustParseAll(t, "10.0.0.1", "10.0.0.3"))
	if a != b {
		t.Errorf("hash depends on order: %d != %d", a, b)
	}
	if a == c {
		t.Errorf("different content produced the same hash %d", a)
	}
}

func TestLastAddr(t *testing.T) {
	if got := LastAddr(false).String(); got != "255.255.255.255" {
		t.Errorf("LastAddr(v4) = %s", got)
	}
	if got := LastAddr(true).String(); got != "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff" {
		t.Errorf("LastAddr(v6) = %s", got)
	}
}

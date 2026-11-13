package nftset

import (
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/google/nftables"

	"github.com/MauveSoftware/nftset-update/internal/interval"
)

func parseIntervals(t *testing.T, ss ...string) []interval.Interval {
	t.Helper()
	ivs := make([]interval.Interval, 0, len(ss))
	for _, s := range ss {
		iv, err := interval.Parse(s)
		if err != nil {
			t.Fatalf("Parse(%q): %v", s, err)
		}
		ivs = append(ivs, iv)
	}
	return ivs
}

func start(addr string) nftables.SetElement {
	return nftables.SetElement{Key: netip.MustParseAddr(addr).AsSlice()}
}

func end(addr string) nftables.SetElement {
	return nftables.SetElement{Key: netip.MustParseAddr(addr).AsSlice(), IntervalEnd: true}
}

func describe(elems []nftables.SetElement) string {
	parts := make([]string, 0, len(elems))
	for _, e := range elems {
		addr, _ := netip.AddrFromSlice(e.Key)
		if e.IntervalEnd {
			parts = append(parts, "end:"+addr.String())
		} else {
			parts = append(parts, "start:"+addr.String())
		}
	}
	return strings.Join(parts, " ")
}

func TestEncode(t *testing.T) {
	tests := []struct {
		name string
		ivs  []string
		want []nftables.SetElement
	}{
		{"single address", []string{"10.0.0.1"}, []nftables.SetElement{start("10.0.0.1"), end("10.0.0.2")}},
		{"range", []string{"10.0.0.0-10.0.0.255"}, []nftables.SetElement{start("10.0.0.0"), end("10.0.1.0")}},
		{"last address has no end element", []string{"255.255.255.0-255.255.255.255"}, []nftables.SetElement{start("255.255.255.0")}},
		{"ipv6", []string{"2001:db8::1"}, []nftables.SetElement{start("2001:db8::1"), end("2001:db8::2")}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Encode(parseIntervals(t, tt.ivs...))
			if describe(got) != describe(tt.want) {
				t.Errorf("Encode = %s, want %s", describe(got), describe(tt.want))
			}
		})
	}
}

func TestEncodeUsesFamilyKeyLength(t *testing.T) {
	elems := Encode(parseIntervals(t, "10.0.0.1", "2001:db8::1"))
	if len(elems[0].Key) != 4 {
		t.Errorf("IPv4 key length = %d, want 4", len(elems[0].Key))
	}
	if len(elems[2].Key) != 16 {
		t.Errorf("IPv6 key length = %d, want 16", len(elems[2].Key))
	}
}

func TestDecode(t *testing.T) {
	tests := []struct {
		name  string
		elems []nftables.SetElement
		is6   bool
		want  []string
	}{
		{
			name:  "unsorted kernel order",
			elems: []nftables.SetElement{end("10.0.0.6"), start("10.0.0.5"), end("10.0.0.2"), start("10.0.0.1")},
			want:  []string{"10.0.0.1", "10.0.0.5"},
		},
		{
			name: "adjacent intervals share a boundary key",
			elems: []nftables.SetElement{
				start("10.0.0.2"), end("10.0.0.3"), start("10.0.0.1"), end("10.0.0.2"),
			},
			want: []string{"10.0.0.1", "10.0.0.2"},
		},
		{
			name:  "leading interval end at 0.0.0.0 is ignored",
			elems: []nftables.SetElement{end("0.0.0.0"), start("10.0.0.1"), end("10.0.0.2")},
			want:  []string{"10.0.0.1"},
		},
		{
			name:  "start without end extends to last address",
			elems: []nftables.SetElement{start("10.0.0.1"), end("10.0.0.2"), start("255.255.255.0")},
			want:  []string{"10.0.0.1", "255.255.255.0-255.255.255.255"},
		},
		{
			name:  "arbitrary non-prefix interval",
			elems: []nftables.SetElement{start("10.0.0.3"), end("10.0.0.10")},
			want:  []string{"10.0.0.3-10.0.0.9"},
		},
		{
			name:  "ipv6",
			elems: []nftables.SetElement{end("::"), start("2001:db8::"), end("2001:db8::4")},
			is6:   true,
			want:  []string{"2001:db8::-2001:db8::3"},
		},
		{
			name:  "empty set",
			elems: nil,
			want:  []string{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Decode(tt.elems, tt.is6)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			gotStr := make([]string, 0, len(got))
			for _, iv := range got {
				gotStr = append(gotStr, iv.String())
			}
			if !slices.Equal(gotStr, tt.want) {
				t.Errorf("Decode = %v, want %v", gotStr, tt.want)
			}
		})
	}
}

func TestDecodeErrors(t *testing.T) {
	tests := []struct {
		name  string
		elems []nftables.SetElement
		is6   bool
	}{
		{"consecutive start elements", []nftables.SetElement{start("10.0.0.1"), start("10.0.0.5"), end("10.0.0.9")}, false},
		{"wrong key length", []nftables.SetElement{start("2001:db8::1")}, false},
		{"invalid key", []nftables.SetElement{{Key: []byte{1, 2, 3}}}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := Decode(tt.elems, tt.is6); err == nil {
				t.Errorf("expected error, got none")
			}
		})
	}
}

func TestEncodeDecodeRoundTrip(t *testing.T) {
	tests := []struct {
		name string
		is6  bool
		ivs  []string
	}{
		{"ipv4", false, []string{"0.0.0.0", "10.0.0.1", "10.0.0.2", "10.0.0.4-10.0.0.7", "255.255.255.255"}},
		{"ipv6", true, []string{"::", "2001:db8::-2001:db8::ff", "2001:db8::100", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			want := parseIntervals(t, tt.ivs...)
			elems := Encode(want)
			// Reverse to make sure decoding does not rely on input order.
			slices.Reverse(elems)
			got, err := Decode(elems, tt.is6)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !slices.Equal(got, want) {
				t.Errorf("round trip = %v, want %v", got, want)
			}
		})
	}
}

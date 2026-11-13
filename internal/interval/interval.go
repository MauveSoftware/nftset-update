// Package interval provides inclusive address ranges as stored in nftables
// interval sets, plus the set operations needed to update them.
package interval

import (
	"fmt"
	"hash/fnv"
	"net/netip"
	"slices"
	"strings"
)

// Interval is an inclusive address range [From, To] of a single family.
type Interval struct {
	From netip.Addr
	To   netip.Addr
}

// FromPrefix returns the interval covered by the prefix.
func FromPrefix(p netip.Prefix) Interval {
	p = p.Masked()
	from := p.Addr()
	return Interval{From: from, To: lastInPrefix(from, p.Bits())}
}

func lastInPrefix(addr netip.Addr, bits int) netip.Addr {
	b := addr.AsSlice()
	for i := range b {
		hostBits := len(b)*8 - bits - (len(b)-1-i)*8
		switch {
		case hostBits >= 8:
			b[i] = 0xff
		case hostBits > 0:
			b[i] |= byte(1<<hostBits) - 1
		}
	}
	last, _ := netip.AddrFromSlice(b)
	return last
}

// Parse parses "addr" or "from-to".
func Parse(s string) (Interval, error) {
	fromStr, toStr, isRange := strings.Cut(s, "-")
	from, err := netip.ParseAddr(fromStr)
	if err != nil {
		return Interval{}, err
	}
	to := from
	if isRange {
		if to, err = netip.ParseAddr(toStr); err != nil {
			return Interval{}, err
		}
	}
	if from.Is4() != to.Is4() {
		return Interval{}, fmt.Errorf("mixed address families in %q", s)
	}
	if to.Less(from) {
		return Interval{}, fmt.Errorf("end before start in %q", s)
	}
	return Interval{From: from, To: to}, nil
}

// String returns "addr" for single addresses and "from-to" otherwise.
func (iv Interval) String() string {
	if iv.From == iv.To {
		return iv.From.String()
	}
	return iv.From.String() + "-" + iv.To.String()
}

// Overlaps reports whether both intervals share at least one address.
func (iv Interval) Overlaps(o Interval) bool {
	return iv.From.Compare(o.To) <= 0 && o.From.Compare(iv.To) <= 0
}

// Compare orders intervals by start, then by end.
func Compare(a, b Interval) int {
	if c := a.From.Compare(b.From); c != 0 {
		return c
	}
	return a.To.Compare(b.To)
}

// Sort sorts intervals in place using Compare.
func Sort(ivs []Interval) {
	slices.SortFunc(ivs, Compare)
}

// LastAddr returns the highest address of the family.
func LastAddr(is6 bool) netip.Addr {
	if is6 {
		return netip.AddrFrom16([16]byte{
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		})
	}
	return netip.AddrFrom4([4]byte{0xff, 0xff, 0xff, 0xff})
}

// Diff returns the intervals in desired but not in current (adds) and the
// intervals in current but not in desired (removes), compared by exact
// boundaries. Both results are sorted.
func Diff(desired, current []Interval) (adds, removes []Interval) {
	return subtract(desired, current), subtract(current, desired)
}

// Apply returns the sorted state that results from adding and removing the
// given intervals to/from current.
func Apply(current, added, removed []Interval) []Interval {
	result := subtract(current, removed)
	result = append(result, added...)
	Sort(result)
	return result
}

func subtract(a, b []Interval) []Interval {
	exclude := make(map[Interval]struct{}, len(b))
	for _, iv := range b {
		exclude[iv] = struct{}{}
	}
	result := make([]Interval, 0)
	for _, iv := range a {
		if _, found := exclude[iv]; !found {
			result = append(result, iv)
		}
	}
	Sort(result)
	return result
}

// Hash returns a 32-bit FNV-1a hash over the sorted intervals, used to compare
// set contents between hosts. 32 bits fit exactly into a Prometheus float.
func Hash(ivs []Interval) uint32 {
	sorted := slices.Clone(ivs)
	Sort(sorted)
	h := fnv.New32a()
	for _, iv := range sorted {
		// Writing to a hash.Hash never returns an error.
		_, _ = fmt.Fprintf(h, "%s-%s\n", iv.From, iv.To)
	}
	return h.Sum32()
}

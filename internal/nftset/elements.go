package nftset

import (
	"bytes"
	"fmt"
	"net/netip"
	"slices"

	"github.com/google/nftables"

	"github.com/MauveSoftware/nftset-update/internal/interval"
)

// Encode converts intervals into nftables interval set elements: a start
// element with Key = From and an end element with Key = To+1 flagged as
// IntervalEnd. Intervals ending at the last address of the family have no
// end element.
func Encode(ivs []interval.Interval) []nftables.SetElement {
	elems := make([]nftables.SetElement, 0, 2*len(ivs))
	for _, iv := range ivs {
		elems = append(elems, nftables.SetElement{Key: iv.From.AsSlice()})
		if next := iv.To.Next(); next.IsValid() {
			elems = append(elems, nftables.SetElement{Key: next.AsSlice(), IntervalEnd: true})
		}
	}
	return elems
}

// Decode reconstructs the intervals stored in an interval set. Element
// timeouts are ignored. End elements without an open start (e.g. the leading
// interval end at 0.0.0.0 written by the nft CLI) are skipped; a start element
// without a following end element extends to the last address of the family.
func Decode(elems []nftables.SetElement, is6 bool) ([]interval.Interval, error) {
	sorted := slices.Clone(elems)
	// For equal keys the end element must come first: adjacent intervals
	// share the boundary key (end of the first == start of the second).
	slices.SortFunc(sorted, func(a, b nftables.SetElement) int {
		if c := bytes.Compare(a.Key, b.Key); c != 0 {
			return c
		}
		switch {
		case a.IntervalEnd == b.IntervalEnd:
			return 0
		case a.IntervalEnd:
			return -1
		default:
			return 1
		}
	})

	ivs := make([]interval.Interval, 0, len(sorted)/2)
	var open *netip.Addr
	for _, e := range sorted {
		addr, err := keyToAddr(e.Key, is6)
		if err != nil {
			return nil, err
		}

		if e.IntervalEnd {
			if open != nil {
				ivs = append(ivs, interval.Interval{From: *open, To: addr.Prev()})
				open = nil
			}
			continue
		}

		if open != nil {
			return nil, fmt.Errorf("malformed interval set: start element %s follows start element %s without end element", addr, open)
		}
		open = &addr
	}
	if open != nil {
		ivs = append(ivs, interval.Interval{From: *open, To: interval.LastAddr(is6)})
	}
	return ivs, nil
}

func keyToAddr(key []byte, is6 bool) (netip.Addr, error) {
	wantLen := 4
	if is6 {
		wantLen = 16
	}
	if len(key) != wantLen {
		return netip.Addr{}, fmt.Errorf("unexpected element key length %d, want %d", len(key), wantLen)
	}
	addr, _ := netip.AddrFromSlice(key)
	return addr, nil
}

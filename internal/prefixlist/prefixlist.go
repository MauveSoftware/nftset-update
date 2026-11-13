// Package prefixlist parses and validates the input list of addresses and
// prefixes (usually the output of net-reduce).
package prefixlist

import (
	"bufio"
	"fmt"
	"io"
	"net/netip"
	"strings"

	"github.com/MauveSoftware/nftset-update/internal/interval"
)

// Parse reads one address or CIDR prefix per line and returns the sorted
// intervals. Empty lines and lines starting with '#' are ignored. The input is
// validated strictly: any unparseable line, prefix with host bits set, entry of
// the wrong family or overlap between entries is an error.
func Parse(r io.Reader, is6 bool) ([]interval.Interval, error) {
	ivs := make([]interval.Interval, 0)
	lines := make(map[interval.Interval]int)

	scanner := bufio.NewScanner(r)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		prefix, err := parsePrefix(line)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", lineNo, err)
		}
		if prefix.Addr().Is6() != is6 {
			return nil, fmt.Errorf("line %d: %q does not match the address family of the set", lineNo, line)
		}

		iv := interval.FromPrefix(prefix)
		if previous, found := lines[iv]; found {
			return nil, fmt.Errorf("line %d: %q overlaps line %d", lineNo, line, previous)
		}
		lines[iv] = lineNo
		ivs = append(ivs, iv)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading input: %w", err)
	}

	interval.Sort(ivs)
	for i := 1; i < len(ivs); i++ {
		if ivs[i-1].Overlaps(ivs[i]) {
			return nil, fmt.Errorf("line %d: %s overlaps line %d: %s",
				lines[ivs[i]], ivs[i], lines[ivs[i-1]], ivs[i-1])
		}
	}
	return ivs, nil
}

func parsePrefix(s string) (netip.Prefix, error) {
	var prefix netip.Prefix
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return netip.Prefix{}, err
		}
		prefix = p
	} else {
		addr, err := netip.ParseAddr(s)
		if err != nil {
			return netip.Prefix{}, err
		}
		if addr.Zone() != "" {
			return netip.Prefix{}, fmt.Errorf("zoned address %q not allowed", s)
		}
		prefix = netip.PrefixFrom(addr, addr.BitLen())
	}

	if prefix.Masked() != prefix {
		return netip.Prefix{}, fmt.Errorf("%q has host bits set", s)
	}
	return unmap(prefix), nil
}

// unmap converts IPv4-mapped IPv6 prefixes (::ffff:a.b.c.d/96+) to IPv4.
// Shorter mapped prefixes stay IPv6 and are rejected by the family check.
func unmap(p netip.Prefix) netip.Prefix {
	addr := p.Addr()
	if !addr.Is4In6() || p.Bits() < 96 {
		return p
	}
	return netip.PrefixFrom(addr.Unmap(), p.Bits()-96)
}

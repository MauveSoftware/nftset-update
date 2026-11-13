// Package nftset reads and updates the elements of an existing nftables
// interval set via netlink.
package nftset

import (
	"errors"
	"fmt"
	"os"

	"github.com/google/nftables"
	"golang.org/x/sys/unix"

	"github.com/MauveSoftware/nftset-update/internal/interval"
)

const (
	// A netlink attribute length is a uint16, so the element list of a single
	// message must stay below 64 KiB. An IPv6 interval needs up to ~70 bytes
	// (start + end element), so 512 intervals stay well below the limit.
	maxIntervalsPerMessage = 512
)

// ErrNotFound is returned by Open if the table or set does not exist.
var ErrNotFound = errors.New("table or set not found")

// Dial opens a lasting netlink connection. netnsFd selects a network
// namespace; 0 uses the namespace of the calling process.
func Dial(netnsFd int) (*nftables.Conn, error) {
	opts := []nftables.ConnOption{nftables.AsLasting(), nftables.WithSockOptions(enlargeSendBuffer, enlargeDumpChunks)}
	if netnsFd > 0 {
		opts = append(opts, nftables.WithNetNSFd(netnsFd))
	}
	return nftables.New(opts...)
}

// Set is an existing nftables interval set of IPv4 or IPv6 addresses.
type Set struct {
	conn   *nftables.Conn
	set    *nftables.Set
	is6    bool
	broken error
}

// Open looks up the set and verifies that it is an interval set of IPv4 or
// IPv6 addresses.
func Open(conn *nftables.Conn, family nftables.TableFamily, table, name string) (*Set, error) {
	s, err := conn.GetSetByName(&nftables.Table{Name: table, Family: family}, name)
	if err != nil {
		if errors.Is(err, unix.ENOENT) || errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("%w: %s %s", ErrNotFound, table, name)
		}
		return nil, fmt.Errorf("looking up set %s in table %s: %w", name, table, err)
	}

	var is6 bool
	switch s.KeyType.Name {
	case nftables.TypeIPAddr.Name:
		is6 = false
	case nftables.TypeIP6Addr.Name:
		is6 = true
	default:
		return nil, fmt.Errorf("set %s has unsupported key type %q", name, s.KeyType.Name)
	}
	if !s.Interval {
		return nil, fmt.Errorf("set %s is not an interval set", name)
	}

	return &Set{conn: conn, set: s, is6: is6}, nil
}

// Is6 reports whether the set holds IPv6 addresses.
func (s *Set) Is6() bool {
	return s.is6
}

// Read dumps the set elements from the kernel and returns the intervals.
func (s *Set) Read() ([]interval.Interval, error) {
	elems, err := s.conn.GetSetElements(s.set)
	if err != nil {
		return nil, fmt.Errorf("reading elements of set %s: %w", s.set.Name, err)
	}
	return Decode(elems, s.is6)
}

// Add adds the intervals in one atomic transaction.
func (s *Set) Add(ivs []interval.Interval) error {
	return s.transaction(ivs, s.conn.SetAddElements)
}

// Delete deletes the intervals in one atomic transaction. The intervals must
// match the stored boundaries exactly.
func (s *Set) Delete(ivs []interval.Interval) error {
	return s.transaction(ivs, s.conn.SetDeleteElements)
}

func (s *Set) transaction(ivs []interval.Interval, queue func(*nftables.Set, []nftables.SetElement) error) error {
	if s.broken != nil {
		return s.broken
	}
	if len(ivs) == 0 {
		return nil
	}
	for start := 0; start < len(ivs); start += maxIntervalsPerMessage {
		end := min(start+maxIntervalsPerMessage, len(ivs))
		if err := queue(s.set, Encode(ivs[start:end])); err != nil {
			// The connection cannot discard already queued messages, so a
			// later Flush would commit a partial transaction. Refuse any
			// further transactions instead.
			s.broken = fmt.Errorf("set %s unusable after failing to queue elements: %w", s.set.Name, err)
			return s.broken
		}
	}
	return s.conn.Flush()
}

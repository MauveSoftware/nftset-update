# TODO

## Open tasks

- [ ] (high) Measure read/apply times on a proxy with kernel 5.15 and ~200k elements (spec §16, §18)
- [ ] (medium) Adapt `update_blocklist.rb` (spec §13), metrics and alerts
- [ ] (low) Verify mail server versions and presence of `blocklist-v6` on all hosts
- [ ] (low) Optional `-dry-run` flag (spec §18)

## Completed

- [x] Rename module (`github.com/MauveSoftware/nftset-update`), pin `github.com/google/nftables` v0.3.0
- [x] `internal/interval`: interval type, diff, content hash
- [x] `internal/prefixlist`: strict input parsing and validation
- [x] `internal/nftset`: element encoding/decoding, netlink read and apply
- [x] `internal/update`: ordering, mass-removal guard, batched apply
- [x] `internal/report`: JSON report
- [x] `main.go`: flags, exit codes, report, signal handling
- [x] Makefile (`build`, `test`, `test-integration`, `lint`)
- [x] Integration tests in a private network namespace (build tag `integration`)
- [x] Rename project directory to `nftset-update`

## Development decisions

- 2026-11-13: CLI tool instead of daemon, called by the existing Ruby script via systemd timer.
  Stateless: every run reads the kernel set, so manual changes are reverted and all hosts with the
  same sources hold identical sets. Manual bans belong in other sets.
- 2026-11-13: Fetching and `net-reduce` consolidation stay in Ruby; Go only replaces the `nft` part.
  Each input prefix is one interval (no merging), matching what the nft CLI wrote.
- 2026-11-13: Go reports a JSON object on stdout; Ruby writes the metrics (existing metric names kept).
- 2026-11-13: Name `nftset-update` (generic tool, not blocklist specific).

- 2026-11-13: `main.go` in the root package instead of `cmd/` because goreleaser builds `.` and
  sets `main.version`.
- 2026-11-13: The netlink socket is primed with a 32 KiB receive so the kernel dumps sets in
  32 KiB chunks; reading 200k intervals drops from ~6 s to ~1.5 s.

## Technical debt

## Recurring issues

- Netlink limits: one attribute < 64 KiB (split element lists), one batch must fit the socket
  send buffer (enlarge with `SO_SNDBUFFORCE`).

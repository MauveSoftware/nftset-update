# TODO

## Open

- [ ] (none)

## Done

- [x] M1: `run`/`execute` take a `setOpener`, so exit codes and report fields are unit tested with a fake set
- [x] M2: `update.Apply` returns `ErrInvalidBatchSize` instead of looping forever on a batch size below 1
- [x] L1: batch size moved into `update.Plan`; `Apply` no longer takes it as a separate argument
- [x] L2: exit code comment in `main.go` points to the README instead of the unpublished spec
- [x] L3: `interval.Parse` rejects zoned addresses, matching `prefixlist`
- [x] L4: removed the redundant first `SetResult` in `execute`; the content hash is now computed once per run
- [x] L5: `logChanges` logs with the run context
- [x] L6: `nftset.Decode` uses the zero `netip.Addr` instead of a pointer to mark "no open interval"

## Decisions

- Batch size lives in `Plan` (set by `NewPlan` from `Config`) so planning and applying share one source of truth.
- The batch size check sits in `applier.run`, so every phase is covered even if `Apply` gains phases later.
- L3: `interval.Parse` stays exported (tests in several packages use it) instead of adding a test-only helper package.
- L4: hash encoding unchanged, hosts compare content hashes across versions.
- Constants use Go's camelCase convention rather than ALL_CAPS.

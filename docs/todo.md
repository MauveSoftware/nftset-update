# TODO

## Open

- [ ] (low) L2: replace the "see spec §6" reference in `main.go`; `spec.md` is not part of the repository
- [ ] (low) L3: `interval.Parse` is only used by tests and accepts zoned addresses; move to a test helper or reject zones
- [ ] (low) L4: content hash is computed twice per run; avoid the first `SetResult` (do NOT change the hash encoding, hosts compare hashes)
- [ ] (low) L5: `logChanges` uses `context.Background()`; pass the run context
- [ ] (low) L6: `nftset.Decode` tracks the open interval via `*netip.Addr`; use the zero `netip.Addr` + `IsValid()`

## Done

- [x] M1: `run`/`execute` take a `setOpener`, so exit codes and report fields are unit tested with a fake set
- [x] M2: `update.Apply` returns `ErrInvalidBatchSize` instead of looping forever on a batch size below 1
- [x] L1: batch size moved into `update.Plan`; `Apply` no longer takes it as a separate argument

## Decisions

- Batch size lives in `Plan` (set by `NewPlan` from `Config`) so planning and applying share one source of truth.
- The batch size check sits in `applier.run`, so every phase is covered even if `Apply` gains phases later.
- Constants use Go's camelCase convention rather than ALL_CAPS.

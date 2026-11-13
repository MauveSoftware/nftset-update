# nftset-update

Makes the elements of an existing nftables interval set equal to a list of addresses and
prefixes. It talks to nf_tables directly via netlink (`github.com/google/nftables`), with no
`nft` CLI and no libnftables.

It is built to replace the `nft` part of `update_blocklist.rb`. Fetching and consolidating the
lists (`net-reduce`) stay in the calling script.

## Features

- Reads the current set from the kernel on every run and applies only the differences.
  Manual changes to the set are reverted.
- New entries are added before removals. Adds that overlap a removed interval are applied
  after the removals.
- Changes are applied in batched, atomic netlink transactions.
- A mass-removal guard prevents an empty or truncated input from unblocking everything.
- Strict input validation: nothing is changed if any input line is invalid.
- Prints a JSON report to stdout for metrics; logs go to stderr.
- Does not change the nftables structure. Tables, chains, rules and sets must already exist.

## Usage

```
nftset-update -set <name> -input <file> [flags]
```

| Flag | Default | Description |
|---|---|---|
| `-set` | (required) | Name of the set |
| `-input` | (required) | Path of the prefix list |
| `-table` | `filter` | Table name |
| `-table-family` | `inet` | `inet`, `ip` or `ip6` |
| `-batch-size` | `10000` | Max. intervals per transaction (1–100000) |
| `-max-remove-fraction` | `0.5` | Mass-removal guard; `1` disables the fraction check |
| `-guard-min-elements` | `1000` | The guard only applies above this set size |
| `-allow-empty` | `false` | Allow an empty input to clear a non-empty set |
| `-debug` | `false` | Log at DEBUG level |
| `-version` | | Print version and exit |

The address family (IPv4/IPv6) is taken from the set's key type. Only interval sets of
`ipv4_addr` or `ipv6_addr` are supported.

Example:

```sh
nftset-update -set blocklist-v4 -input /run/blocklist/v4.txt
```

### Input format

One IPv4/IPv6 address or CIDR prefix per line. Empty lines and lines starting with `#` are
ignored. IPv4-mapped IPv6 addresses are normalized to IPv4. The run aborts without changes on
any of these:

- an unparseable line
- host bits set (e.g. `10.0.0.1/24`)
- an entry of the wrong address family
- overlapping or duplicate entries

Each prefix is stored as one interval. Adjacent prefixes are not merged; consolidate the list
before calling the tool (e.g. with `net-reduce`).

### Exit codes

| Code | Meaning |
|---|---|
| 0 | Set equals the input (including "no changes") |
| 1 | Netlink or transaction error; set may be partially updated |
| 2 | Usage or input error; nothing changed |
| 3 | Mass-removal guard tripped; adds applied, removals skipped |
| 4 | Table or set does not exist; nothing changed |

### Report

After every run (except flag errors), one JSON object is written to stdout:

```json
{"table":"inet filter","set":"blocklist-v4","afi":"v4","present":true,"success":true,
 "exit_code":0,"input_intervals":201240,"intervals_before":201234,"intervals_after":201240,
 "added":8,"removed":2,"pending_adds":0,"pending_removes":0,"guard_tripped":false,
 "transactions":1,"read_seconds":0.41,"apply_seconds":0.02,"duration_seconds":0.47,
 "content_hash":3735928559,"error":""}
```

`content_hash` is a 32-bit FNV-1a hash of the set content after the run. Compare it across
hosts to check that their sets are identical.

## Requirements

- Linux kernel 5.15 or newer
- `CAP_NET_ADMIN`

## Build

```sh
make build
```

This runs `CGO_ENABLED=0 go build -trimpath -ldflags='-s -w'` and produces a fully static
binary with no libc dependency, so it runs on Ubuntu 22.04, 24.04 and other Linux
distributions. Releases are built with goreleaser for amd64, arm and arm64.

## Test

```sh
make test     # unit tests, no privileges required
make lint     # go vet (and staticcheck, if installed)
```

The integration tests run against the kernel in a private user and network namespace (via
`unshare -rn`), so the host ruleset is never touched:

```sh
make test-integration
```

They cover a full load of 200k intervals, small deltas, a rotation of 35k adds / 28k removes,
reshaping, reverting manual changes, a recreated set, a missing set and compatibility with
sets written by the `nft` CLI.

## Performance

Reading the set from the kernel dominates a run with large sets: the kernel restarts its tree
walk for every dump chunk. The tool makes the kernel use its maximum chunk size (32 KiB), which
brings reading 200k intervals down from ~6 s to ~1.5 s. Applying a handful of changes takes
well under 0.1 s; a full load of 200k intervals takes ~2 s.

## License

See [LICENSE](LICENSE).

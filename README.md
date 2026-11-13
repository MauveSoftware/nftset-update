# nftset-update

Makes the elements of an existing nftables interval set equal to a list of addresses and
prefixes. It talks to nf_tables directly via netlink (`github.com/google/nftables`), with no
`nft` CLI and no libnftables.

Typical uses are blocklists or allowlists that are maintained elsewhere (APIs, threat feeds,
inventories) and need to be kept in sync on many hosts. The tool follows the Unix philosophy:
it only updates the set. Fetching, merging and consolidating the lists, as well as turning the
report into metrics, are left to the caller.

Updating sets via netlink avoids the fixed cost of the `nft` CLI, which loads the elements of
all sets before every operation. With sets of several 100k elements this makes each `nft` call
take seconds, while `nftset-update` applies small changes in milliseconds.

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

## Prerequisites

The table and the set must already exist; the tool never creates, changes or deletes tables,
chains, rules or sets. The set must be an interval set of `ipv4_addr` or `ipv6_addr`, for
example:

```
table inet filter {
    set blocklist-v4 { type ipv4_addr; flags interval; }
    set blocklist-v6 { type ipv6_addr; flags interval; }

    chain input {
        type filter hook input priority filter - 1; policy accept;
        ip saddr @blocklist-v4 drop
        ip6 saddr @blocklist-v6 drop
    }
}
```

The tool owns the set's elements: entries that are not in the input are removed on the next
run, including entries added manually. Use a separate set for manual entries.

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

A typical caller (script, systemd timer, cron job) fetches the lists, consolidates them, writes
the result completely to a file and then calls the tool:

```sh
#!/bin/sh
set -eu
list=$(mktemp)
trap 'rm -f "$list"' EXIT

curl -fsS https://example.com/blocklist-v4.txt | aggregate > "$list"
nftset-update -set blocklist-v4 -input "$list" > report.json
```

Pass a complete file rather than a pipe: if the fetch fails halfway, the tool must not see a
truncated list. The mass-removal guard is a second line of defence, not a replacement.

### Input format

One IPv4/IPv6 address or CIDR prefix per line. Empty lines and lines starting with `#` are
ignored. IPv4-mapped IPv6 addresses are normalized to IPv4. The run aborts without changes on
any of these:

- an unparseable line
- host bits set (e.g. `10.0.0.1/24`)
- an entry of the wrong address family
- overlapping or duplicate entries

Each prefix is stored as one interval. Adjacent prefixes are not merged and overlapping
entries are rejected, so consolidate the list before calling the tool (e.g. with
`aggregate`, `net-reduce` or `iprange`).

### Exit codes

| Code | Meaning |
|---|---|
| 0 | Set equals the input (including "no changes") |
| 1 | Netlink or transaction error; set may be partially updated |
| 2 | Usage or input error; nothing changed |
| 3 | Mass-removal guard tripped; adds applied, removals skipped |
| 4 | Table or set does not exist; nothing changed |

### Report

After every run (except flag errors), one JSON object is written to stdout. It is meant to be
turned into metrics by the caller (e.g. for the Prometheus node exporter textfile collector):

```json
{"table":"inet filter","set":"blocklist-v4","afi":"v4","present":true,"success":true,
 "exit_code":0,"input_intervals":201240,"intervals_before":201234,"intervals_after":201240,
 "added":8,"removed":2,"pending_adds":0,"pending_removes":0,"guard_tripped":false,
 "transactions":1,"read_seconds":0.41,"apply_seconds":0.02,"duration_seconds":0.47,
 "content_hash":3735928559,"error":""}
```

| Field | Meaning |
|---|---|
| `present` | The set exists |
| `success` / `exit_code` | Outcome of the run, see exit codes |
| `input_intervals` | Intervals in the input |
| `intervals_before` / `intervals_after` | Intervals in the set before and after the run |
| `added` / `removed` | Intervals committed in this run |
| `pending_adds` / `pending_removes` | Changes not applied (guard or error) |
| `guard_tripped` | The mass-removal guard skipped the removals |
| `transactions` | Committed netlink transactions |
| `read_seconds` / `apply_seconds` / `duration_seconds` | Time spent reading the set, applying changes and in total |
| `content_hash` | 32-bit FNV-1a hash of the set content after the run |
| `error` | Error message, empty on success |

Compare `content_hash` across hosts to check that their sets are identical.

### Mass-removal guard

If the set holds more than `-guard-min-elements` intervals and more than
`-max-remove-fraction` of them would be removed, the removals are skipped and the tool exits
with code 3. New entries are still added. An empty input never clears a non-empty set unless
`-allow-empty` is given. The guard does not apply to an initially empty set.

## Requirements

- Linux kernel 5.15 or newer
- `CAP_NET_ADMIN`

## Build

```sh
make build
```

This runs `CGO_ENABLED=0 go build -trimpath -ldflags='-s -w'` and produces a fully static
binary with no libc dependency, so it runs on any Linux distribution. Releases are built with goreleaser for amd64, arm and arm64.

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

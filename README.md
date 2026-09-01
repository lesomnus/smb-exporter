# smb-exporter

Exports **who is pulling how much over SMB**, and **how many file operations
they are doing to get it**, via [OpenTelemetry](https://opentelemetry.io/) or
any exporter [mkot](https://github.com/lesomnus/mkot) supports.

## Why

Samba tells you plenty about *sessions* and nothing useful about *volume*.
`smbstatus` has no byte counters, and the usual Prometheus samba exporters only
count connections. So the two questions that actually matter during an incident
— *who is saturating the fileserver* and *is it bandwidth or is it IOPS* — have
no answer.

The second half is the interesting one. A client streaming one large dataset
and a client walking ten million tiny files look identical in every
session-level metric, but only one of them collapses the storage. The
distinguishing signal is **bytes per operation**, and it needs both numbers to
exist.

## What it reports

| Metric | Attributes | Source |
|---|---|---|
| `smb.bytes.sent` | `user` | `ss -tin` |
| `smb.bytes.received` | `user` | `ss -tin` |
| `smb.operations` | `user`, `share`, `operation` | `full_audit` |
| `smb.connections` | — | `ss` |
| `smb.sessions` | — | `smbstatus` |

`smb.bytes.sent` is server to client: the direction a dataset pull goes.

Divide operations by bytes and the scan pattern above stands out on its own —
an account doing thousands of opens per second for a few megabytes is not doing
what an account pulling a gigabyte in one stream is doing.

## How it works

Three ordinary tools, read on an interval, joined:

- **`ss -tin`** — per-socket `bytes_sent` / `bytes_received`. These come from
  the kernel's `tcp_info`; `/proc/net/tcp` has no byte counters, which is why
  this shells out rather than reading procfs.
- **`smbstatus -b`** — the only thing that maps a client address to an account.
- **Samba's `full_audit` log** — followed and **counted, never stored**. On a
  scan of many small files this stream reaches hundreds of lines per second;
  turning it into counters at the source is the entire point. Nothing is
  forwarded to a log backend.

### What it does not measure exactly

The byte counters belong to the socket, so:

- a connection seen for the first time contributes **zero**, not its history —
  otherwise every restart would publish a spike that never happened;
- traffic on a connection that opens *and* closes between two polls is never
  seen.

SMB sessions are long-lived, so in practice this is close. But the totals are a
**floor**, not an exact accounting, and it is worth knowing that before using
them to bill anyone.

The audit log rotates, and records written during the swap are lost. These are
rate counters, not an audit trail — this is not where to look for "who deleted
that file".

## Configuration

See [`smb-exporter.yaml`](smb-exporter.yaml). Defaults assume the SMB port is
445 and Samba's tdb directory is where `smbstatus` expects it.

Operation metrics need `full_audit` on the server:

```ini
vfs objects        = full_audit
full_audit:prefix  = %u|%I|%S
full_audit:success = create_file mkdirat unlinkat renameat
full_audit:failure = none
```

`create_file` is a **file open**, including opens for reading — that is what
makes it a usable proxy for scan rate. Reads and writes themselves are not
logged by Samba's audit module at all, which is also why bytes have to come
from the socket.

## Running

It needs to see two things that usually live in different places: the **network
namespace** holding the SMB port, and Samba's **tdb directory**. Alongside the
smbd process is the simple answer — as a sidecar in the same pod when smbd runs
in Kubernetes, sharing the pod's network namespace and mounting the same state
volume.

```sh
docker run --rm -it --network host \
  -v /var/lib/samba:/var/lib/samba:ro \
  -v /var/log/samba:/var/log/samba:ro \
  -v $(pwd)/smb-exporter.yaml:/smb-exporter.yaml:ro \
  ghcr.io/lesomnus/smb-exporter:latest
```

## Build

```sh
go install github.com/lesomnus/smb-exporter@latest
```

Requires Go 1.26+.

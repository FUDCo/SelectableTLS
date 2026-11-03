# Optional benchmark and diagnostic tools

These tools support future implementation and performance investigations. They
are not needed by applications using the API. Run commands from the repository
root; see [build setup](../../BUILD.md) and [the contributor overview](../README.md).

Normal builds have no runtime dependency on a comparison library. All harnesses
use generated test identities and certificate verification; no trust-all settings
or production security-policy changes are needed.

## Concurrent traffic and churn

```
make stress ARGS='256 64 2000 32'
make stress ARGS='256 64 100 32 128'
```

Arguments are pairs, active pairs, round trips per active pair, waves, and an
optional JSSE session-cache size. Each wave establishes the population, exercises
the active subset concurrently, retains the other connections idle, then closes
everything. Both endpoints run in one JVM on selectors. No per-connection test
threads are created. Every payload is checked for identity, sequence and content.

The harness warms a full population before collecting baseline heap and resource
counts. Each wave must release all native transports and selection keys before
the next wave. Eight waves each of malformed and silent peers follow, then valid
traffic must recover. The throughput interval excludes warmup and the fault phase;
final resource counts include the fault phase. Latencies include initial connection
authentication and are sampled from the first million replies. Heap is measured
after requested GC; descriptor counts are available on Unix platforms. Thread and
heap differences are reported, not converted into brittle pass thresholds.
Process CPU and collector count/time deltas cover the traffic interval only,
excluding requested baseline/final heap collections and the subsequent fault phase.
Collector times are JVM totals, not an application stop-the-world latency measure.

JSSE session caching can legitimately retain substantial memory after connection
churn. The optional cache setting applies only to the probe's SSLContext; the
library does not silently change application cache policy. A size of zero means
unlimited under the JSSE API and should not be used as a way to disable caching.

## Idle-population and sequential diagnostics

```
make probe ARGS='1000 10000 plain'
make probe ARGS='1000 10000 tls'
make capacity ARGS='10000 10000'
```

The capacity command caps the JVM heap at 8 GiB, adjusts only its process's
descriptor limit, and admits connections in groups of 256. It supports at most
100,000 pairs. Distinct per-group listeners and SO_REUSEADDR on the probe's own
source ports avoid exhausting the host's ephemeral-port allocator. No system-wide
network settings are changed. Both endpoints are local: a pair counts as one TCP
connection and two TLS endpoints. Only up to 64 pairs exchange sequential requests.
This is not a simulation of the same number of independent application users.

## TLS Channel comparison

Use the public [TLS Channel 1.0.0 release](https://github.com/marianobarrios/tls-channel/releases/tag/1.0.0),
Maven coordinate `com.github.marianobarrios:tls-channel:1.0.0`. Supply its JAR as an
explicit argument; it is not checked into this repository or bundled in artifacts.
The executed Maven Central JAR has SHA-256:

```
8c043d431aa516f330bad1678cd2fc37a62f3da12199270c5a60b5f2685df1b1
```

```
make compare ARGS='/path/to/tls-channel-1.0.0.jar 1000 10000 heap'
make compare ARGS='/path/to/tls-channel-1.0.0.jar 1000 10000 pooled'
```

The separately compiled adapter uses public TLS Channel APIs. It matches
ResourceProbe's 32 warmup pairs, 500 warmup exchanges, 32-byte sequential echoes,
population size and active subset. Both libraries use JSSE with authenticated
localhost identity and TLS 1.3/1.2 enabled. TLS Channel post-handshake reads are
driven to quiescence before measuring idle heap; SelectableTLS drives them itself.

`heap` uses TLS Channel's HeapBufferAllocator for both buffer types with buffer
release enabled. `pooled` uses SelectableTLS's bounded heap pool as an alternative
allocator. Its 32 KiB minimum allocation can inflate retained TLS Channel buffers;
it is not TLS Channel's default or necessarily its optimal pooling configuration.
TLS Channel runs delegated tasks inline in this adapter. SelectableTLS uses its
shared reactor and bounded workers. Thus the results compare these concrete
integration choices, not cryptographic primitives or exception overhead in
isolation. Exception counts are observed during traffic, excluding setup.

All reported measurements are diagnostics. Repeat on the target deployment,
record host/runtime settings, and include concurrent workloads before drawing
capacity or production-latency conclusions. See [measurement methodology](../MEASUREMENTS.md) for interpretation limits.

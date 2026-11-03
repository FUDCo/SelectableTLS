# Measurement methodology and further work

These notes are for contributors investigating resource use and performance.
They do not specify application capacity or make a performance comparison claim.
Commands and workload arguments are in [the diagnostic guide](Benchmarks/README.md).
Run them from the repository root and record the exact source revision, runtime,
operating system, host limits and TLS configuration with every result.

## What the tools measure

`ResourceProbe` creates both endpoints in one JVM. A TCP connection therefore
counts as one connection and two TLS endpoints. After a warmup it measures idle
heap and sequential 32-byte echoes across a limited active subset. This is useful
for examining per-endpoint overhead; it does not simulate the same number of
independent active users or establish maximum concurrent throughput.

`StressProbe` creates traffic concurrently across an active subset, retains the
other peers idle, and repeats establishment and closure in waves. It checks
payload identity and sequence, transport/key cleanup, malformed and silent-peer
handling, and recovery with valid traffic. Reported CPU, GC, heap and latency
values describe the configured workload; they are not pass thresholds or service
level commitments.

`NetworkProbe` separates the processes and can run across hosts. It checks
ordered delivery, verified TLS identity and clean EOF. Record which host initiated
connections and qualify each direction independently. A successful transport test
does not by itself qualify a distributed application or a sustained capacity limit.

## Interpretation limits

- Heap measurements exclude native memory and RSS. Requested GC does not guarantee
  identical retained-heap snapshots. Compare heap, process memory and descriptor
  use rather than interpreting one number as total connection cost.
- JSSE session caches can retain state after connection churn. Record cache limits
  and session counts. A cache size of zero means unlimited, not disabled.
- Include idle population, active population, payload size, admission rate,
  handshake/authentication configuration and queue limits with throughput results.
- Distinguish warmup, traffic and fault phases. JVM-wide collector times do not
  directly measure individual application pause times.
- A large mostly idle population is not an application-capacity guarantee. Repeat
  with representative concurrent traffic and slow peers before extrapolating.
- The optional TLS Channel adapter compares particular integration and allocation
  choices. It does not isolate exception overhead or prove one library universally
  faster than another.

## Useful future investigations

Repeat measurements across JDKs and deployment environments with CPU and process
memory profiling. Extend slow-reader/writer, handshake-storm and fairness workloads;
combine sustained application traffic with admission churn and realistic payloads.
Test long-lived sessions and additional TLS peers. Multi-day runs and independent
repetition would strengthen confidence before making operational capacity claims.

Keep the raw output and configuration alongside any future report. Publish results
with workload limits and reproducible commands rather than a single headline
connection count or throughput number.

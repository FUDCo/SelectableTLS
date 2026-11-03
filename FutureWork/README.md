# Information for future implementation work

This directory is optional material for contributors investigating or extending
SelectableTLS. Applications using the API do not need these notes or benchmarks.
Start with the repository's [API guide](../API.md) and
[channel contract](../CONTRACT.md) for supported behavior.

- [Test coverage and further work](CONFORMANCE.md) maps the executable tests to
  behavior and lists useful additional test campaigns.
- [Measurement methodology](MEASUREMENTS.md) explains what the diagnostic tools
  measure, their limitations and questions worth investigating.
- [Benchmark and diagnostic tools](Benchmarks/README.md) describes workloads,
  reproduction commands and the optional comparison adapter.

These notes do not promise future features, performance targets or a release
schedule. Large connection counts and benchmark throughput are workload-dependent
and are not guarantees made by the channel API. Diagnostic code and third-party
comparison libraries are not dependencies of the runtime JAR.

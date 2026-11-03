# Security policy

## Reporting a vulnerability

Report suspected vulnerabilities privately through the repository's
[security reporting form](https://github.com/FUDCo/SelectableTLS/security/advisories/new).
Include the version, JDK vendor/version, OS, configuration and a minimal
reproduction without real credentials or application data. Do not post exploitable
details in public issues. Ordinary defects can be reported through GitHub issues.

Maintenance is on a best-effort basis. Reports should identify whether the issue
reproduces with the latest release. There is no guaranteed response time,
long-term support period or promise to backport fixes to older versions.

## Application responsibilities

Cryptography, chain validation and endpoint identification are provided by JSSE.
Use a maintained JDK and appropriate trust/key configuration. The library does not
install trust-all defaults or weaken JVM algorithm restrictions. Client endpoint
identification is enabled; requiring client certificates is opt-in. TLS
authentication does not replace application authorization.

Per-connection buffering, handshake deadlines and delegated-task queues are
bounded. Applications control admission limits, established-connection idle
policies and their own queues. A blocked custom trust manager can occupy a worker;
a deadline cannot forcibly stop arbitrary application code. Session cache settings
belong to the supplied SSLContext. Heap buffers are not zeroized after use.
See [the architecture](DESIGN.md) for resource and ownership details.

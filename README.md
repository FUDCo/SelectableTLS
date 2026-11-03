# SelectableTLS

SelectableTLS provides TLS socket channels and selectors using Java NIO and
JSSE. Applications use normal channel reads, writes and selection interests;
the library handles TLS negotiation and encrypted transport progress.
The runtime requires Java 17 or newer and has no dependencies beyond Java SE.

## Getting started

Start with [the API guide](API.md) and [the echo example](Examples/README.md).
[The channel contract](CONTRACT.md) describes connection, selection and shutdown
behavior. TLS channels use the library's matching selector, which can also handle
ordinary Java socket channels, pipes and datagrams.

Release coordinates are `com.fudco:selectable-tls:0.1.0`. See
[installation and release contents](RELEASE.md) for direct JAR, Maven and Gradle
use. The library is licensed under the [MIT License](LICENSE).

## Building

Build with `make` and run `make test`, using GNU make, jdep, a JDK and bash.
[Build instructions](BUILD.md) cover setup, test targets and the optional Maven
build. The runtime JAR is `build/selectable-tls.jar`. `make examples` runs the
verified TLS echo example with temporary credentials.

The test matrix covers Linux, macOS and Windows with JDKs 17, 21 and 25.
Tests exercise channel/selector contracts, certificate validation, concurrent
traffic, TLS shutdown and failure recovery.

## Documentation

- [API guide](API.md): configuration, I/O, authentication and lifecycle.
- [Channel contract](CONTRACT.md): supported behavior and NIO boundaries.
- [Architecture](DESIGN.md): engine ownership, selection and resource bounds.
- [Security policy](SECURITY.md): reporting and application responsibilities.
- [Future implementation work](FutureWork/README.md): optional testing and
  performance material for library contributors.

# Installation and release contents

SelectableTLS 0.1.0 requires Java 17 or newer and is licensed under the MIT License.
Its runtime depends only on Java SE. The package and automatic module name are
`com.fudco.selectabletls`.

## Install a binary release

Release downloads are available from the
[GitHub releases page](https://github.com/FUDCo/SelectableTLS/releases).
Download the runtime JAR and accompanying checksums, then verify the files you
obtained against `SHA256SUMS`. If you downloaded the complete asset set, use:

```sh
shasum -a 256 -c SHA256SUMS
```

Add `selectable-tls-0.1.0.jar` to your application's compile and runtime classpaths.
No other runtime JAR is required. Configure keys and trust through an initialized
SSLContext; application credentials are not part of the distribution.

## Maven and Gradle

SelectableTLS is available from
[Maven Central](https://repo.maven.apache.org/maven2/com/fudco/selectable-tls/0.1.0/)
as `com.fudco:selectable-tls:0.1.0`. For Maven:

```xml
<dependency>
  <groupId>com.fudco</groupId>
  <artifactId>selectable-tls</artifactId>
  <version>0.1.0</version>
</dependency>
```

For Gradle using Kotlin DSL:

```kotlin
repositories { mavenCentral() }
dependencies { implementation("com.fudco:selectable-tls:0.1.0") }
```

Consumers can also install downloaded artifacts into a local Maven repository:

```sh
mvn install:install-file \
  -Dfile=selectable-tls-0.1.0.jar \
  -DpomFile=selectable-tls-0.1.0.pom \
  -Dsources=selectable-tls-0.1.0-sources.jar \
  -Djavadoc=selectable-tls-0.1.0-javadoc.jar
```

This command installs locally; it does not publish anything. Applications using
plain classpaths do not need Maven or Gradle.

## Download inventory

| File | Contents |
| --- | --- |
| `selectable-tls-0.1.0.jar` | Runtime classes and MIT license |
| `selectable-tls-0.1.0-sources.jar` | Library Java sources and license for IDE/source browsing |
| `selectable-tls-0.1.0-javadoc.jar` | Generated API documentation and license |
| `selectable-tls-0.1.0-src.tar.gz` | Complete public source tree, including builds, tests, example, docs and optional contributor tools |
| `selectable-tls-0.1.0.pom` | Maven coordinates, project metadata and optional Maven build |
| `LICENSE` | MIT license |
| `PROVENANCE.md` | Public source revision and build toolchain |
| `SHA256SUMS` | SHA-256 checksums of the release files |

Maven Central includes PGP signatures and per-file checksums for the POM and
three JARs. The complete source archive and contributor tools are not runtime
dependencies.

The source tree's `FutureWork/` directory contains optional testing and performance
notes for library contributors. It is separate from application-facing API
information. Generated test identities, private development records and
third-party comparison binaries are excluded from the distribution.

## Build from source

```sh
tar -xzf selectable-tls-0.1.0-src.tar.gz
cd selectable-tls-0.1.0
make test distribution examples
```

Install the toolchain described in [BUILD.md](BUILD.md) first. The development
build uses GNU make/jdep; outputs are under `build/`. Maven is an independent
alternative (`mvn clean verify`). JAR entry timestamps are fixed for reproducible
builds with the same JDK/toolchain; byte-for-byte identity across different JDK
versions is not promised.

For behavior and supported scope, see [the API guide](API.md) and
[channel contract](CONTRACT.md). Reporting and maintenance are described in
[SECURITY.md](SECURITY.md).

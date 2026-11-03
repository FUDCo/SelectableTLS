# Building and testing

The development build uses GNU make, bash, a JDK (17 or newer), and
[jdep](https://github.com/FUDCo/jdep). The runtime has no third-party dependencies.
Maven is available as an independent alternative; it does not need make or jdep.

## Setup

Install jdep from its source repository:

```sh
git clone https://github.com/FUDCo/jdep
make -C jdep
```

Put `jdep/bin` on your PATH, or pass `JDEP=/absolute/path/to/jdep/bin/jdep` to make.
Use revision `7b940380b090159b854d69a2a8ba6a8ae9226c84` or a later compatible
revision with support for modern class files. CI builds that pinned revision.
A C compiler is needed to build jdep, but not to build this library once jdep is
installed. This build uses `mkdir` and `touch` directly, so it does not need the
companion `touchp` command.

Set `JAVA_HOME` to choose a JDK; otherwise JDK tools come from PATH. Compilation
targets Java 17 with warnings treated as errors. The make build is intended for
Unix environments (including macOS); use the Maven alternative for native Windows.

## Common targets

Run these from the project root:

| Command | Result |
| --- | --- |
| `make` | Build `build/selectable-tls.jar` incrementally |
| `make test` | Compile and run conformance, including forced TLS key updates |
| `make examples` | Compile and run the verified TLS echo example |
| `make stress ARGS='64 16 100 4 128'` | Concurrent traffic, churn and fault recovery |
| `make lifecycle ARGS=1000` | Repeat interrupted reads and TLS close/drain races |
| `make javadoc` | Generate API documentation under `build/javadoc` |
| `make distribution` | Build binary, source and Javadoc JARs |
| `make check-build` | Test incremental builds and failure recovery in a temporary tree |
| `make clean` | Remove generated files under `build` |

`make -j4 package test-classes distribution` can build independent outputs in
parallel. Run `make clean` separately before a fresh build. Optional diagnostics
also have `probe`, `capacity`, `network`, `compare`, `key-updates` and
`key-update-trace` targets; pass their arguments in `ARGS`. See
[the optional contributor diagnostics](FutureWork/Benchmarks/README.md) for
workloads and argument meanings. These are tools for investigating the library,
not requirements for applications using it.
For arguments containing spaces, quote each argument inside `ARGS`, for example
`make compare ARGS='"/path with spaces/tls-channel.jar" 8 100 heap'`.

The older `bash build.sh ...` commands delegate compilation to make and remain
available for existing scripts. No target publishes an artifact.

## Incremental compilation

jdep reads the compiled outer and nested classes and writes `.d` dependencies.
Make marks the affected classes, then compiles their sources together in one javac
invocation. The successful compilation marker is written only after dependency
generation succeeds. A failed batch forces a complete retry. Old nested classes
are removed when their source is recompiled; source-list or compiler-option
changes trigger a fresh compilation so removed classes cannot enter the JAR.
Tests are compiled as a batch when their sources or the library change.

The build supports one top-level class per source file in its package directory,
with nested classes permitted. `package-info.java` is included in compilation and
documentation without requiring javac to emit a class file for it. A no-change
build leaves compiled files and artifacts untouched.

## Maven alternative

```sh
mvn clean verify
mvn clean install
```

Both run the same standalone conformance suite. `install` additionally installs
`com.fudco:selectable-tls:0.1.0` in the local Maven repository. Maven writes
under `target`; make writes under `build`. These directories are independent.

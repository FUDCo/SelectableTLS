# Using the API

Package: `com.fudco.selectabletls`. Release coordinates:
`com.fudco:selectable-tls:0.1.0`. See [RELEASE.md](RELEASE.md) for installation.

Create a `TlsProvider` with an initialized `SSLContext`, then obtain its
`TlsSocketChannel`, `TlsServerSocketChannel`, and `TlsSelector` instances.
The context supplies keys and trust managers using ordinary JSSE configuration.
The library does not replace the JVM's global SelectorProvider.

For a client, `openSocketChannel("server.example.com")` specifies the identity
that the certificate must authenticate, independently of the address passed to
`connect`. The no-argument factory uses that address's host string instead.
Hostname verification uses JSSE's HTTPS endpoint-identification rules. Loading a
trusted certificate does not silently bypass identity verification.

Channel `connect` and `finishConnect` complete TCP establishment. TLS negotiation
starts automatically and may still be in progress. Use `handshakeComplete()`
and `session()` for authentication/session information. A write can queue bounded
plaintext before authentication; it is not sent as application data until the
handshake succeeds. Application OP_WRITE readiness is withheld until negotiation
finishes. Errors wake interested application selectors and are reported by I/O.

Configure the provider before opening connections:

- `setEnabledProtocols`: TLS 1.3 and TLS 1.2 are enabled by default.
- `setNeedClientAuth`: requires verified client certificates on subsequently
  accepted connections; defaults to false.
- `setHandshakeTimeout`: positive Duration, up to one day, default 30 seconds.
  Covers TCP establishment and initial authentication.
- `setShutdownTimeout`: positive Duration, up to one day, default 30 seconds.
  Covers subsequent output-shutdown/close drains.
- The constructor's queue-limit argument bounds pending application output,
  default 65,536 bytes, minimum 32,768 bytes.
- The four-argument constructor also selects positive delegated-task thread and
  queue limits; defaults are two workers and 1,024 queued batches.

Use normal `SelectionKey` interests and selected-key removal. TLS handshakes,
delegated tasks and pending ciphertext do not require empty writes or forced
application read interest. Decrypted buffered bytes remain readable/selectable.
Native plaintext socket/listener channels can share the TLS selector. A TLS
channel requires a matching TLS-aware selector; it cannot portably register with
an arbitrary stock JDK selector through public APIs.
Native pipes and datagrams can share the selector too. TLS factories support
explicit INET and INET6 address families; Unix-domain TLS factories are not provided.

One reader and one writer can operate concurrently. Blocking channels and their
socket streams wait independently; socket read timeouts do not close the channel.
Scattering/gathering operations preserve positions and return partial progress.

`shutdownInput()` produces application EOF while permitting TLS control reads.
`shutdownOutput()` drains accepted writes and close_notify, leaving reads open
where the negotiated TLS version permits. `close()` closes the application channel
immediately and drains in the background until both close notifications complete
or the shutdown deadline expires. It discards inbound application data during
that drain; waiting for peer closure avoids resetting a socket with unread data.
`abort()` discards pending data and closes the transport immediately. SO_LINGER=0
also requests an abort. Positive linger on a blocking channel makes the closing
caller wait for the TLS close exchange, bounded by the shorter of the linger
interval and the configured shutdown timeout. The shared reactor keeps running.
An explicit abort or provider shutdown interrupts that wait. Positive linger on
a nonblocking channel leaves close asynchronous under the normal shutdown timeout.
The library owns this option rather than enabling blocking native close on its
shared reactor. Values above 65,535 seconds are clamped; negative values disable
linger. Do not infer peer application acknowledgment from close completion.

Pending I/O retains the blocking mode captured when it began. Later mode changes
affect subsequent operations. Selection snapshots interest changes at the start
of each operation; changes made while it waits apply to the next selection.

Close the provider at application shutdown. It aborts its TLS sockets and closes
its listeners/selectors/shared workers. It leaves caller-owned native channels
open, including channels registered with its selectors. Closing the provider
immediately after channel.close can therefore cancel a pending graceful drain;
applications needing orderly exchange should finish shutdown before provider close.

The implementation uses one transport thread and at most two delegated
task workers per provider by default, with at most 1,024 queued task batches.
Task submission failure fails the affected connection. Applications control
established-connection idle expiry, admission limits and SSLContext session-cache
settings. See [the architecture](DESIGN.md) for buffer and executor bounds.

Build with `make test` or `mvn clean install`. The latter runs the same
standalone conformance suite in a separate JVM and installs the
artifact locally. Neither command publishes anything. Select a JDK with JAVA_HOME;
see [BUILD.md](BUILD.md) for the make/jdep setup.

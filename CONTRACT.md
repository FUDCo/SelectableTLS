# Channel and selector contract

SelectableTLS implements Java NIO socket-channel interfaces with TLS transport,
peer authentication and bounded asynchronous shutdown. The
[API guide](API.md) describes configuration and use; [the architecture](DESIGN.md)
explains how transport progress and application I/O interact.

## Channels and connection establishment

`TlsSocketChannel` and `TlsServerSocketChannel` support blocking and nonblocking
operations, socket adapters, socket options, address queries and
scattering/gathering I/O. One reader and one writer may operate concurrently.
Reads waiting for input do not prevent otherwise possible writes from progressing.

`connect()` and `finishConnect()` complete TCP establishment. TLS authentication
then progresses automatically. `handshakeComplete()` and `session()` expose its
state. Writes may queue a bounded amount of plaintext during negotiation; the
library sends application data only after authentication succeeds. Application
write readiness begins after authentication. Failures wake interested selectors
and are reported by I/O operations.

Nonblocking operations preserve zero/partial transfers and buffer positions.
Readiness requests do not use special exceptions. Blocking operations support
interruption and asynchronous close; pending operations retain the blocking mode
captured when they began. Socket read timeouts do not close the channel.

Clients authenticate the peer name using JSSE endpoint identification and the
SSLContext's trust configuration. Servers can require client certificates. TLS
authentication does not replace application authorization.

## Selection

TLS channels register with `TlsSelector`, supplied by their `TlsProvider`.
Public Java APIs do not allow these channels to register portably with arbitrary
stock JDK selectors. Native socket channels, server sockets, pipes and datagrams
can share a TLS selector. The provider does not replace the JVM's global provider.

Application interests describe application I/O. Handshakes, delegated tasks and
pending ciphertext progress without empty writes or forced application read
interest. Buffered plaintext remains readable/selectable without a fresh network
event. Readiness remains a hint; applications must handle zero and partial transfers.

Keys support attachments, cancellation and normal selected-key removal. Zero,
read-only, write-only and combined interests are supported. Interest changes are
captured at the start of a selection operation; changes made while it waits apply
to the next selection. A channel can register with multiple selectors while one
reactor owns its TLS engine.

## Shutdown and ownership

`shutdownInput()` produces application EOF and discards subsequent inbound
application data while allowing TLS control reads to continue.
`shutdownOutput()` drains accepted output and sends TLS `close_notify`, retaining
input where the negotiated protocol permits. TLS 1.2 does not provide the same
independent half-close behavior as TLS 1.3. A transport EOF without `close_notify`
is reported as a TLS failure rather than clean EOF.

`close()` closes the application channel immediately and drains accepted output
in the background. It discards inbound application data during the close exchange
and waits for peer closure, bounded by the shutdown timeout. Positive SO_LINGER
on a blocking channel makes the caller wait for that exchange, bounded by the
shorter of linger and shutdown timeout. Positive linger on a nonblocking channel
leaves close asynchronous. `abort()` and SO_LINGER=0 discard pending output and
close the transport immediately. Closure does not prove peer application receipt.

Closing a provider aborts its TLS connections and closes its listeners, selectors
and shared workers. Caller-owned native channels remain open. Applications that
require graceful delivery must complete their shutdown exchange before closing
the provider.

## Resource bounds and supported scope

A provider uses one shared transport thread and a bounded delegated-task executor;
connections do not require individual threads. Pending output, decrypted input,
ciphertext and cached buffers are bounded. Backpressure can limit protocol
progress when an application stops consuming data. Handshake and shutdown
timeouts bound those phases; established-connection idle expiry and admission
limits belong to the application. Configuration defaults are listed in the
[API guide](API.md).

The library supports Java 17 and later, TLS 1.2/1.3 and INET/INET6 TLS sockets.
Unix-domain TLS and urgent/OOB data are outside its supported scope. Memory,
throughput and connection capacity depend on the application, SSLContext,
JDK and deployment environment; the API makes no fixed capacity guarantee.

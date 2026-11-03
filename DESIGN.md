# Architecture

Each `TlsProvider` owns one transport reactor and a bounded executor for JSSE
handshake tasks. The reactor owns `SSLEngine` progression and native socket
readiness. Application channels expose bounded plaintext queues; reads and writes
wait independently. This keeps TLS progress independent of application selection
interests and avoids holding application locks across network waits.

## Selection and engine ownership

TLS selectors combine native plaintext registrations with TLS application
readiness. State changes wake selectors through `Selector.wakeup()` and queued
key updates. Only keys whose readiness needs attention are revisited; idle
connections are not scanned on every application selection. A channel can
register with multiple selectors while one reactor owns its engine.

Application interests are distinct from transport interests. A handshake may
require transport reads even when an application is waiting only to write.
Pending ciphertext is flushed automatically, and buffered plaintext produces
application read readiness without another transport event.

## Connection and authentication

`connect()` and `finishConnect()` describe TCP establishment. TLS negotiation
starts automatically and is observable through `handshakeComplete()` and
`session()`. Writes can queue within the configured bound during negotiation;
application data crosses the TLS boundary only after authentication succeeds.

Client engines use HTTPS endpoint identification against the explicit peer name
or the connect address's host string. The supplied SSLContext provides keys and
trust managers. Servers can require client certificates through
`setNeedClientAuth()` before accepting connections.

## Shutdown and deadlines

`close()` closes the application channel immediately, then drains accepted
plaintext and exchanges `close_notify` asynchronously. It discards inbound
application data during the exchange and waits for peer closure before releasing
the transport, avoiding TCP resets caused by unread peer data. The transport's
lifetime extends beyond the application channel's lifetime while this drain runs.
`abort()` discards pending data and releases the transport immediately.

`shutdownOutput()` drains accepted output and sends `close_notify` while retaining
reads where the TLS protocol permits. Its output-drain completion means ciphertext
and the notification have been handed to TCP; it does not imply peer application
receipt or completion of the reciprocal shutdown. `shutdownInput()` ends
application reads while permitting TLS control traffic to continue.

Initial authentication, including TCP connect, and output shutdown each have a
30-second default deadline, configurable up to one day. Expiry closes the
transport and wakes application operations with `SocketTimeoutException`.
An ordered timer set avoids scanning established idle connections.

Closing the provider aborts its connections and releases its listeners, selectors
and workers. Native channels registered with its selectors remain caller-owned.
See [the channel contract](CONTRACT.md) for blocking linger and ownership details.

## Buffering and execution limits

By default, a provider uses two delegated-task workers with at most 1,024 queued
task batches. Rejection fails the affected connection. Custom trust managers may
block a worker; a connection deadline cannot forcibly stop application code.

Input buffering permits one decrypted record and a bounded ciphertext buffer.
Output buffering permits one application queue and one encrypted record. The
application queue defaults to 64 KiB per connection and has a 32 KiB minimum.
Backpressure stops further application writes when that queue fills.

The provider caches at most 64 buffers of each of two sizes: 32 KiB records and
the configured application queue size. At the default queue size this is at most
6 MiB of cached buffers, in addition to in-use buffers and JSSE state. Released
heap buffers retain bytes internally until overwritten; positions and limits
prevent exposure through the channel API. Memory zeroization is not provided.

The package and automatic module name are `com.fudco.selectabletls`. The library
uses public Java APIs and delegates cryptography and certificate processing to
JSSE. Build setup is described in [BUILD.md](BUILD.md).

# Echo example

Run `make examples` from the project root. This compiles the example,
creates a temporary localhost identity with keytool, runs a selector-based server
and a blocking client, verifies the echo and clean TLS EOF, and stops the server.
See [build setup](../BUILD.md) for prerequisites. Temporary credentials are deleted
afterward.

`TlsEcho.java` uses the standard JSSE default context. In your application, supply
an initialized SSLContext to TlsProvider, or configure the JVM's key/trust stores
before the default context is initialized. The shell smoke test shows the latter
with disposable test credentials; its password is not a deployment credential.
The client authenticates the supplied hostname. No trust-all manager is used.

The server demonstrates selected-key removal, partial writes, bounded application
buffers and read backpressure. Application interest bits describe application I/O;
the provider handles handshakes and ciphertext automatically. The client waits for
the reply before output shutdown and consumes peer EOF before closing the provider.

This example binds loopback and runs until interrupted. It does not implement
application authentication, admission limits or idle-client expiry. A deployed
service should add those policies. Provider shutdown aborts remaining connections;
finish application shutdown exchanges before closing it when graceful delivery is
required. See [the API guide](../API.md) for the lifecycle and ownership contract.

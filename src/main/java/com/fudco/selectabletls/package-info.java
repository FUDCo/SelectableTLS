/**
 * TLS-aware Java NIO channels using public JSSE and selector APIs.
 *
 * <p>Create a {@link com.fudco.selectabletls.TlsProvider} with an initialized
 * {@link javax.net.ssl.SSLContext}. It owns one shared transport reactor and a
 * bounded delegated-task executor. It does not replace the global NIO provider.
 * TLS channels require its selector; ordinary native channels can share it.
 *
 * <p>Connect completion describes TCP establishment, not authentication. TLS
 * progresses automatically and write readiness starts after authentication.
 * Client certificate names are verified against the configured peer name using
 * JSSE endpoint identification. Application writes may queue before
 * authentication within the provider's buffer limit, but are not transmitted
 * until it succeeds.
 *
 * <p>Default channel close drains accepted output asynchronously under a
 * deadline; abort discards it immediately. Closing the provider aborts its
 * remaining TLS channels, so applications must finish orderly exchanges before
 * provider close when delivery matters. Readiness is a hint and applications
 * must handle partial and zero transfers. This API currently has development,
 * not release, status.
 */
package com.fudco.selectabletls;

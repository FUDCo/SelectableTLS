package com.fudco.selectabletls;

import java.io.Closeable;
import java.io.IOException;
import java.net.ProtocolFamily;
import java.net.StandardProtocolFamily;
import java.nio.channels.ClosedChannelException;
import java.nio.channels.DatagramChannel;
import java.nio.channels.Pipe;
import java.nio.channels.spi.SelectorProvider;
import java.time.Duration;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;

/**
 * Explicit TLS provider; does not replace the JVM's default networking
 * provider.
 */
public final class TlsProvider extends SelectorProvider
    implements AutoCloseable
{

    /** Application-supplied key, trust and session configuration. */
    private final SSLContext myContext;

    /** Shared transport reactor for this provider's TLS channels. */
    final Reactor myReactor;

    /** Maximum queued plaintext output bytes per connection. */
    final int myQueueLimit;

    /** Bounded cache of reusable connection buffers. */
    final BufferPool myBuffers;

    /** Native provider used without changing the JVM default. */
    private final SelectorProvider myTransport = SelectorProvider.provider();

    /** Owned channels and selectors to release during shutdown. */
    private final Set<Closeable> myResources = ConcurrentHashMap.newKeySet();

    /** Atomic gate preventing new resources after shutdown begins. */
    private final AtomicBoolean myClosed = new AtomicBoolean();

    /** Whether subsequently accepted peers must present a certificate. */
    private volatile boolean myNeedClientAuth;

    /** Protocol versions enabled on subsequently created engines. */
    private volatile String[] myProtocols = { "TLSv1.3", "TLSv1.2" };

    /** Time allowed for TCP connection and initial TLS authentication. */
    private volatile long myHandshakeTimeoutNanos =
        Duration.ofSeconds(30).toNanos();

    /** Time allowed for output drain and the TLS close exchange. */
    private volatile long myShutdownTimeoutNanos =
        Duration.ofSeconds(30).toNanos();

    /**
     * Creates a provider with a 64 KiB output queue, two task workers and 1,024
     * queued task batches.
     *
     * @param context  Key, trust and session configuration for TLS engines.
     * @throws IOException if the transport selector cannot be opened.
     */
      public
    TlsProvider(SSLContext context) throws IOException
    {
        this(context, 65536);
    }

    /**
     * Creates a provider with an output queue of at least 32 KiB per connection
     * and default task bounds.
     *
     * @param context  Key, trust and session configuration for TLS engines.
     * @param queueLimit  Maximum queued plaintext output bytes per connection.
     * @throws IOException if the transport selector cannot be opened.
     * @throws IllegalArgumentException if queueLimit is less than 32768.
     */
      public
    TlsProvider(SSLContext context, int queueLimit) throws IOException
    {
        this(context, queueLimit, 2, 1024);
    }

    /**
     * Creates a provider with explicit per-connection and delegated-task
     * bounds.
     *
     * @param context  Key, trust and session configuration for TLS engines.
     * @param queueLimit  Maximum queued plaintext output bytes per connection.
     * @param taskThreads  Number of workers for JSSE delegated tasks.
     * @param queuedTasks  Maximum waiting batches of delegated tasks.
     * @throws IOException if the transport selector cannot be opened.
     * @throws IllegalArgumentException if queueLimit is less than 32768 or
     * either task bound is less than one.
     */
      public
    TlsProvider(SSLContext context, int queueLimit, int taskThreads,
        int queuedTasks) throws IOException
    {
        myContext = Objects.requireNonNull(context);
        if (queueLimit < 32768) {
            throw new IllegalArgumentException(
                "queueLimit must be at least 32768");
        }
        if (taskThreads < 1 || queuedTasks < 1) {
            throw new IllegalArgumentException("task bounds must be positive");
        }
        myQueueLimit = queueLimit;
        myBuffers = new BufferPool(queueLimit);
        myReactor = new Reactor(taskThreads, queuedTasks);
    }

    /**
     * Closes this provider's TLS channels/listeners/selectors and shared
     * workers.
     *
     * @throws IOException if a resource cannot be closed.
     */
    @Override
      public void
    close() throws IOException
    {
        if (!myClosed.compareAndSet(false, true)) {
            return;
        }
        IOException failure = null;
        for (Closeable resource : myResources) {
            try {
                if (resource instanceof TlsSocketChannel channel) {
                    channel.abort();
                } else {
                    resource.close();
                }
            } catch (IOException error) {
                if (failure == null) {
                    failure = error;
                } else {
                    failure.addSuppressed(error);
                }
            }
        }
        try {
            myReactor.close();
        } catch (IOException error) {
            if (failure == null) {
                failure = error;
            } else {
                failure.addSuppressed(error);
            }
        }
        if (failure != null) {
            throw failure;
        }
    }

    /**
     * Create a role-specific engine with verified client identity or the
     * configured client-auth requirement.
     */
      SSLEngine
    engine(boolean client, String peer, int port)
    {
        SSLEngine engine =
            client ? myContext.createSSLEngine(peer, port) :
                myContext.createSSLEngine();
        engine.setUseClientMode(client);
        SSLParameters parameters = engine.getSSLParameters();
        parameters.setProtocols(myProtocols);
        if (client) {
            parameters.setEndpointIdentificationAlgorithm("HTTPS");
        } else {
            parameters.setNeedClientAuth(myNeedClientAuth);
        }
        engine.setSSLParameters(parameters);
        return engine;
    }

    /**
     * Reject factories after provider shutdown or transport-reactor failure.
     */
      private void
    ensureOpen() throws IOException
    {
        if (myClosed.get()) {
            throw new ClosedChannelException();
        }
        myReactor.ensureOpen();
    }

    /**
     * Return the configured bound for TCP connection and initial
     * authentication.
     */
      long
    handshakeTimeoutNanos()
    {
        return myHandshakeTimeoutNanos;
    }

    /** Reject address families without supported Internet TLS transports. */
      private static void
    internetFamily(ProtocolFamily family)
    {
        Objects.requireNonNull(family);
        if (family != StandardProtocolFamily.INET && family !=
            StandardProtocolFamily.INET6)
        {
            throw new UnsupportedOperationException(
                "TLS socket factories support INET and INET6");
        }
    }

    /**
     * {@inheritDoc} Native channels returned by these pass-through factories
     * remain caller-owned.
     */
    @Override
      public DatagramChannel
    openDatagramChannel() throws IOException
    {
        ensureOpen();
        return myTransport.openDatagramChannel();
    }

    /** {@inheritDoc} */
    @Override
      public DatagramChannel
    openDatagramChannel(ProtocolFamily family) throws IOException
    {
        ensureOpen();
        return myTransport.openDatagramChannel(family);
    }

    /** {@inheritDoc} */
    @Override
      public Pipe
    openPipe() throws IOException
    {
        ensureOpen();
        return myTransport.openPipe();
    }

    /** {@inheritDoc} */
    @Override
      public TlsSelector
    openSelector() throws IOException
    {
        ensureOpen();
        return own(new TlsSelector(this, myTransport.openSelector()));
    }

    /** {@inheritDoc} */
    @Override
      public TlsServerSocketChannel
    openServerSocketChannel() throws IOException
    {
        ensureOpen();
        return own(new TlsServerSocketChannel(this,
            myTransport.openServerSocketChannel()));
    }

    /** {@inheritDoc} */
    @Override
      public TlsServerSocketChannel
    openServerSocketChannel(ProtocolFamily family) throws IOException
    {
        internetFamily(family);
        ensureOpen();
        return own(new TlsServerSocketChannel(this,
            myTransport.openServerSocketChannel(family)));
    }

    /** {@inheritDoc} */
    @Override
      public TlsSocketChannel
    openSocketChannel() throws IOException
    {
        ensureOpen();
        return own(new TlsSocketChannel(this, myTransport.openSocketChannel(),
            null));
    }

    /**
     * Set the authenticated TLS peer name independently of the network address.
     *
     * @param peerName  DNS name or IP address to verify in the certificate.
     * @return An unconnected TLS channel owned by this provider.
     * @throws IOException if the provider is closed or creation fails.
     */
      public TlsSocketChannel
    openSocketChannel(String peerName) throws IOException
    {
        Objects.requireNonNull(peerName);
        ensureOpen();
        return own(new TlsSocketChannel(this, myTransport.openSocketChannel(),
            peerName));
    }

    /** {@inheritDoc} */
    @Override
      public TlsSocketChannel
    openSocketChannel(ProtocolFamily family) throws IOException
    {
        internetFamily(family);
        ensureOpen();
        return own(new TlsSocketChannel(this,
            myTransport.openSocketChannel(family), null));
    }

    /**
     * Select an Internet address family and independently authenticated peer
     * name.
     *
     * @param family  INET or INET6 transport address family.
     * @param peerName  DNS name or IP address to verify in the certificate.
     * @return An unconnected TLS channel owned by this provider.
     * @throws IOException if the provider is closed or creation fails.
     * @throws UnsupportedOperationException if the family is unsupported.
     */
      public TlsSocketChannel
    openSocketChannel(ProtocolFamily family, String peerName) throws IOException
    {
        internetFamily(family);
        Objects.requireNonNull(peerName);
        ensureOpen();
        return own(new TlsSocketChannel(this,
            myTransport.openSocketChannel(family), peerName));
    }

    /**
     * Register a resource, releasing it if provider shutdown raced its
     * creation.
     */
      <T extends Closeable> T
    own(T resource) throws IOException
    {
        myResources.add(resource);
        try {
            ensureOpen();
        } catch (IOException error) {
            myResources.remove(resource);
            try {
                if (resource instanceof TlsSocketChannel channel) {
                    channel.abort();
                } else {
                    resource.close();
                }
            } catch (IOException cleanup) {
                error.addSuppressed(cleanup);
            }
            throw error;
        }
        return resource;
    }

    /** Remove a resource after its final transport or selector release. */
      void
    released(Closeable resource)
    {
        myResources.remove(resource);
    }

    /**
     * Protocols applied to subsequently created engines; validated by JSSE.
     *
     * @param protocols  Protocol version names supported by the SSL context.
     * @throws IllegalArgumentException if a protocol is unsupported.
     */
      public void
    setEnabledProtocols(String... protocols)
    {
        Objects.requireNonNull(protocols);
        SSLEngine probe = myContext.createSSLEngine();
        probe.setEnabledProtocols(protocols);
        myProtocols = protocols.clone();
    }

    /**
     * Bounds transport connection and initial TLS negotiation for new
     * connections.
     *
     * @param timeout  Positive duration no greater than one day.
     * @throws IllegalArgumentException if timeout is outside that range.
     */
      public void
    setHandshakeTimeout(Duration timeout)
    {
        myHandshakeTimeoutNanos = timeoutNanos(timeout);
    }

    /**
     * Controls engines for connections subsequently accepted by this provider.
     *
     * @param required  Whether accepted peers must present a certificate.
     */
      public void
    setNeedClientAuth(boolean required)
    {
        myNeedClientAuth = required;
    }

    /**
     * Bounds output drain and close_notify after subsequent shutdownOutput or
     * close calls.
     *
     * @param timeout  Positive duration no greater than one day.
     * @throws IllegalArgumentException if timeout is outside that range.
     */
      public void
    setShutdownTimeout(Duration timeout)
    {
        myShutdownTimeoutNanos = timeoutNanos(timeout);
    }

    /** Return the configured bound for output drain and TLS closure. */
      long
    shutdownTimeoutNanos()
    {
        return myShutdownTimeoutNanos;
    }

    /**
     * Validate a positive timeout of at most one day and convert it to
     * nanoseconds.
     */
      private static long
    timeoutNanos(Duration timeout)
    {
        Objects.requireNonNull(timeout);
        if (timeout.isNegative() || timeout.isZero() ||
            timeout.compareTo(Duration.ofDays(1)) > 0)
        {
            throw new IllegalArgumentException(
                "timeout must be positive and at most one day");
        }
        return timeout.toNanos();
    }
}

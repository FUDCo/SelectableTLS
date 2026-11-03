package com.fudco.selectabletls;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketAddress;
import java.net.SocketException;
import java.net.SocketOption;
import java.net.SocketTimeoutException;
import java.net.StandardSocketOptions;
import java.nio.ByteBuffer;
import java.nio.channels.AlreadyConnectedException;
import java.nio.channels.AsynchronousCloseException;
import java.nio.channels.ClosedByInterruptException;
import java.nio.channels.ClosedChannelException;
import java.nio.channels.ConnectionPendingException;
import java.nio.channels.IllegalBlockingModeException;
import java.nio.channels.NoConnectionPendingException;
import java.nio.channels.NotYetConnectedException;
import java.nio.channels.SelectionKey;
import java.nio.channels.SocketChannel;
import java.nio.channels.UnsupportedAddressTypeException;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicBoolean;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLSession;

/** TLS byte stream driven by a shared transport reactor. */
public final class TlsSocketChannel extends SocketChannel {

    /** Read-only empty source for TLS control records. */
    private static final ByteBuffer EMPTY =
        ByteBuffer.allocate(0).asReadOnlyBuffer();

    /** Nonblocking transport accessed by the shared reactor. */
    final SocketChannel myRaw;

    /** Whether a reactor update is already queued for this channel. */
    final AtomicBoolean myScheduled = new AtomicBoolean();

    /** Provider responsible for transport, workers and buffer reuse. */
    private final TlsProvider myOwner;

    /** Explicit client identity, or null to use the connect address. */
    private final String myPeerName;

    /** Monitor guarding engine state, buffers and application waiters. */
    private final Object myState = new Object();

    /** Serializes reads without excluding an independent writer. */
    private final Object myReader = new Object();

    /** Serializes writes without excluding an independent reader. */
    private final Object myWriter = new Object();

    /** Application registrations notified when TLS readiness changes. */
    private final List<TlsSelector.Key> myKeys = new CopyOnWriteArrayList<>();

    /** JSSE engine progressed by the reactor and its delegated tasks. */
    private SSLEngine myEngine;

    /** Whether TCP establishment has completed for the application. */
    private boolean myConnected;

    /** Whether the application has a pending nonblocking connect. */
    private boolean myPending;

    /** Whether initial engine negotiation has been started. */
    private boolean myStarted;

    /** Whether delegated tasks temporarily own engine progression. */
    private boolean myTaskRunning;

    /** Whether the initial TLS authentication has completed. */
    private boolean myHandshakeComplete;

    /** Whether the TLS input direction has reached orderly EOF. */
    private boolean myInputEnded;

    /** Whether the application explicitly discarded its input direction. */
    private boolean myInputShutdown;

    /** Whether further application output is prohibited. */
    private boolean myOutputEnded;

    /** Whether the reactor has shut down the raw output direction. */
    private boolean myTransportOutputEnded;

    /** Whether unwrap needs fresh ciphertext rather than buffered records. */
    private boolean myNeedNetworkRead = true;

    /** Remembers explicit shutdownOutput calls for the Socket adapter. */
    private boolean myApplicationOutputShutdown;

    /** Whether an application-closed channel is finishing its TLS exchange. */
    private boolean myDrainingClose;

    /** Rejects I/O while abort releases transport before logical closure. */
    private volatile boolean myAbortRequested;

    /**
     * Linger belongs to the logical channel. A positive native linger on the
     * reactor's nonblocking socket could block every connection during close.
     */
    private int myLinger = -1;

    /** First transport or TLS failure to report to application operations. */
    private IOException myFailure;

    /** Monotonic deadline for TCP establishment and initial authentication. */
    private long myHandshakeDeadline;

    /** Monotonic deadline for output shutdown or close drain. */
    private long myShutdownDeadline;

    /** Ciphertext in write mode awaiting unwrap or more network input. */
    private ByteBuffer myEncryptedIn;

    /** Ciphertext in read mode awaiting transport output. */
    private ByteBuffer myEncryptedOut;

    /** Decrypted bytes in read mode awaiting application consumption. */
    private ByteBuffer myPlainIn;

    /** Accepted plaintext in write mode awaiting encryption. */
    private ByteBuffer myPlainOut;

    /** Lazily created Socket view sharing this channel's lifecycle. */
    private Socket mySocket;

    /** Wrap a provider-owned transport while keeping native I/O nonblocking. */
    TlsSocketChannel(TlsProvider owner, SocketChannel raw,
        String peerName) throws IOException
    {
        super(owner);
        myOwner = owner;
        myRaw = raw;
        myPeerName = peerName;
        raw.configureBlocking(false);
    }

    /**
     * Immediately discard pending output and close the transport, without
     * close_notify.
     *
     * @throws IOException if transport or channel closure fails.
     */
      public void
    abort() throws IOException
    {
        myAbortRequested = true;
        /*
         * Release a concurrent lingering close before acquiring the channel's
         * close lock. Provider shutdown must not wait for that linger interval.
         */
        try {
            synchronized (myState) {
                abortTransport();
            }
        } finally {
            close();
        }
    }

    /**
     * Attempt an abortive TCP close while guaranteeing transport release if
     * linger cannot be changed.
     */
      private void
    abortTransport() throws IOException
    {
        try {
            if (myRaw.isOpen() && !myTransportOutputEnded) {
                myRaw.setOption(StandardSocketOptions.SO_LINGER, 0);
            }
        } catch (IOException ignored) {
            /*
             * Some systems reject changing linger on a transport already shut
             * down by its peer. Resource release must still happen.
             */
        } finally {
            closeTransport();
        }
    }

    /**
     * Wrap an accepted transport, create its server engine and transfer
     * ownership to the provider.
     */
      static TlsSocketChannel
    accepted(TlsProvider owner, SocketChannel raw) throws IOException
    {
        TlsSocketChannel channel = new TlsSocketChannel(owner, raw, null);
        channel.myConnected = true;
        channel.myEngine = owner.engine(false, null, -1);
        channel.myHandshakeDeadline =
            System.nanoTime() + owner.handshakeTimeoutNanos();
        owner.own(channel);
        owner.myReactor.add(channel);
        return channel;
    }

    /**
     * Track an application selector registration for readiness notification.
     */
      void
    addKey(TlsSelector.Key key)
    {
        myKeys.add(key);
    }

    /**
     * Wait on the channel state monitor, deferring interrupt-driven close until
     * the monitor is released.
     */
      private void
    awaitChange() throws IOException
    {
        try {
            myState.wait();
        } catch (InterruptedException error) {
            /*
             * Restore interruption only after releasing state: interrupt's
             * close hook takes AbstractInterruptibleChannel's close lock before
             * this monitor.
             */
            throw new ClosedByInterruptException();
        }
    }

    /**
     * Wait on the channel state monitor, deferring interrupt-driven close until
     * the monitor is released.
     */
      private void
    awaitChange(long deadline) throws IOException
    {
        if (deadline == 0) {
            awaitChange();
            return;
        }
        long remaining = deadline - System.nanoTime();
        if (remaining <= 0) {
            throw new SocketTimeoutException("TLS read timed out");
        }
        try {
            myState.wait(Math.max(1, (remaining + 999999) / 1_000_000));
        } catch (InterruptedException error) {
            throw new ClosedByInterruptException();
        }
    }

    /** {@inheritDoc} */
    @Override
      public TlsSocketChannel
    bind(SocketAddress local) throws IOException
    {
        synchronized (myState) {
            checkOpen();
            myRaw.bind(local);
            return this;
        }
    }

    /**
     * Require an open, failure-free channel with completed TCP establishment.
     */
      private void
    checkConnected() throws IOException
    {
        checkOpen();
        if (!myConnected) {
            throw new NotYetConnectedException();
        }
    }

    /**
     * Fail the transport when its earliest active handshake or shutdown
     * deadline expires.
     */
      void
    checkDeadline(long now)
    {
        synchronized (myState) {
            long deadline = nextDeadline();
            if (deadline != 0 && now - deadline >= 0) {
                fail(new SocketTimeoutException(deadline ==
                    myShutdownDeadline ? "TLS output shutdown timed out" :
                    "TLS handshake timed out"));
            }
        }
    }

    /**
     * Reject closed, aborting or failed channels before accepting application
     * operations.
     */
      private void
    checkOpen() throws IOException
    {
        if (!isOpen()) {
            throw new ClosedChannelException();
        }
        /*
         * abort releases the raw transport before taking the channel close lock
         * so it can interrupt a lingering close. Reject I/O throughout that
         * gap, including writers woken when their queued buffers are discarded.
         */
        if (myAbortRequested) {
            throw new AsynchronousCloseException();
        }
        if (myFailure != null) {
            throw myFailure;
        }
    }

    /**
     * Release the raw socket and buffers, wake waiters and relinquish provider
     * ownership.
     */
      private void
    closeTransport() throws IOException
    {
        try {
            myRaw.close();
        } finally {
            myDrainingClose = false;
            releaseBuffers();
            notifyState();
            myOwner.myReactor.forget(this);
            myOwner.released(this);
        }
    }

    /** {@inheritDoc} */
    @Override
      public boolean
    connect(SocketAddress address) throws IOException
    {
        return connect(address, 0);
    }

    /**
     * Serialize TCP establishment with reads, writes and blocking-mode changes.
     */
      private boolean
    connect(SocketAddress address, long deadline) throws IOException
    {
        Objects.requireNonNull(address);
        synchronized (blockingLock()) {
            synchronized (myReader) {
                synchronized (myWriter) {
                    return connectLocked(address, deadline);
                }
            }
        }
    }

    /**
     * Begin TCP establishment and wait according to the operation's captured
     * blocking mode.
     */
      private boolean
    connectLocked(SocketAddress address, long deadline) throws IOException
    {
        boolean complete = false;
        boolean interrupted = false;
        boolean blocking = isBlocking();
        if (blocking) {
            begin();
        }
        try {
            synchronized (myState) {
                checkOpen();
                if (myConnected) {
                    throw new AlreadyConnectedException();
                }
                if (myPending) {
                    throw new ConnectionPendingException();
                }
                if (!(address instanceof InetSocketAddress inet)) {
                    throw new UnsupportedAddressTypeException();
                }
                myEngine =
                    myOwner.engine(true, myPeerName ==
                    null ? inet.getHostString() : myPeerName, inet.getPort());
                boolean immediate = myRaw.connect(address);
                myPending = !immediate;
                myConnected = immediate;
                myHandshakeDeadline =
                    System.nanoTime() + myOwner.handshakeTimeoutNanos();
                myOwner.myReactor.add(this);
                if (!isBlocking() || immediate) {
                    complete = true;
                    return immediate;
                }
                while (!myRaw.isConnected()) {
                    checkOpen();
                    awaitChange(deadline);
                }
                checkOpen();
                myConnected = true;
                myPending = false;
                complete = true;
                notifyState();
                return true;
            }
        } catch (ClosedByInterruptException error) {
            interrupted = true;
            Thread.currentThread().interrupt();
            close();
            throw error;
        } catch (IOException error) {
            complete = true;
            abort();
            throw error;
        } finally {
            if (blocking) {
                endOperation(complete, interrupted);
            }
        }
    }

    /**
     * End blocking I/O without losing an interruption observed by wait(). The
     * waiting thread can close the channel before the interrupting thread's
     * close hook runs. In that case end() knows only about the close, whereas
     * the operation has already observed the more specific interruption.
     */
      private void
    endOperation(boolean complete, boolean interrupted)
        throws AsynchronousCloseException
    {
        try {
            end(complete);
        } catch (AsynchronousCloseException error) {
            if (interrupted) {
                throw new ClosedByInterruptException();
            }
            throw error;
        }
    }

    /**
     * Retain the first failure, close the transport and wake application
     * operations.
     */
      void
    fail(Throwable error)
    {
        synchronized (myState) {
            if (myFailure == null) {
                myFailure =
                    error instanceof IOException io ? io : new IOException(
                    "TLS transport failed", error);
            }
            try {
                myRaw.close();
            } catch (IOException ignored) {
                /* retain original failure */
            }
            releaseBuffers();
            if (myDrainingClose) {
                myDrainingClose = false;
                myOwner.released(this);
            }
            notifyState();
        }
    }

    /** {@inheritDoc} */
    @Override
      public boolean
    finishConnect() throws IOException
    {
        synchronized (blockingLock()) {
            synchronized (myReader) {
                synchronized (myWriter) {
                    return finishConnectLocked();
                }
            }
        }
    }

    /**
     * Complete pending TCP establishment without waiting for TLS
     * authentication.
     */
      private boolean
    finishConnectLocked() throws IOException
    {
        boolean complete = false;
        boolean interrupted = false;
        boolean blocking = isBlocking();
        if (blocking) {
            begin();
        }
        try {
            synchronized (myState) {
                checkOpen();
                if (myConnected) {
                    complete = true;
                    return true;
                }
                if (!myPending) {
                    throw new NoConnectionPendingException();
                }
                if (!myRaw.isConnected() && !isBlocking()) {
                    complete = true;
                    return false;
                }
                while (!myRaw.isConnected()) {
                    checkOpen();
                    awaitChange();
                }
                checkOpen();
                myConnected = true;
                myPending = false;
                complete = true;
                notifyState();
                return true;
            }
        } catch (ClosedByInterruptException error) {
            interrupted = true;
            Thread.currentThread().interrupt();
            close();
            throw error;
        } catch (IOException error) {
            complete = true;
            abort();
            throw error;
        } finally {
            if (blocking) {
                endOperation(complete, interrupted);
            }
        }
    }

    /** {@inheritDoc} */
    @Override
      public SocketAddress
    getLocalAddress() throws IOException
    {
        synchronized (myState) {
            checkOpen();
            return myRaw.getLocalAddress();
        }
    }

    /** {@inheritDoc} */
    @Override
      public <T> T
    getOption(SocketOption<T> name) throws IOException
    {
        synchronized (myState) {
            checkOpen();
            return name == StandardSocketOptions.SO_LINGER ? name.type()
                .cast(myLinger) : myRaw.getOption(name);
        }
    }

    /** {@inheritDoc} */
    @Override
      public SocketAddress
    getRemoteAddress() throws IOException
    {
        synchronized (myState) {
            checkOpen();
            return myRaw.getRemoteAddress();
        }
    }

    /**
     * Reports completion of initial authentication; does not imply the channel
     * is still open.
     *
     * @return True once the initial TLS handshake has completed.
     */
      public boolean
    handshakeComplete()
    {
        synchronized (myState) {
            return myHandshakeComplete;
        }
    }

    /** {@inheritDoc} */
    @Override
      protected void
    implCloseSelectableChannel() throws IOException
    {
        boolean interrupted = false;
        try {
            synchronized (myState) {
                if (!myAbortRequested && myFailure == null && (myConnected ||
                    myPending) && myRaw.isOpen() && myLinger != 0)
                {
                    /*
                     * The channel closes immediately to callers. Keep its
                     * transport alive only to drain accepted output under the
                     * shutdown deadline.
                     */
                    myDrainingClose = true;
                    myOutputEnded = true;
                    myOwner.myBuffers.release(myPlainIn);
                    myPlainIn = null;
                    if (myShutdownDeadline == 0) {
                        myShutdownDeadline =
                            System.nanoTime() + myOwner.shutdownTimeoutNanos();
                    }
                    if (myLinger > 0 && isBlocking()) {
                        long lingerDeadline =
                            System.nanoTime() + myLinger * 1_000_000_000L;
                        myShutdownDeadline =
                            Math.min(myShutdownDeadline, lingerDeadline);
                    }
                    notifyState();
                    myOwner.myReactor.signal(this);
                    if (myLinger > 0 && isBlocking()) {
                        while (myDrainingClose && myRaw.isOpen()) {
                            long remaining =
                                myShutdownDeadline - System.nanoTime();
                            if (remaining <= 0) {
                                abortTransport();
                                break;
                            }
                            try {
                                myState.wait(Math.max(1, (remaining +
                                    999999) / 1_000_000));
                            } catch (InterruptedException error) {
                                interrupted = true;
                                abortTransport();
                                break;
                            }
                        }
                    }
                } else {
                    if (myAbortRequested || myLinger == 0) {
                        abortTransport();
                    } else {
                        closeTransport();
                    }
                }
            }
        } finally {
            if (interrupted) {
                Thread.currentThread().interrupt();
            }
        }
    }

    /** {@inheritDoc} */
    @Override
      protected void
    implConfigureBlocking(boolean block)
    {
        /*
         * Transport remains reactor-owned and nonblocking. Each application I/O
         * operation captures its mode so pending operations retain their
         * contract.
         */
    }

    /** {@inheritDoc} */
    @Override
      public boolean
    isConnected()
    {
        synchronized (myState) {
            return isOpen() && myConnected;
        }
    }

    /** {@inheritDoc} */
    @Override
      public boolean
    isConnectionPending()
    {
        synchronized (myState) {
            return isOpen() && myPending;
        }
    }

    /**
     * Test transport lifetime independently of the logical channel. Java marks
     * the channel closed before invoking our close handler; the reactor must
     * retain registration across that gap so the handler can drain output.
     */
      boolean
    isTransportOpen()
    {
        synchronized (myState) {
            return myRaw.isOpen();
        }
    }

    /**
     * Find the earliest applicable monotonic deadline, or zero when no timer is
     * needed.
     */
      long
    nextDeadline()
    {
        synchronized (myState) {
            if (!isTransportOpen() || myFailure != null) {
                return 0;
            }
            long handshake = myHandshakeComplete ? 0 : myHandshakeDeadline;
            long shutdown =
                myTransportOutputEnded &&
                !myDrainingClose ? 0 : myShutdownDeadline;
            return handshake == 0 ? shutdown : shutdown ==
                0 ? handshake : Math.min(handshake, shutdown);
        }
    }

    /**
     * Wake blocking operations and notify every registered application
     * selector.
     */
      private void
    notifyState()
    {
        myState.notifyAll();
        for (TlsSelector.Key key : myKeys) {
            key.mySelector.changed(key);
        }
    }

    /**
     * Advance bounded TLS and transport work while preserving duplex progress
     * and buffer limits.
     */
      void
    pump() throws IOException
    {
        synchronized (myState) {
            if (!isTransportOpen() || myFailure != null || myTaskRunning) {
                return;
            }
            if (myRaw.isConnectionPending() && !myRaw.finishConnect()) {
                return;
            }
            if (!myRaw.isConnected()) {
                return;
            }
            notifyState();
            if (!myStarted) {
                myEngine.beginHandshake();
                myStarted = true;
            }
            boolean favorRead = false;
            for (int turns = 0; turns < 32; turns++) {
                if (myEncryptedOut != null) {
                    myRaw.write(myEncryptedOut);
                    if (!myEncryptedOut.hasRemaining()) {
                        myOwner.myBuffers.release(myEncryptedOut);
                        myEncryptedOut = null;
                    }
                    /*
                     * A full TCP send buffer must not prevent independent
                     * reads.
                     */
                }
                SSLEngineResult.HandshakeStatus hs =
                    myEngine.getHandshakeStatus();
                if (hs == SSLEngineResult.HandshakeStatus.NEED_TASK) {
                    List<Runnable> batch = new ArrayList<>();
                    Runnable task;
                    while (true) {
                        task = myEngine.getDelegatedTask();
                        if (task == null) {
                            break;
                        }
                        batch.add(task);
                    }
                    if (batch.isEmpty()) {
                        throw new SSLException("NEED_TASK without a task");
                    }
                    myTaskRunning = true;
                    myOwner.myReactor.tasks(this, batch);
                    return;
                }
                if (hs == SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING &&
                    !myHandshakeComplete)
                {
                    myHandshakeComplete = true;
                    notifyState();
                }
                if (myOutputEnded && myPlainOut == null &&
                    myHandshakeComplete && !myEngine.isOutboundDone())
                {
                    myEngine.closeOutbound();
                }
                hs = myEngine.getHandshakeStatus();
                if (myEncryptedOut != null && hs ==
                    SSLEngineResult.HandshakeStatus.NEED_WRAP)
                {
                    return;
                }
                if (myEncryptedOut == null && (hs ==
                    SSLEngineResult.HandshakeStatus.NEED_WRAP || (hs ==
                    SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING &&
                    myHandshakeComplete && myPlainOut != null &&
                    !myEngine.isOutboundDone() && (!favorRead || myPlainIn !=
                    null || myInputEnded))))
                {
                    myEncryptedOut =
                        myOwner.myBuffers.acquire(myEngine.getSession()
                        .getPacketBufferSize());
                    ByteBuffer source =
                        myPlainOut == null ? EMPTY.duplicate() : myPlainOut;
                    if (myPlainOut != null) {
                        source.flip();
                    }
                    SSLEngineResult result =
                        myEngine.wrap(source, myEncryptedOut);
                    if (myPlainOut != null) {
                        source.compact();
                        if (source.position() == 0) {
                            myOwner.myBuffers.release(myPlainOut);
                            myPlainOut = null;
                        }
                    }
                    myEncryptedOut.flip();
                    if (result.getStatus() ==
                        SSLEngineResult.Status.BUFFER_OVERFLOW)
                    {
                        throw new SSLException(
                            "Unexpected wrap buffer overflow");
                    }
                    if (result.getHandshakeStatus() ==
                        SSLEngineResult.HandshakeStatus.FINISHED)
                    {
                        myHandshakeComplete = true;
                    }
                    if (hs == SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING) {
                        favorRead = true;
                    }
                    notifyState();
                    continue;
                }
                if (myEngine.isOutboundDone()) {
                    if (myPlainOut != null) {
                        throw new SSLException(
                            "TLS output closed before queued data drained");
                    }
                    myOutputEnded = true;
                    if (myEncryptedOut == null && !myTransportOutputEnded) {
                        myRaw.shutdownOutput();
                        myTransportOutputEnded = true;
                    }
                    notifyState();
                }
                /*
                 * Closing with unread inbound TLS records can reset the TCP
                 * connection (notably on Windows), discarding our final output
                 * at the peer. Drain/discard input through its close_notify,
                 * bounded by the close deadline, before releasing the socket.
                 */
                if (myDrainingClose && myTransportOutputEnded && myInputEnded) {
                    closeTransport();
                    return;
                }
                if (myInputEnded || myPlainIn != null) {
                    return;
                }
                if (myEncryptedIn == null) {
                    myEncryptedIn =
                        myOwner.myBuffers.acquire(myEngine.getSession()
                        .getPacketBufferSize());
                }
                int read = 0;
                if (myNeedNetworkRead && hs !=
                    SSLEngineResult.HandshakeStatus.NEED_UNWRAP_AGAIN)
                {
                    read = myRaw.read(myEncryptedIn);
                }
                if (read < 0) {
                    myEngine.closeInbound();
                    myInputEnded = true;
                    myOwner.myBuffers.release(myEncryptedIn);
                    myEncryptedIn = null;
                    notifyState();
                    return;
                }
                if (myEncryptedIn.position() == 0 && hs !=
                    SSLEngineResult.HandshakeStatus.NEED_UNWRAP_AGAIN)
                {
                    myOwner.myBuffers.release(myEncryptedIn);
                    myEncryptedIn = null;
                    scheduleOutput();
                    return;
                }
                ByteBuffer output =
                    myOwner.myBuffers.acquire(myEngine.getSession()
                    .getApplicationBufferSize());
                myEncryptedIn.flip();
                SSLEngineResult result;
                try {
                    result = myEngine.unwrap(myEncryptedIn, output);
                } catch (IOException | RuntimeException error) {
                    myOwner.myBuffers.release(output);
                    throw error;
                }
                myEncryptedIn.compact();
                if (output.position() > 0 && !myInputShutdown &&
                    !myDrainingClose)
                {
                    output.flip();
                    myPlainIn = output;
                    notifyState();
                } else {
                    myOwner.myBuffers.release(output);
                }
                if (result.getStatus() ==
                    SSLEngineResult.Status.BUFFER_UNDERFLOW)
                {
                    int needed = myEngine.getSession().getPacketBufferSize();
                    if (needed > myEncryptedIn.capacity()) {
                        if (needed > myOwner.myQueueLimit) {
                            throw new SSLException(
                                "TLS record exceeds buffer limit");
                        }
                        ByteBuffer larger = myOwner.myBuffers.acquire(needed);
                        myEncryptedIn.flip();
                        larger.put(myEncryptedIn);
                        myOwner.myBuffers.release(myEncryptedIn);
                        myEncryptedIn = larger;
                    }
                    myNeedNetworkRead = true;
                    /*
                     * If bytes were consumed from the socket, try another read
                     * on a later reactor turn. This also handles complete
                     * buffered records followed by a partial record without
                     * requiring another application read.
                     */
                    if (read > 0) {
                        myOwner.myReactor.signal(this);
                    }
                    scheduleOutput();
                    return;
                }
                if (result.getStatus() ==
                    SSLEngineResult.Status.BUFFER_OVERFLOW)
                {
                    throw new SSLException("Unexpected unwrap buffer overflow");
                }
                if (result.getStatus() == SSLEngineResult.Status.CLOSED) {
                    myInputEnded = true;
                }
                if (result.getHandshakeStatus() ==
                    SSLEngineResult.HandshakeStatus.FINISHED)
                {
                    myHandshakeComplete = true;
                }
                myNeedNetworkRead = myEncryptedIn.position() == 0;
                if (myNeedNetworkRead) {
                    myOwner.myBuffers.release(myEncryptedIn);
                    myEncryptedIn = null;
                }
                favorRead = false;
                notifyState();
                if (result.bytesConsumed() == 0 && result.bytesProduced() ==
                    0 && result.getHandshakeStatus() == hs)
                {
                    return;
                }
            }
            myOwner.myReactor.signal(this);
        }
    }

    /** {@inheritDoc} */
    @Override
      public int
    read(ByteBuffer destination) throws IOException
    {
        return read(destination, 0, isBlocking());
    }

    /**
     * Consume buffered plaintext or wait according to the captured blocking
     * mode and optional deadline.
     */
      private int
    read(ByteBuffer destination, long deadline,
        boolean blocking) throws IOException
    {
        Objects.requireNonNull(destination);
        if (destination.isReadOnly()) {
            throw new IllegalArgumentException("Read-only destination");
        }
        synchronized (myReader) {
            boolean complete = false;
            boolean interrupted = false;
            if (blocking) {
                begin();
            }
            try {
                synchronized (myState) {
                    checkConnected();
                    if (!destination.hasRemaining()) {
                        complete = true;
                        return 0;
                    }
                    for (; ; ) {
                        checkConnected();
                        if (myPlainIn != null && myPlainIn.hasRemaining()) {
                            int count =
                                Math.min(destination.remaining(),
                                myPlainIn.remaining());
                            int limit = myPlainIn.limit();
                            myPlainIn.limit(myPlainIn.position() + count);
                            destination.put(myPlainIn);
                            myPlainIn.limit(limit);
                            if (!myPlainIn.hasRemaining()) {
                                myOwner.myBuffers.release(myPlainIn);
                                myPlainIn = null;
                            }
                            complete = true;
                            myOwner.myReactor.signal(this);
                            notifyState();
                            return count;
                        }
                        if (myInputEnded || myInputShutdown) {
                            complete = true;
                            return -1;
                        }
                        if (!blocking) {
                            complete = true;
                            return 0;
                        }
                        awaitChange(deadline);
                    }
                }
            } catch (ClosedByInterruptException error) {
                interrupted = true;
                Thread.currentThread().interrupt();
                close();
                throw error;
            } finally {
                if (blocking) {
                    endOperation(complete, interrupted);
                }
            }
        }
    }

    /** {@inheritDoc} */
    @Override
      public long
    read(ByteBuffer[] destinations, int offset, int length) throws IOException
    {
        boolean blocking = isBlocking();
        Objects.checkFromIndexSize(offset, length, destinations.length);
        for (int i = offset; i < offset + length; i++) {
            Objects.requireNonNull(destinations[i]);
            if (destinations[i].isReadOnly()) {
                throw new IllegalArgumentException("Read-only destination");
            }
        }
        synchronized (myReader) {
            long count = 0;
            for (int i = offset; i < offset + length; i++) {
                if (!destinations[i].hasRemaining()) {
                    continue;
                }
                if (count > 0) {
                    synchronized (myState) {
                        if (myPlainIn == null) {
                            break;
                        }
                    }
                }
                int n = read(destinations[i], 0, blocking);
                if (n < 0) {
                    return count == 0 ? -1 : count;
                }
                count += n;
                if (n == 0) {
                    break;
                }
            }
            synchronized (myState) {
                checkConnected();
            }
            return count;
        }
    }

    /**
     * Compute application readiness independently of the engine's native I/O
     * requirements.
     */
      int
    readyOps()
    {
        synchronized (myState) {
            if (!isOpen()) {
                return 0;
            }
            if (myFailure != null) {
                return SelectionKey.OP_READ | SelectionKey.OP_WRITE |
                    SelectionKey.OP_CONNECT;
            }
            int ops =
                myPending && myRaw.isConnected() ? SelectionKey.OP_CONNECT : 0;
            if (myConnected) {
                if (myPlainIn != null || myInputEnded || myInputShutdown) {
                    ops |= SelectionKey.OP_READ;
                }
                if (myHandshakeComplete && (myPlainOut == null ||
                    myPlainOut.hasRemaining()) || myOutputEnded)
                {
                    ops |= SelectionKey.OP_WRITE;
                }
            }
            return ops;
        }
    }

    /**
     * Return every retained connection buffer to the provider's bounded cache.
     */
      private void
    releaseBuffers()
    {
        myOwner.myBuffers.release(myPlainIn);
        myOwner.myBuffers.release(myPlainOut);
        myOwner.myBuffers.release(myEncryptedIn);
        myOwner.myBuffers.release(myEncryptedOut);
        myEncryptedOut = null;
        myEncryptedIn = myEncryptedOut;
        myPlainOut = myEncryptedIn;
        myPlainIn = myPlainOut;
    }

    /** Stop notifying a cancelled application selector registration. */
      void
    removeKey(TlsSelector.Key key)
    {
        myKeys.remove(key);
    }

    /** Arrange another reactor turn when queued plaintext can make progress. */
      private void
    scheduleOutput()
    {
        if (myPlainOut != null && myEncryptedOut == null &&
            myEngine.getHandshakeStatus() ==
            SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING &&
            !myEngine.isOutboundDone())
        {
            myOwner.myReactor.signal(this);
        }
    }

    /**
     * Returns the current authenticated session on an open connected channel.
     *
     * @return The engine's current authenticated TLS session.
     * @throws IllegalStateException if initial authentication has not completed
     * @throws IOException if the channel is closed or its TLS transport has
     * failed
     */
      public SSLSession
    session() throws IOException
    {
        synchronized (myState) {
            checkConnected();
            if (!myHandshakeComplete) {
                throw new IllegalStateException("Handshake incomplete");
            }
            return myEngine.getSession();
        }
    }

    /** {@inheritDoc} */
    @Override
      public <T> TlsSocketChannel
    setOption(SocketOption<T> name, T value) throws IOException
    {
        synchronized (myState) {
            checkOpen();
            if (name == StandardSocketOptions.SO_LINGER) {
                int seconds = (Integer) Objects.requireNonNull(value);
                myLinger = seconds < 0 ? -1 : Math.min(seconds, 65535);
            } else {
                myRaw.setOption(name, value);
            }
            return this;
        }
    }

    /** {@inheritDoc} */
    @Override
      public TlsSocketChannel
    shutdownInput() throws IOException
    {
        /*
         * Application EOF is separate from TLS inbound closure: the engine
         * still needs peer handshake/control records to make outbound progress.
         */
        synchronized (myState) {
            checkConnected();
            myInputShutdown = true;
            myOwner.myBuffers.release(myPlainIn);
            myPlainIn = null;
            notifyState();
            myOwner.myReactor.signal(this);
            return this;
        }
    }

    /** {@inheritDoc} */
    @Override
      public TlsSocketChannel
    shutdownOutput() throws IOException
    {
        synchronized (myState) {
            checkConnected();
            myApplicationOutputShutdown = true;
            if (!myOutputEnded) {
                myShutdownDeadline =
                    System.nanoTime() + myOwner.shutdownTimeoutNanos();
            }
            myOutputEnded = true;
            notifyState();
            myOwner.myReactor.signal(this);
            return this;
        }
    }

    /** {@inheritDoc} */
    @Override
      public Socket
    socket()
    {
        synchronized (myState) {
            if (mySocket == null) {
                mySocket = new Adapter();
            }
            return mySocket;
        }
    }

    /** {@inheritDoc} */
    @Override
      public Set<SocketOption<?>>
    supportedOptions()
    {
        return myRaw.supportedOptions();
    }

    /**
     * Return engine control to the reactor and publish a delegated task failure
     * if one occurred.
     */
      void
    taskCompleted(Throwable error)
    {
        synchronized (myState) {
            myTaskRunning = false;
            if (error != null) {
                fail(error);
            }
            notifyState();
            myOwner.myReactor.signal(this);
        }
    }

    /** Compute native readiness needed for transport and TLS progression. */
      int
    transportInterests()
    {
        synchronized (myState) {
            if (myFailure != null || !isTransportOpen()) {
                return 0;
            }
            if (myRaw.isConnectionPending()) {
                return SelectionKey.OP_CONNECT;
            }
            if (!myRaw.isConnected() || myTaskRunning) {
                return 0;
            }
            int ops = 0;
            if (!myInputEnded && myPlainIn == null && !(myEncryptedOut !=
                null && myEngine.getHandshakeStatus() ==
                SSLEngineResult.HandshakeStatus.NEED_WRAP))
            {
                ops |= SelectionKey.OP_READ;
            }
            if (myEncryptedOut != null && myEncryptedOut.hasRemaining()) {
                ops |= SelectionKey.OP_WRITE;
            }
            return ops;
        }
    }

    /** {@inheritDoc} */
    @Override
      public int
    write(ByteBuffer source) throws IOException
    {
        return write(source, isBlocking());
    }

    /**
     * Accept bounded plaintext output, waiting only when the operation began in
     * blocking mode.
     */
      private int
    write(ByteBuffer source, boolean blocking) throws IOException
    {
        Objects.requireNonNull(source);
        synchronized (myWriter) {
            boolean complete = false;
            boolean interrupted = false;
            if (blocking) {
                begin();
            }
            try {
                synchronized (myState) {
                    checkConnected();
                    if (myOutputEnded) {
                        throw new ClosedChannelException();
                    }
                    if (!source.hasRemaining()) {
                        complete = true;
                        return 0;
                    }
                    for (; ; ) {
                        checkConnected();
                        if (myOutputEnded) {
                            throw new AsynchronousCloseException();
                        }
                        if (myPlainOut == null) {
                            myPlainOut =
                                myOwner.myBuffers.acquire(myOwner.myQueueLimit);
                        }
                        int count =
                            Math.min(source.remaining(),
                            myPlainOut.remaining());
                        if (count > 0) {
                            int limit = source.limit();
                            source.limit(source.position() + count);
                            myPlainOut.put(source);
                            source.limit(limit);
                            complete = true;
                            myOwner.myReactor.signal(this);
                            notifyState();
                            return count;
                        }
                        if (!blocking) {
                            complete = true;
                            return 0;
                        }
                        awaitChange();
                    }
                }
            } catch (ClosedByInterruptException error) {
                interrupted = true;
                Thread.currentThread().interrupt();
                close();
                throw error;
            } finally {
                if (blocking) {
                    endOperation(complete, interrupted);
                }
            }
        }
    }

    /** {@inheritDoc} */
    @Override
      public long
    write(ByteBuffer[] sources, int offset, int length) throws IOException
    {
        boolean blocking = isBlocking();
        Objects.checkFromIndexSize(offset, length, sources.length);
        for (int i = offset; i < offset + length; i++) {
            Objects.requireNonNull(sources[i]);
        }
        synchronized (myWriter) {
            synchronized (myState) {
                checkConnected();
                if (myOutputEnded) {
                    throw new ClosedChannelException();
                }
            }
            long count = 0;
            for (int i = offset; i < offset + length; i++) {
                if (!sources[i].hasRemaining()) {
                    continue;
                }
                if (count > 0) {
                    synchronized (myState) {
                        if (myPlainOut != null && !myPlainOut.hasRemaining()) {
                            break;
                        }
                    }
                }
                int n = write(sources[i], blocking);
                count += n;
                if (n == 0) {
                    break;
                }
            }
            synchronized (myState) {
                checkConnected();
            }
            return count;
        }
    }

    /**
     * Socket API view backed by the enclosing TLS channel's state and lifetime.
     */
    private final class Adapter extends Socket {

        /**
         * Socket read or accept timeout in milliseconds; zero means no timeout.
         */
        private volatile int myTimeout;

        /** {@inheritDoc} */
        @Override
          public void
        bind(SocketAddress address) throws IOException
        {
            try {
                TlsSocketChannel.this.bind(address);
            } catch (IOException | RuntimeException error) {
                throw SocketErrors.io(error);
            }
        }

        /** {@inheritDoc} */
        @Override
          public void
        close() throws IOException
        {
            TlsSocketChannel.this.close();
        }

        /** {@inheritDoc} */
        @Override
          public void
        connect(SocketAddress address) throws IOException
        {
            connect(address, 0);
        }

        /** {@inheritDoc} */
        @Override
          public void
        connect(SocketAddress address, int timeout) throws IOException
        {
            if (timeout < 0) {
                throw new IllegalArgumentException("timeout");
            }
            synchronized (blockingLock()) {
                if (!isBlocking()) {
                    throw new IllegalBlockingModeException();
                }
                try {
                    TlsSocketChannel.this.connect(address, timeout ==
                        0 ? 0 : System.nanoTime() + timeout * 1_000_000L);
                } catch (IOException | RuntimeException error) {
                    throw SocketErrors.connect(error, address);
                }
            }
        }

        /** {@inheritDoc} */
        @Override
          public SocketChannel
        getChannel()
        {
            return TlsSocketChannel.this;
        }

        /** {@inheritDoc} */
        @Override
          public InetAddress
        getInetAddress()
        {
            return myRaw.socket().getInetAddress();
        }

        /** {@inheritDoc} */
        @Override
          public InputStream
        getInputStream() throws IOException
        {
            try {
                synchronized (myState) {
                    checkConnected();
                    if (myInputShutdown) {
                        throw new SocketException("Input shut down");
                    }
                }
            } catch (IOException | RuntimeException error) {
                throw SocketErrors.io(error);
            }
            return new InputStream() {

                /** {@inheritDoc} */
                @Override
                  public int
                available() throws IOException
                {
                    try {
                        synchronized (myState) {
                            checkOpen();
                            return myPlainIn ==
                                null ? 0 : myPlainIn.remaining();
                        }
                    } catch (IOException error) {
                        throw SocketErrors.io(error);
                    }
                }

                /** {@inheritDoc} */
                @Override
                  public void
                close() throws IOException
                {
                    TlsSocketChannel.this.close();
                }

                /** {@inheritDoc} */
                @Override
                  public int
                read() throws IOException
                {
                    byte[] one = new byte[1];
                    return read(one, 0, 1) < 0 ? -1 : one[0] & 255;
                }

                /** {@inheritDoc} */
                @Override
                  public int
                read(byte[] bytes, int offset, int length) throws IOException
                {
                    Objects.checkFromIndexSize(offset, length, bytes.length);
                    if (!isBlocking()) {
                        throw new IllegalBlockingModeException();
                    }
                    long deadline =
                        myTimeout == 0 ? 0 : System.nanoTime() +
                        myTimeout * 1_000_000L;
                    try {
                        return TlsSocketChannel.this.read(ByteBuffer.wrap(bytes,
                            offset, length), deadline, true);
                    } catch (IOException | RuntimeException error) {
                        throw SocketErrors.io(error);
                    }
                }
            };
        }

        /** {@inheritDoc} */
        @Override
          public boolean
        getKeepAlive() throws SocketException
        {
            return option(StandardSocketOptions.SO_KEEPALIVE);
        }

        /** {@inheritDoc} */
        @Override
          public InetAddress
        getLocalAddress()
        {
            return isClosed() ? new InetSocketAddress(0)
                .getAddress() : myRaw.socket().getLocalAddress();
        }

        /** {@inheritDoc} */
        @Override
          public int
        getLocalPort()
        {
            return myRaw.socket().getLocalPort();
        }

        /** {@inheritDoc} */
        @Override
          public SocketAddress
        getLocalSocketAddress()
        {
            return isBound() ? new InetSocketAddress(getLocalAddress(),
                getLocalPort()) : null;
        }

        /** {@inheritDoc} */
        @Override
          public boolean
        getOOBInline() throws SocketException
        {
            if (isClosed()) {
                throw new SocketException("Socket closed");
            }
            return false;
        }

        /** {@inheritDoc} */
        @Override
          public <T> T
        getOption(SocketOption<T> name) throws IOException
        {
            return TlsSocketChannel.this.getOption(name);
        }

        /** {@inheritDoc} */
        @Override
          public OutputStream
        getOutputStream() throws IOException
        {
            try {
                synchronized (myState) {
                    checkConnected();
                    if (myOutputEnded) {
                        throw new SocketException("Output shut down");
                    }
                }
            } catch (IOException | RuntimeException error) {
                throw SocketErrors.io(error);
            }
            return new OutputStream() {

                /** {@inheritDoc} */
                @Override
                  public void
                close() throws IOException
                {
                    TlsSocketChannel.this.close();
                }

                /** {@inheritDoc} */
                @Override
                  public void
                write(int value) throws IOException
                {
                    write(new byte[] { (byte) value });
                }

                /** {@inheritDoc} */
                @Override
                  public void
                write(byte[] bytes, int offset, int length) throws IOException
                {
                    Objects.checkFromIndexSize(offset, length, bytes.length);
                    if (!isBlocking()) {
                        throw new IllegalBlockingModeException();
                    }
                    ByteBuffer source = ByteBuffer.wrap(bytes, offset, length);
                    try {
                        synchronized (myWriter) {
                            while (source.hasRemaining()) {
                                TlsSocketChannel.this.write(source, true);
                            }
                        }
                    } catch (IOException | RuntimeException error) {
                        throw SocketErrors.io(error);
                    }
                }
            };
        }

        /** {@inheritDoc} */
        @Override
          public int
        getPort()
        {
            return myRaw.socket().getPort();
        }

        /** {@inheritDoc} */
        @Override
          public int
        getReceiveBufferSize() throws SocketException
        {
            return option(StandardSocketOptions.SO_RCVBUF);
        }

        /** {@inheritDoc} */
        @Override
          public SocketAddress
        getRemoteSocketAddress()
        {
            return myRaw.socket().getRemoteSocketAddress();
        }

        /** {@inheritDoc} */
        @Override
          public boolean
        getReuseAddress() throws SocketException
        {
            return option(StandardSocketOptions.SO_REUSEADDR);
        }

        /** {@inheritDoc} */
        @Override
          public int
        getSendBufferSize() throws SocketException
        {
            return option(StandardSocketOptions.SO_SNDBUF);
        }

        /** {@inheritDoc} */
        @Override
          public int
        getSoLinger() throws SocketException
        {
            return option(StandardSocketOptions.SO_LINGER);
        }

        /** {@inheritDoc} */
        @Override
          public int
        getSoTimeout() throws SocketException
        {
            if (isClosed()) {
                throw new SocketException("Socket closed");
            }
            return myTimeout;
        }

        /** {@inheritDoc} */
        @Override
          public boolean
        getTcpNoDelay() throws SocketException
        {
            return option(StandardSocketOptions.TCP_NODELAY);
        }

        /** {@inheritDoc} */
        @Override
          public int
        getTrafficClass() throws SocketException
        {
            return option(StandardSocketOptions.IP_TOS);
        }

        /** {@inheritDoc} */
        @Override
          public boolean
        isBound()
        {
            return myRaw.socket().isBound();
        }

        /** {@inheritDoc} */
        @Override
          public boolean
        isClosed()
        {
            return !TlsSocketChannel.this.isOpen();
        }

        /**
         * {@inheritDoc} Socket retains its historical connected state after
         * close; the channel itself reports false once closed, per the separate
         * channel contract.
         */
        @Override
          public boolean
        isConnected()
        {
            synchronized (myState) {
                return myConnected;
            }
        }

        /** {@inheritDoc} */
        @Override
          public boolean
        isInputShutdown()
        {
            synchronized (myState) {
                return myInputShutdown;
            }
        }

        /** {@inheritDoc} */
        @Override
          public boolean
        isOutputShutdown()
        {
            synchronized (myState) {
                return myApplicationOutputShutdown;
            }
        }

        /**
         * Access a channel socket option while translating failures to the
         * legacy Socket contract.
         */
          private <T> void
        option(SocketOption<T> name, T value) throws SocketException
        {
            try {
                TlsSocketChannel.this.setOption(name, value);
            } catch (IOException error) {
                throw socketError(error);
            }
        }

        /**
         * Access a channel socket option while translating failures to the
         * legacy Socket contract.
         */
          private <T> T
        option(SocketOption<T> name) throws SocketException
        {
            try {
                return TlsSocketChannel.this.getOption(name);
            } catch (IOException error) {
                throw socketError(error);
            }
        }

        /** {@inheritDoc} */
        @Override
          public void
        sendUrgentData(int value) throws IOException
        {
            throw new SocketException("Urgent data is not supported by TLS");
        }

        /** {@inheritDoc} */
        @Override
          public void
        setKeepAlive(boolean value) throws SocketException
        {
            option(StandardSocketOptions.SO_KEEPALIVE, value);
        }

        /** {@inheritDoc} */
        @Override
          public void
        setOOBInline(boolean value) throws SocketException
        {
            if (isClosed()) {
                throw new SocketException("Socket closed");
            }
            if (value) {
                throw new SocketException(
                    "Urgent data is not supported by TLS");
            }
        }

        /** {@inheritDoc} */
        @Override
          public <T> Socket
        setOption(SocketOption<T> name, T value) throws IOException
        {
            TlsSocketChannel.this.setOption(name, value);
            return this;
        }

        /** {@inheritDoc} */
        @Override
          public void
        setReceiveBufferSize(int value) throws SocketException
        {
            option(StandardSocketOptions.SO_RCVBUF, value);
        }

        /** {@inheritDoc} */
        @Override
          public void
        setReuseAddress(boolean value) throws SocketException
        {
            option(StandardSocketOptions.SO_REUSEADDR, value);
        }

        /** {@inheritDoc} */
        @Override
          public void
        setSendBufferSize(int value) throws SocketException
        {
            option(StandardSocketOptions.SO_SNDBUF, value);
        }

        /** {@inheritDoc} */
        @Override
          public void
        setSoLinger(boolean on, int value) throws SocketException
        {
            if (on && value < 0) {
                throw new IllegalArgumentException("negative linger");
            }
            option(StandardSocketOptions.SO_LINGER, on ? Math.min(value,
                65535) : -1);
        }

        /** {@inheritDoc} */
        @Override
          public void
        setSoTimeout(int value) throws SocketException
        {
            if (value < 0) {
                throw new IllegalArgumentException("timeout");
            }
            if (isClosed()) {
                throw new SocketException("Socket closed");
            }
            myTimeout = value;
        }

        /** {@inheritDoc} */
        @Override
          public void
        setTcpNoDelay(boolean value) throws SocketException
        {
            option(StandardSocketOptions.TCP_NODELAY, value);
        }

        /** {@inheritDoc} */
        @Override
          public void
        setTrafficClass(int value) throws SocketException
        {
            option(StandardSocketOptions.IP_TOS, value);
        }

        /** {@inheritDoc} */
        @Override
          public void
        shutdownInput() throws IOException
        {
            try {
                TlsSocketChannel.this.shutdownInput();
            } catch (IOException | RuntimeException error) {
                throw SocketErrors.io(error);
            }
        }

        /** {@inheritDoc} */
        @Override
          public void
        shutdownOutput() throws IOException
        {
            try {
                TlsSocketChannel.this.shutdownOutput();
            } catch (IOException | RuntimeException error) {
                throw SocketErrors.io(error);
            }
        }

        /**
         * Translate channel I/O failures for a Socket method restricted to
         * SocketException.
         */
          private SocketException
        socketError(IOException cause)
        {
            if (cause instanceof SocketException socketError) {
                return socketError;
            }
            SocketException error =
                new SocketException(isClosed(
                ) ? "Socket closed" : cause.getMessage());
            error.initCause(cause);
            return error;
        }

        /** {@inheritDoc} */
        @Override
          public Set<SocketOption<?>>
        supportedOptions()
        {
            return TlsSocketChannel.this.supportedOptions();
        }
    }
}

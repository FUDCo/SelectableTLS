package com.fudco.selectabletls;

import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketAddress;
import java.net.SocketException;
import java.net.SocketOption;
import java.net.SocketTimeoutException;
import java.nio.channels.IllegalBlockingModeException;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.util.Set;

/**
 * Listener that accepts channels whose TLS handshakes progress automatically.
 */
public final class TlsServerSocketChannel extends ServerSocketChannel {

    /** Nonblocking native listener underlying the logical channel. */
    final ServerSocketChannel myRaw;

    /** Provider that creates and owns accepted TLS connections. */
    private final TlsProvider myOwner;

    /** ServerSocket view sharing this listener's lifecycle. */
    private final ServerSocket myAdapter;

    /** Serializes accept operations while allowing independent closure. */
    private final Object myAcceptLock = new Object();

    /** Wrap a native listener and create its shared ServerSocket view. */
    TlsServerSocketChannel(TlsProvider owner,
        ServerSocketChannel raw) throws IOException
    {
        super(owner);
        myOwner = owner;
        myRaw = raw;
        raw.configureBlocking(false);
        myAdapter = new Adapter();
    }

    /** {@inheritDoc} */
    @Override
      public TlsSocketChannel
    accept() throws IOException
    {
        return accept(0, isBlocking());
    }

    /**
     * Accept using the operation's original blocking mode and an optional
     * absolute deadline.
     */
      private TlsSocketChannel
    accept(long deadline, boolean blocking) throws IOException
    {
        synchronized (myAcceptLock) {
            boolean complete = false;
            if (blocking) {
                begin();
            }
            Selector waiter = null;
            try {
                for (; ; ) {
                    SocketChannel accepted = myRaw.accept();
                    if (accepted != null) {
                        try {
                            TlsSocketChannel channel =
                                TlsSocketChannel.accepted(myOwner, accepted);
                            complete = true;
                            return channel;
                        } catch (IOException | RuntimeException error) {
                            accepted.close();
                            throw error;
                        }
                    }
                    if (!blocking) {
                        complete = true;
                        return null;
                    }
                    if (waiter == null) {
                        waiter = Selector.open();
                        myRaw.register(waiter, SelectionKey.OP_ACCEPT);
                    }
                    long remaining =
                        deadline ==
                        0 ? Long.MAX_VALUE : deadline - System.nanoTime();
                    if (remaining <= 0) {
                        throw new SocketTimeoutException("Accept timed out");
                    }
                    /*
                     * Bounded wait also observes asynchronous listener closure,
                     * which need not wake a stock selector when its sole native
                     * key is cancelled.
                     */
                    waiter.select(Math.min(100, Math.max(1,
                        remaining / 1_000_000L)));
                    waiter.selectedKeys().clear();
                }
            } finally {
                if (waiter != null) {
                    waiter.close();
                }
                if (blocking) {
                    end(complete);
                }
            }
        }
    }

    /** {@inheritDoc} */
    @Override
      public TlsServerSocketChannel
    bind(SocketAddress address, int backlog) throws IOException
    {
        myRaw.bind(address, backlog);
        return this;
    }

    /** {@inheritDoc} */
    @Override
      public SocketAddress
    getLocalAddress() throws IOException
    {
        return myRaw.getLocalAddress();
    }

    /** {@inheritDoc} */
    @Override
      public <T> T
    getOption(SocketOption<T> option) throws IOException
    {
        return myRaw.getOption(option);
    }

    /** {@inheritDoc} */
    @Override
      protected void
    implCloseSelectableChannel() throws IOException
    {
        try {
            myRaw.close();
        } finally {
            myOwner.released(this);
        }
    }

    /** {@inheritDoc} */
    @Override
      protected void
    implConfigureBlocking(boolean block)
    {
        /* logical blocking uses a temporary native selector */
    }

    /** {@inheritDoc} */
    @Override
      public <T> TlsServerSocketChannel
    setOption(SocketOption<T> option, T value) throws IOException
    {
        myRaw.setOption(option, value);
        return this;
    }

    /** {@inheritDoc} */
    @Override
      public ServerSocket
    socket()
    {
        return myAdapter;
    }

    /** {@inheritDoc} */
    @Override
      public Set<SocketOption<?>>
    supportedOptions()
    {
        return myRaw.supportedOptions();
    }

    /**
     * Socket API view backed by the enclosing TLS channel's state and lifetime.
     */
    private final class Adapter extends ServerSocket {

        /**
         * Socket read or accept timeout in milliseconds; zero means no timeout.
         */
        private volatile int myTimeout;

        /**
         * Create the socket view whose operations share the enclosing channel.
         */
        Adapter() throws IOException
        {
            super();
        }

        /** {@inheritDoc} */
        @Override
          public Socket
        accept() throws IOException
        {
            if (!isBlocking()) {
                throw new IllegalBlockingModeException();
            }
            try {
                return TlsServerSocketChannel.this.accept(myTimeout ==
                    0 ? 0 : System.nanoTime() + myTimeout * 1_000_000L, true)
                    .socket();
            } catch (IOException | RuntimeException error) {
                throw SocketErrors.io(error);
            }
        }

        /** {@inheritDoc} */
        @Override
          public void
        bind(SocketAddress address) throws IOException
        {
            bind(address, 50);
        }

        /** {@inheritDoc} */
        @Override
          public void
        bind(SocketAddress address, int backlog) throws IOException
        {
            try {
                TlsServerSocketChannel.this.bind(address, backlog);
            } catch (IOException | RuntimeException error) {
                throw SocketErrors.io(error);
            }
        }

        /** {@inheritDoc} */
        @Override
          public void
        close() throws IOException
        {
            TlsServerSocketChannel.this.close();
        }

        /** {@inheritDoc} */
        @Override
          public ServerSocketChannel
        getChannel()
        {
            return TlsServerSocketChannel.this;
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
            return myRaw.socket().getLocalSocketAddress();
        }

        /** {@inheritDoc} */
        @Override
          public <T> T
        getOption(SocketOption<T> name) throws IOException
        {
            return myRaw.getOption(name);
        }

        /** {@inheritDoc} */
        @Override
          public int
        getReceiveBufferSize() throws SocketException
        {
            return myRaw.socket().getReceiveBufferSize();
        }

        /** {@inheritDoc} */
        @Override
          public boolean
        getReuseAddress() throws SocketException
        {
            return myRaw.socket().getReuseAddress();
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
        isBound()
        {
            return myRaw.socket().isBound();
        }

        /** {@inheritDoc} */
        @Override
          public boolean
        isClosed()
        {
            return !TlsServerSocketChannel.this.isOpen();
        }

        /** {@inheritDoc} */
        @Override
          public <T> ServerSocket
        setOption(SocketOption<T> name, T value) throws IOException
        {
            myRaw.setOption(name, value);
            return this;
        }

        /** {@inheritDoc} */
        @Override
          public void
        setReceiveBufferSize(int value) throws SocketException
        {
            myRaw.socket().setReceiveBufferSize(value);
        }

        /** {@inheritDoc} */
        @Override
          public void
        setReuseAddress(boolean value) throws SocketException
        {
            myRaw.socket().setReuseAddress(value);
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
          public Set<SocketOption<?>>
        supportedOptions()
        {
            return myRaw.supportedOptions();
        }
    }
}

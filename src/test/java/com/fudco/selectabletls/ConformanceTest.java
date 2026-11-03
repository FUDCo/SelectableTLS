package com.fudco.selectabletls;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.Field;
import java.net.ConnectException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketAddress;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.net.StandardProtocolFamily;
import java.net.StandardSocketOptions;
import java.nio.ByteBuffer;
import java.nio.channels.AsynchronousCloseException;
import java.nio.channels.ClosedByInterruptException;
import java.nio.channels.ClosedChannelException;
import java.nio.channels.ClosedSelectorException;
import java.nio.channels.DatagramChannel;
import java.nio.channels.Pipe;
import java.nio.channels.SelectionKey;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Random;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicInteger;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509ExtendedTrustManager;

/**
 * Executable contract tests with real JSSE peers and locally generated
 * credentials.
 */
public final class ConformanceTest {

    /** Generated identity and trust configuration shared by the scenarios. */
    private static SSLContext theContext;

    /** Trusted client context that supplies no client certificate. */
    private static SSLContext theClientWithoutIdentity;

    /** Certificate verifier wrapped by the delegated-task saturation test. */
    private static X509ExtendedTrustManager theVerifier;

    /** Number of successfully completed core scenarios. */
    private static int theTests;

    /** Prevent construction of this utility class. */
      private
    ConformanceTest()
    {
    }

    /**
     * Verify abort interrupts a concurrent lingering close. Closing on another
     * thread is the behavior under test.
     */
    @SuppressWarnings("try")
      private static void
    abortLinger() throws Exception
    {
        try (TlsProvider provider = new TlsProvider(theContext);
            ServerSocketChannel listener = ServerSocketChannel.open();
            TlsSocketChannel stalled =
                provider.openSocketChannel("localhost")) {
            listener.bind(loopback());
            stalled.connect(listener.getLocalAddress());
            try (SocketChannel peer = listener.accept()) {
                require(peer.isConnected(), "stalled peer accepted");
                stalled.setOption(StandardSocketOptions.SO_LINGER, 20);
                ExecutorService executor = Executors.newSingleThreadExecutor();
                try {
                    Future<?> closure = executor.submit(() -> {
                        stalled.close();
                        return null;
                    });
                    long limit = System.nanoTime() + 2_000_000_000L;
                    while (stalled.isOpen() && System.nanoTime() < limit) {
                        Thread.sleep(1);
                    }
                    require(!stalled.isOpen(), "lingering close entered");
                    long abortStarted = System.nanoTime();
                    stalled.abort();
                    require(System.nanoTime() - abortStarted < 2_000_000_000L,
                        "abort must not wait for linger interval");
                    closure.get(2, TimeUnit.SECONDS);
                    require(!stalled.myRaw.isOpen(),
                        "abort released lingering transport");
                } finally {
                    executor.shutdownNow();
                }
            }
        }
    }

    /** Exercise a TLS exchange with the specified Internet address family. */
      private static void
    addressFamily(StandardProtocolFamily family, String host) throws Exception
    {
        try (TlsProvider provider = new TlsProvider(theContext);
            TlsServerSocketChannel listener =
                provider.openServerSocketChannel(family);
            TlsSocketChannel client =
                provider.openSocketChannel(family, "localhost")) {
            listener.bind(new InetSocketAddress(host, 0));
            client.connect(listener.getLocalAddress());
            try (TlsSocketChannel server = listener.accept()) {
                client.write(ByteBuffer.wrap(new byte[] { 49 }));
                ByteBuffer value = ByteBuffer.allocate(1);
                require(server.read(value) == 1 && value.get(0) == 49,
                    "family exchange " + family);
            }
        }
    }

    /** Verify asynchronous close releases blocked reader. */
      private static void
    asynchronousClose() throws Exception
    {
        try (Pair pair = new Pair()) {
            ExecutorService executor = Executors.newSingleThreadExecutor();
            try {
                CountDownLatch waiting = new CountDownLatch(1);
                Future<Boolean> result = executor.submit(() -> {
                    waiting.countDown();
                    try {
                        pair.myClient.read(ByteBuffer.allocate(1));
                        return false;
                    } catch (ClosedChannelException expected) {
                        return true;
                    }
                });
                waiting.await();
                pair.myClient.close();
                require(result.get(3, TimeUnit.SECONDS),
                    "close must release blocked read");
            } finally {
                executor.shutdownNow();
            }
        }
    }

    /** Verify bounded queue applies backpressure to stalled handshake. */
      private static void
    backpressure() throws Exception
    {
        try (ServerSocketChannel listener = ServerSocketChannel.open();
            TlsProvider provider = new TlsProvider(theContext, 32768);
            TlsSocketChannel client = provider.openSocketChannel("localhost")) {
            listener.bind(loopback());
            client.connect(listener.getLocalAddress());
            try (SocketChannel stalled = listener.accept()) {
                require(stalled.isConnected(), "raw stalled peer");
                client.configureBlocking(false);
                ByteBuffer payload = ByteBuffer.allocate(65536);
                require(client.write(payload) == 32768, "queue bound");
                require(client.write(payload) == 0, "full queue returns zero");
                require(payload.position() == 32768,
                    "unaccepted bytes untouched");
            }
        }
    }

    /** Verify inbound traffic progresses while outbound TCP is blocked. */
      private static void
    blockedOutputDuplex() throws Exception
    {
        try (Pair pair = new Pair()) {
            /*
             * Extremely small receive windows can keep trickling records rather
             * than reaching a sustained stall on some TCP implementations.
             */
            pair.myClient.setOption(StandardSocketOptions.SO_SNDBUF, 65536);
            pair.myServer.setOption(StandardSocketOptions.SO_RCVBUF, 65536);
            pair.myClient.write(ByteBuffer.wrap(new byte[] { 1 }));
            pair.myServer.read(ByteBuffer.allocate(1));
            ExecutorService executor = Executors.newSingleThreadExecutor();
            AtomicInteger accepted = new AtomicInteger();
            Future<?> writer = executor.submit(() -> {
                ByteBuffer payload = ByteBuffer.allocate(65536);
                for (int i = 0; i < 1024; i++) {
                    payload.clear();
                    while (payload.hasRemaining()) {
                        accepted.addAndGet(pair.myClient.write(payload));
                    }
                }
                return null;
            });
            try {
                int previous = -1;
                int stable = 0;
                long limit = System.nanoTime() + 10_000_000_000L;
                while (stable < 5 && System.nanoTime() < limit) {
                    Thread.sleep(20);
                    int current = accepted.get();
                    stable =
                        current > 0 && current == previous ? stable + 1 : 0;
                    previous = current;
                }
                /* surface unexpected transport failure */
                if (writer.isDone()) {
                    writer.get();
                }
                require(stable == 5 && !writer.isDone(),
                    "outbound stream is backpressured: accepted=" +
                    accepted.get() + ", stable=" + stable);
                pair.myServer.write(ByteBuffer.wrap(new byte[] { 77 }));
                pair.myClient.socket().setSoTimeout(2000);
                require(pair.myClient.socket().getInputStream().read() == 77,
                    "independent incoming message while writer blocked");
            } finally {
                writer.cancel(true);
                executor.shutdownNow();
                require(executor.awaitTermination(3, TimeUnit.SECONDS),
                    "blocked writer stopped");
            }
        }
    }

    /** Verify buffer boundaries and empty gathering writes. */
      private static void
    bufferBoundaries() throws Exception
    {
        try (ServerSocketChannel listener = ServerSocketChannel.open()) {
            listener.bind(loopback());
            try (SocketChannel client =
                SocketChannel.open(listener.getLocalAddress());
                SocketChannel server = listener.accept()) {
                require(server.isConnected(), "native reference accepted");
                buffers(client);
            }
        }
        try (Pair pair = new Pair()) {
            buffers(pair.myClient);
        }
    }

    /**
     * Compare empty, invalid and output-shutdown buffer operations with the
     * channel contract.
     */
      private static void
    buffers(SocketChannel channel) throws Exception
    {
        require(channel.read(ByteBuffer.allocate(0)) == 0 &&
            channel.write(ByteBuffer.allocate(0)) == 0, "empty scalar buffers");
        require(channel.read(new ByteBuffer[0]) == 0 &&
            channel.write(new ByteBuffer[0]) == 0, "empty vector buffers");
        try {
            channel.read(ByteBuffer.allocate(1).asReadOnlyBuffer());
            throw new AssertionError("read-only destination accepted");
        } catch (IllegalArgumentException expected) {
            /* destination must be writable */
        }
        try {
            channel.read(new ByteBuffer[] { ByteBuffer.allocate(1) }, -1, 1);
            throw new AssertionError("negative vector offset accepted");
        } catch (IndexOutOfBoundsException expected) {
            /* bounds validation */
        }
        channel.shutdownOutput();
        expectIOError(() -> channel.write(new ByteBuffer[0]));
    }

    /**
     * Generate temporary credentials and construct the trusted contexts used by
     * the scenarios.
     */
      static SSLContext
    certificateContext(Path directory) throws Exception
    {
        Path store = directory.resolve("identity.p12");
        String password = UUID.randomUUID().toString();
        Process child =
            new ProcessBuilder(Path.of(System.getProperty("java.home"), "bin",
            "keytool").toString(), "-genkeypair", "-alias", "server", "-keyalg",
            "EC", "-groupname", "secp256r1", "-dname", "CN=localhost", "-ext",
            "SAN=dns:localhost,ip:127.0.0.1", "-validity", "2", "-storetype",
            "PKCS12", "-keystore", store.toString(), "-storepass", password,
            "-keypass", password, "-noprompt").redirectErrorStream(true)
            .redirectOutput(directory.resolve("keytool.log").toFile()).start();
        if (!child.waitFor(30, TimeUnit.SECONDS)) {
            child.destroyForcibly();
            throw new AssertionError("keytool timeout");
        }
        require(child.exitValue() == 0, "keytool failed: " +
            Files.readString(directory.resolve("keytool.log")));
        KeyStore keys = KeyStore.getInstance("PKCS12");
        try (InputStream stream = Files.newInputStream(store)) {
            keys.load(stream, password.toCharArray());
        }
        Files.write(directory.resolve("certificate.der"),
            keys.getCertificate("server").getEncoded());
        KeyManagerFactory km =
            KeyManagerFactory.getInstance(
            KeyManagerFactory.getDefaultAlgorithm());
        km.init(keys, password.toCharArray());
        TrustManagerFactory tm =
            TrustManagerFactory.getInstance(
            TrustManagerFactory.getDefaultAlgorithm());
        tm.init(keys);
        theVerifier = (X509ExtendedTrustManager) tm.getTrustManagers()[0];
        SSLContext result = SSLContext.getInstance("TLS");
        result.init(km.getKeyManagers(), tm.getTrustManagers(), null);
        theClientWithoutIdentity = SSLContext.getInstance("TLS");
        theClientWithoutIdentity.init(new KeyManager[0], tm.getTrustManagers(),
            null);
        return result;
    }

    /** Verify required client certificate. */
      private static void
    clientCertificate() throws Exception
    {
        try (TlsProvider provider = new TlsProvider(theContext);
            TlsServerSocketChannel listener =
                provider.openServerSocketChannel();
            TlsSocketChannel client = provider.openSocketChannel("localhost")) {
            provider.setNeedClientAuth(true);
            listener.bind(loopback());
            client.connect(listener.getLocalAddress());
            try (TlsSocketChannel server = listener.accept()) {
                client.write(ByteBuffer.wrap(new byte[] { 11 }));
                server.read(ByteBuffer.allocate(1));
                require(server.session().getPeerCertificates().length > 0,
                    "verified client certificate");
            }
        }
    }

    /**
     * Verify delivery of accepted output and clean EOF for the selected TLS
     * version.
     */
      private static void
    closeDrainsOutput(String protocol) throws Exception
    {
        try (Pair pair = new Pair(protocol)) {
            byte[] message = new byte[60000];
            new Random(99).nextBytes(message);
            require(pair.myClient.write(ByteBuffer.wrap(message)) ==
                message.length, "queued final message");
            pair.myClient.close();
            require(!pair.myClient.isOpen(),
                "close returns with application channel closed");
            ByteBuffer received = ByteBuffer.allocate(message.length);
            while (received.hasRemaining()) {
                require(pair.myServer.read(received) > 0,
                    "accepted output must survive close");
            }
            require(Arrays.equals(received.array(), message),
                "final message integrity");
            require(pair.myServer.read(ByteBuffer.allocate(1)) == -1,
                "close terminates with close_notify");
        }
    }

    /** Verify close deadline bounds waiting for peer close_notify. */
      private static void
    closePeerDeadline() throws Exception
    {
        try (Pair pair = new Pair("TLSv1.3")) {
            pair.myClient.write(ByteBuffer.wrap(new byte[] { 7 }));
            require(pair.myServer.read(ByteBuffer.allocate(1)) == 1,
                "handshake and initial message");
            pair.myProvider.setShutdownTimeout(Duration.ofMillis(500));
            pair.myClient.close();
            require(pair.myServer.read(ByteBuffer.allocate(1)) == -1,
                "peer receives close_notify");
            /*
             * TLS 1.3 permits the peer to leave its output direction open.
             * Inspect only our transport's public channel state to verify that
             * asynchronous close eventually releases the native resource.
             */
            long limit = System.nanoTime() + 3_000_000_000L;
            while (pair.myClient.myRaw.isOpen() && System.nanoTime() < limit) {
                Thread.sleep(10);
            }
            require(!pair.myClient.myRaw.isOpen(),
                "close deadline releases transport without " +
                "reciprocal close_notify");
        }
    }

    /** Verify transport ownership spans logical close and close-handler entry. */
      private static void
    closeRegistrationGap() throws Exception
    {
        try (Pair pair = new Pair()) {
            /* Control our own monitor, without accessing any JDK internals. */
            Field field = TlsSocketChannel.class.getDeclaredField("myState");
            field.setAccessible(true);
            Object state = field.get(pair.myClient);
            CompletableFuture<Void> closed = new CompletableFuture<>();
            Thread closer = new Thread(() -> {
                try {
                    pair.myClient.close();
                    closed.complete(null);
                } catch (IOException error) {
                    closed.completeExceptionally(error);
                }
            });
            pair.myClient.write(ByteBuffer.wrap(new byte[] { 73 }));
            try {
                synchronized (state) {
                    closer.start();
                    long deadline = System.nanoTime() + 3_000_000_000L;
                    while (pair.myClient.isOpen() &&
                        System.nanoTime() < deadline)
                    {
                        Thread.onSpinWait();
                    }
                    require(!pair.myClient.isOpen(), "logical close reached");
                    require(pair.myClient.isTransportOpen(),
                        "reactor retains transport before close handler entry");
                }
                closed.get(3, TimeUnit.SECONDS);
                pair.myServer.socket().setSoTimeout(3000);
                InputStream input = pair.myServer.socket().getInputStream();
                require(input.read() == 73 && input.read() == -1,
                    "accepted output and close_notify survive close gap");
            } finally {
                closer.join(3000);
                require(!closer.isAlive(), "close thread terminated");
            }
        }
    }

    /**
     * Verify closed TLS channel rejects options and address queries during
     * drain.
     */
      private static void
    closedChannelOperations() throws Exception
    {
        try (Pair pair = new Pair("TLSv1.3")) {
            pair.myClient.write(ByteBuffer.wrap(new byte[] { 7 }));
            require(pair.myServer.read(ByteBuffer.allocate(1)) == 1,
                "initial exchange");
            pair.myClient.close();
            expectClosed(() ->
                pair.myClient.setOption(StandardSocketOptions.TCP_NODELAY,
                true));
            expectClosed(() ->
                pair.myClient.getOption(StandardSocketOptions.SO_SNDBUF));
            expectClosed(() -> pair.myClient.getLocalAddress());
            expectClosed(() -> pair.myClient.getRemoteAddress());
            try {
                pair.myClient.socket().setTcpNoDelay(true);
                throw new AssertionError("closed socket option succeeded");
            } catch (SocketException expected) {
                /* adapter must report socket closure too */
            }
        }
    }

    /** Verify completed handshake cancels deadline. */
      private static void
    completedDeadline() throws Exception
    {
        try (TlsProvider provider = new TlsProvider(theContext);
            TlsServerSocketChannel listener =
                provider.openServerSocketChannel();
            TlsSocketChannel client = provider.openSocketChannel("localhost");
            TlsSelector selector = provider.openSelector()) {
            provider.setHandshakeTimeout(Duration.ofSeconds(1));
            listener.bind(loopback());
            client.connect(listener.getLocalAddress());
            try (TlsSocketChannel server = listener.accept()) {
                client.write(ByteBuffer.wrap(new byte[] { 1 }));
                server.read(ByteBuffer.allocate(1));
                client.configureBlocking(false);
                client.register(selector, SelectionKey.OP_READ);
                require(selector.select(1200) == 0,
                    "completed handshake must not time out");
                server.write(ByteBuffer.wrap(new byte[] { 2 }));
                require(selector.select(3000) == 1 &&
                    client.read(ByteBuffer.allocate(1)) == 1,
                    "connection remains usable after original deadline");
            }
        }
    }

    /** Verify concurrent blocking reader and writer. */
      private static void
    concurrentReadWrite() throws Exception
    {
        try (Pair pair = new Pair()) {
            ExecutorService executor = Executors.newFixedThreadPool(2);
            try {
                CountDownLatch reading = new CountDownLatch(1);
                Future<Integer> response = executor.submit(() -> {
                    reading.countDown();
                    ByteBuffer b = ByteBuffer.allocate(1);
                    int n = pair.myClient.read(b);
                    return n == 1 ? (int) b.get(0) : -1;
                });
                reading.await();
                Future<Integer> server = executor.submit(() -> {
                    ByteBuffer b = ByteBuffer.allocate(1);
                    int n = pair.myServer.read(b);
                    b.flip();
                    pair.myServer.write(b);
                    return n;
                });
                require(pair.myClient.write(ByteBuffer.wrap(
                    new byte[] { 42 })) == 1, "write while reader pending");
                require(response.get(5, TimeUnit.SECONDS) == 42,
                    "concurrent duplex response");
                require(server.get(5, TimeUnit.SECONDS) == 1, "server read");
            } finally {
                executor.shutdownNow();
            }
        }
    }

    /** Require an operation to report a closed channel. */
      private static void
    expectClosed(Checked operation) throws Exception
    {
        try {
            operation.run();
            throw new AssertionError("closed channel operation succeeded");
        } catch (ClosedChannelException expected) {
            /* required channel error */
        }
    }

    /** Require an operation to report an I/O failure. */
      private static void
    expectIOError(Checked operation) throws Exception
    {
        try {
            operation.run();
            throw new AssertionError("invalid I/O operation succeeded");
        } catch (IOException expected) {
            /* Native adapters may retain a channel IOException subtype. */
        }
    }

    /** Require an adapter operation to report a SocketException. */
      private static void
    expectSocketError(Checked operation) throws Exception
    {
        try {
            operation.run();
            throw new AssertionError("invalid socket operation succeeded");
        } catch (SocketException expected) {
            /* Socket API error, not an unchecked channel-state exception */
        }
    }

    /** Verify failed nonblocking connect closes channel. */
      private static void
    failedConnect() throws Exception
    {
        SocketAddress unavailable;
        try (ServerSocketChannel reservation = ServerSocketChannel.open()) {
            reservation.bind(loopback());
            unavailable = reservation.getLocalAddress();
        }
        try (TlsProvider provider = new TlsProvider(theContext);
            TlsSocketChannel channel = provider.openSocketChannel("localhost");
            TlsSelector selector = provider.openSelector()) {
            channel.configureBlocking(false);
            boolean failed = false;
            try {
                if (!channel.connect(unavailable)) {
                    channel.register(selector, SelectionKey.OP_CONNECT);
                    require(selector.select(3000) > 0,
                        "failed connect readiness");
                    channel.finishConnect();
                }
            } catch (ConnectException expected) {
                failed = true;
            }
            require(failed && !channel.isOpen(),
                "connection failure closes the channel");
        }
    }

    /**
     * Forward a stream in small pieces to exercise record fragmentation
     * independently of TLS framing.
     */
      private static void
    fragment(Socket source, Socket destination) throws IOException
    {
        byte[] bytes = new byte[137];
        InputStream input = source.getInputStream();
        OutputStream output = destination.getOutputStream();
        int count;
        while (true) {
            count = input.read(bytes);
            if (count == -1) {
                break;
            }
            for (int offset = 0; offset < count; ) {
                int size = Math.min(count - offset, 1 + (offset % 19));
                output.write(bytes, offset, size);
                offset += size;
            }
        }
        destination.shutdownOutput();
    }

    /** Verify fragmented records and close_notify. */
      private static void
    fragmentedTransport() throws Exception
    {
        ExecutorService relay = Executors.newFixedThreadPool(3);
        try (TlsProvider provider = new TlsProvider(theContext);
            TlsServerSocketChannel listener =
                provider.openServerSocketChannel();
            ServerSocket proxy = new ServerSocket();
            TlsSocketChannel client = provider.openSocketChannel("localhost")) {
            listener.bind(loopback());
            proxy.bind(loopback());
            client.connect(proxy.getLocalSocketAddress());
            try (Socket incoming = proxy.accept();
                Socket outgoing = new Socket()) {
                outgoing.connect(listener.getLocalAddress());
                incoming.setSoTimeout(5000);
                outgoing.setSoTimeout(5000);
                try (TlsSocketChannel server = listener.accept()) {
                    Future<?> forward = relay.submit(() -> {
                        fragment(incoming, outgoing);
                        return null;
                    });
                    Future<?> backward = relay.submit(() -> {
                        fragment(outgoing, incoming);
                        return null;
                    });
                    byte[] payload = new byte[131071];
                    new Random(17).nextBytes(payload);
                    Future<?> sender = relay.submit(() -> {
                        ByteBuffer source = ByteBuffer.wrap(payload);
                        while (source.hasRemaining()) {
                            client.write(source);
                        }
                        client.shutdownOutput();
                        return null;
                    });
                    ByteBuffer received = ByteBuffer.allocate(payload.length);
                    while (received.hasRemaining()) {
                        require(server.read(received) > 0,
                            "fragmented payload premature EOF");
                    }
                    require(Arrays.equals(payload, received.array()),
                        "fragmentation preserves payload");
                    require(server.read(ByteBuffer.allocate(1)) == -1,
                        "fragmented close_notify");
                    server.shutdownOutput();
                    require(client.read(ByteBuffer.allocate(1)) == -1,
                        "reverse close_notify");
                    sender.get(5, TimeUnit.SECONDS);
                    forward.get(5, TimeUnit.SECONDS);
                    backward.get(5, TimeUnit.SECONDS);
                }
            }
        } finally {
            relay.shutdownNow();
            require(relay.awaitTermination(5, TimeUnit.SECONDS),
                "relay workers stopped");
        }
    }

    /** Verify read shutdown preserves handshake and writes. */
      private static void
    inputShutdown() throws Exception
    {
        try (Pair pair = new Pair()) {
            pair.myClient.shutdownInput();
            require(pair.myClient.read(ByteBuffer.allocate(1)) == -1,
                "local input shutdown EOF");
            pair.myClient.write(ByteBuffer.wrap(new byte[] { 73 }));
            pair.myClient.shutdownOutput();
            ByteBuffer received = ByteBuffer.allocate(1);
            require(pair.myServer.read(received) == 1 && received.get(0) == 73,
                "handshake and queued output survive local " + "read shutdown");
            require(pair.myServer.read(ByteBuffer.allocate(1)) == -1,
                "output drained with close_notify");
        }
    }

    /** Verify selected key retention and zero-interest transition. */
      private static void
    interestTransitions() throws Exception
    {
        try (Pair pair = new Pair();
            TlsSelector selector = pair.myProvider.openSelector()) {
            pair.myServer.configureBlocking(false);
            SelectionKey key =
                pair.myServer.register(selector, SelectionKey.OP_READ);
            pair.myClient.write(ByteBuffer.wrap(new byte[] { 1 }));
            require(selector.select(3000) > 0, "initial readiness");
            long start = System.nanoTime();
            selector.select(2000);
            require(System.nanoTime() - start < 500_000_000L,
                "retained ready key does not block");
            key.interestOps(0);
            selector.selectedKeys().clear();
            require(selector.select(50) == 0,
                "zero interests suppress application notification");
            key.interestOps(SelectionKey.OP_READ);
            require(selector.select(1000) > 0,
                "restored interest sees buffered bytes");
        }
    }

    /** Verify interrupt closes blocked TLS channel. */
      private static void
    interruptRead() throws Exception
    {
        try (Pair pair = new Pair()) {
            CountDownLatch entering = new CountDownLatch(1);
            CompletableFuture<Boolean> observed = new CompletableFuture<>();
            Thread reader = new Thread(() -> {
                entering.countDown();
                try {
                    pair.myClient.read(ByteBuffer.allocate(1));
                    observed.complete(false);
                } catch (ClosedByInterruptException expected) {
                    observed.complete(Thread.currentThread().isInterrupted());
                } catch (IOException error) {
                    observed.completeExceptionally(error);
                }
            });
            reader.start();
            entering.await();
            reader.interrupt();
            require(observed.get(3, TimeUnit.SECONDS) &&
                !pair.myClient.isOpen(), "interrupt contract");
            reader.join(1000);
            require(!reader.isAlive(), "reader terminated");
        }
    }

    /**
     * Verify that preexisting interruption leaves nonblocking connect and
     * accept usable.
     */
      private static void
    interruptedConnectAndAccept(ServerSocketChannel listener,
        SocketChannel client) throws Exception
    {
        listener.bind(loopback());
        listener.configureBlocking(false);
        client.configureBlocking(false);
        SocketChannel accepted = null;
        Thread.currentThread().interrupt();
        try {
            require(listener.accept() == null && listener.isOpen(),
                "interrupted nonblocking accept remains open");
            long limit = System.nanoTime() + 2_000_000_000L;
            if (!client.connect(listener.getLocalAddress())) {
                while (!client.finishConnect()) {
                    require(System.nanoTime() < limit,
                        "nonblocking connection timeout");
                }
            }
            while (true) {
                accepted = listener.accept();
                if (accepted != null) {
                    break;
                }
                require(System.nanoTime() < limit,
                    "nonblocking accept timeout");
            }
            require(client.isConnected() && accepted.isConnected() &&
                Thread.currentThread().isInterrupted(),
                "TCP establishment preserves channels and " + "interrupt flag");
        } finally {
            Thread.interrupted();
            if (accepted != null) {
                accepted.close();
            }
        }
    }

    /**
     * Verify that preexisting interruption neither closes nonblocking I/O nor
     * clears the flag.
     */
      private static void
    interruptedNonblockingIO(SocketChannel channel) throws Exception
    {
        channel.configureBlocking(false);
        Thread.currentThread().interrupt();
        try {
            require(channel.write(ByteBuffer.wrap(new byte[] { 1 })) == 1,
                "nonblocking write with interrupt flag set");
            require(channel.read(ByteBuffer.allocate(1)) == 0,
                "nonblocking read with interrupt flag set");
            require(channel.isOpen() && Thread.currentThread().isInterrupted(),
                "channel and interrupt state preserved");
        } finally {
            Thread.interrupted();
        }
    }

    /** Verify standard JSSE server interoperability. */
      private static void
    jsseServer() throws Exception
    {
        try (SSLServerSocket listener =
            (SSLServerSocket) theContext.getServerSocketFactory()
            .createServerSocket(0, 50, InetAddress.getLoopbackAddress());
            TlsProvider provider = new TlsProvider(theContext);
            TlsSocketChannel client = provider.openSocketChannel("localhost")) {
            ExecutorService executor = Executors.newSingleThreadExecutor();
            try {
                Future<Integer> peer = executor.submit(() -> {
                    try (SSLSocket socket = (SSLSocket) listener.accept()) {
                        socket.setSoTimeout(5000);
                        int b = socket.getInputStream().read();
                        socket.getOutputStream().write(b + 1);
                        return b;
                    }
                });
                client.connect(listener.getLocalSocketAddress());
                client.write(ByteBuffer.wrap(new byte[] { 19 }));
                ByteBuffer reply = ByteBuffer.allocate(1);
                require(client.read(reply) == 1 && reply.get(0) == 20,
                    "JSSE peer response");
                require(peer.get(5, TimeUnit.SECONDS) == 19,
                    "JSSE peer request");
            } finally {
                executor.shutdownNow();
            }
        }
    }

    /** Verify large bidirectional transfer and output drain. */
      private static void
    largeTransfer() throws Exception
    {
        try (Pair pair = new Pair()) {
            byte[] expected = new byte[1024 * 1024];
            new Random(91).nextBytes(expected);
            ExecutorService executor = Executors.newFixedThreadPool(2);
            try {
                Future<byte[]> received = executor.submit(() -> {
                    ByteArrayOutputStream result = new ByteArrayOutputStream();
                    ByteBuffer buffer = ByteBuffer.allocate(7919);
                    while (pair.myServer.read(buffer) >= 0) {
                        buffer.flip();
                        byte[] part = new byte[buffer.remaining()];
                        buffer.get(part);
                        result.write(part);
                        buffer.clear();
                    }
                    pair.myServer.write(ByteBuffer.wrap(new byte[] { 77 }));
                    pair.myServer.shutdownOutput();
                    return result.toByteArray();
                });
                Future<Integer> response = executor.submit(() -> {
                    ByteBuffer buffer = ByteBuffer.allocate(1);
                    int n = pair.myClient.read(buffer);
                    return n < 0 ? -1 : (int) buffer.get(0);
                });
                ByteBuffer source = ByteBuffer.wrap(expected);
                while (source.hasRemaining()) {
                    pair.myClient.write(source);
                }
                pair.myClient.shutdownOutput();
                require(Arrays.equals(expected, received.get(10,
                    TimeUnit.SECONDS)), "large payload and close drain");
                require(response.get(5, TimeUnit.SECONDS) == 77,
                    "half-close preserves reverse direction");
                require(pair.myClient.session().getProtocol().equals("TLSv1.3"),
                    "large-transfer TLS 1.3");
                require(pair.myClient.session().getCipherSuite()
                    .contains("GCM"), "key-limit cipher selected");
            } finally {
                executor.shutdownNow();
            }
        }
    }

    /** Return an ephemeral IPv4 loopback address for an isolated listener. */
      private static InetSocketAddress
    loopback()
    {
        return new InetSocketAddress("127.0.0.1", 0);
    }

    /**
     * Run the ConformanceTest entry point with its documented command-line
     * arguments.
     */
      public static void
    main(String[] args) throws Exception
    {
        boolean keyUpdates = args.length == 1 && args[0].equals("key-updates");
        if (keyUpdates) {
            Security.setProperty("jdk.tls.keyLimits",
                "AES/GCM/NoPadding KeyUpdate 16384");
        }
        Path credentials = Files.createTempDirectory("SelectableTLS-Test-");
        try {
            theContext = certificateContext(credentials);
            if (args.length == 2 && args[0].equals("lifecycle")) {
                int repetitions = Integer.parseInt(args[1]);
                require(repetitions > 0, "positive lifecycle repetitions");
                closeRegistrationGap();
                for (int i = 0; i < repetitions; i++) {
                    interruptRead();
                    closeDrainsOutput("TLSv1.3");
                }
                System.out.println("Verified " + repetitions +
                    " interrupt/close-drain repetitions on " +
                    System.getProperty("java.version"));
                return;
            }
            if (keyUpdates) {
                test("TLS 1.3 key updates during sustained transfer",
                    ConformanceTest::largeTransfer);
                System.out.println("Verified forced-key-update transfer on " +
                    System.getProperty("java.version"));
                return;
            }
            test("plaintext registration, cancellation and wakeup",
                ConformanceTest::plaintext);
            test("TLS with write-only interests and buffered " +
                "read readiness", ConformanceTest::tlsSelection);
            test("concurrent blocking reader and writer",
                ConformanceTest::concurrentReadWrite);
            test("standard JSSE server interoperability",
                ConformanceTest::jsseServer);
            test("hostname validation rejects wrong name",
                ConformanceTest::wrongHostname);
            test("untrusted certificate rejection",
                ConformanceTest::wrongTrust);
            test("asynchronous close releases blocked reader",
                ConformanceTest::asynchronousClose);
            test("large bidirectional transfer and output drain",
                ConformanceTest::largeTransfer);
            test("socket streams support duplex and read timeout",
                ConformanceTest::socketStreams);
            test("one TLS channel registered with two selectors",
                ConformanceTest::multipleSelectors);
            test("server socket adapter timeout and secure stream",
                ConformanceTest::serverSocketAdapter);
            test("selector close releases pending selection",
                ConformanceTest::selectorClose);
            test("nonblocking connect and scattering/gathering",
                ConformanceTest::nonblockingConnect);
            test("TLS 1.2 interoperability", () -> protocol("TLSv1.2"));
            test("TLS 1.3 interoperability", () -> protocol("TLSv1.3"));
            test("required client certificate",
                ConformanceTest::clientCertificate);
            test("bounded queue applies backpressure to " + "stalled handshake",
                ConformanceTest::backpressure);
            test("interrupt closes blocked TLS channel",
                ConformanceTest::interruptRead);
            test("transport registration spans logical close",
                ConformanceTest::closeRegistrationGap);
            test("selected key retention and zero-interest transition",
                ConformanceTest::interestTransitions);
            test("read shutdown preserves handshake and writes",
                ConformanceTest::inputShutdown);
            test("missing required client certificate rejected",
                ConformanceTest::missingClientCertificate);
            test("truncated TLS stream reports failure",
                ConformanceTest::truncatedStream);
            test("selector callback receives TLS readiness",
                ConformanceTest::selectionCallback);
            test("provider close releases all owned resources",
                ConformanceTest::providerClose);
            test("fragmented records and close_notify",
                ConformanceTest::fragmentedTransport);
            test("stalled handshake deadline", () -> stalledDeadline(false));
            test("stalled output shutdown deadline", () ->
                stalledDeadline(true));
            test("completed handshake cancels deadline",
                ConformanceTest::completedDeadline);
            test("selector accepts maximum timeout",
                ConformanceTest::maximumSelectTimeout);
            test("TLS 1.2 close drains already accepted output", () ->
                closeDrainsOutput("TLSv1.2"));
            test("TLS 1.3 close drains already accepted output", () ->
                closeDrainsOutput("TLSv1.3"));
            test("close deadline bounds waiting for peer close_notify",
                ConformanceTest::closePeerDeadline);
            test("closed TLS channel rejects options and " +
                "address queries during drain",
                ConformanceTest::closedChannelOperations);
            test("selector honors its public synchronization monitor",
                ConformanceTest::selectorMonitor);
            test("registration racing selector close leaves " +
                "no registration", ConformanceTest::registrationCloseRace);
            test("positive linger is bounded without " +
                "blocking shared TLS progress",
                ConformanceTest::positiveLinger);
            test("abort interrupts a concurrent lingering close",
                ConformanceTest::abortLinger);
            test("blocking-mode changes leave pending reads unchanged",
                ConformanceTest::pendingReadMode);
            test("blocking-mode changes leave pending writes unchanged",
                ConformanceTest::pendingWriteMode);
            test("blocking-mode changes leave pending " + "accepts unchanged",
                ConformanceTest::pendingAcceptMode);
            test("positive linger completes a successful TLS drain",
                ConformanceTest::successfulLinger);
            test("interest changes apply on the next selection",
                ConformanceTest::selectionInterestSnapshot);
            test("preexisting interruption does not close " + "nonblocking I/O",
                ConformanceTest::nonblockingInterrupt);
            test("preexisting interruption preserves " +
                "nonblocking connect and accept",
                ConformanceTest::nonblockingConnectInterrupt);
            test("socket adapters preserve Socket exception contracts",
                ConformanceTest::socketAdapterErrors);
            test("channel and socket options agree",
                ConformanceTest::socketOptions);
            test("buffer boundaries and empty gathering writes",
                ConformanceTest::bufferBoundaries);
            test("failed nonblocking connect closes channel",
                ConformanceTest::failedConnect);
            test("socket retains connected state after close",
                ConformanceTest::socketConnectedAfterClose);
            test("zero linger explicitly aborts TLS",
                ConformanceTest::zeroLinger);
            test("bounded delegated tasks fail excess " +
                "handshakes and recover", ConformanceTest::taskSaturation);
            test("TLS, native pipes and datagrams share a selector",
                ConformanceTest::mixedNativeChannels);
            test("explicit IPv4 TLS family", () ->
                addressFamily(StandardProtocolFamily.INET, "127.0.0.1"));
            test("explicit IPv6 TLS family", () ->
                addressFamily(StandardProtocolFamily.INET6, "::1"));
            test("TLS 1.2 renegotiation with queued output",
                ConformanceTest::renegotiation);
            test("inbound traffic progresses while outbound " +
                "TCP is blocked", ConformanceTest::blockedOutputDuplex);
            System.out.println("Verified " + theTests +
                " conformance scenarios on " +
                System.getProperty("java.version"));
            /*
             * JSSE reads key-limit policy at initialization. Use an isolated
             * JVM for frequent key updates without changing the ordinary test
             * policy.
             */
            Process updates =
                new ProcessBuilder(Path.of(System.getProperty("java.home"),
                "bin/java").toString(), "-ea", "-cp",
                System.getProperty("java.class.path"),
                ConformanceTest.class.getName(), "key-updates").inheritIO()
                .start();
            if (!updates.waitFor(35, TimeUnit.SECONDS)) {
                updates.destroyForcibly();
                updates.waitFor();
                throw new AssertionError("key-update test timed out");
            }
            require(updates.exitValue() == 0, "key-update subprocess failed");
        } finally {
            try (var paths = Files.walk(credentials)) {
                for (Path path : paths.sorted(Comparator.reverseOrder())
                    .toList())
                {
                    Files.delete(path);
                }
            }
        }
    }

    /** Verify selector accepts maximum timeout. */
      private static void
    maximumSelectTimeout() throws Exception
    {
        try (TlsProvider provider = new TlsProvider(theContext);
            TlsSelector selector = provider.openSelector()) {
            selector.wakeup();
            require(selector.select(Long.MAX_VALUE) == 0,
                "positive long timeout must be accepted");
        }
    }

    /** Verify missing required client certificate rejected. */
      private static void
    missingClientCertificate() throws Exception
    {
        try (TlsProvider serverProvider = new TlsProvider(theContext);
            TlsProvider clientProvider =
                new TlsProvider(theClientWithoutIdentity);
            TlsServerSocketChannel listener =
                serverProvider.openServerSocketChannel();
            TlsSocketChannel client =
                clientProvider.openSocketChannel("localhost")) {
            serverProvider.setNeedClientAuth(true);
            listener.bind(loopback());
            client.connect(listener.getLocalAddress());
            try (TlsSocketChannel server = listener.accept()) {
                client.write(ByteBuffer.wrap(new byte[] { 1 }));
                boolean rejected = false;
                try {
                    server.read(ByteBuffer.allocate(1));
                } catch (SSLException expected) {
                    rejected = true;
                }
                require(rejected && !server.handshakeComplete(),
                    "unauthenticated client data rejected");
            }
        }
    }

    /** Verify tLS, native pipes and datagrams share a selector. */
      private static void
    mixedNativeChannels() throws Exception
    {
        try (Pair pair = new Pair();
            TlsSelector selector = pair.myProvider.openSelector()) {
            Pipe pipe = pair.myProvider.openPipe();
            try (Pipe.SourceChannel source = pipe.source();
                Pipe.SinkChannel sink = pipe.sink();
                DatagramChannel receiver =
                    pair.myProvider.openDatagramChannel();
                DatagramChannel sender =
                    pair.myProvider.openDatagramChannel()) {
                pair.myServer.configureBlocking(false);
                source.configureBlocking(false);
                receiver.configureBlocking(false);
                receiver.bind(loopback());
                pair.myServer.register(selector, SelectionKey.OP_READ, "tls");
                source.register(selector, SelectionKey.OP_READ, "pipe");
                receiver.register(selector, SelectionKey.OP_READ, "datagram");
                pair.myClient.write(ByteBuffer.wrap(new byte[] { 1 }));
                sink.write(ByteBuffer.wrap(new byte[] { 2 }));
                sender.send(ByteBuffer.wrap(new byte[] { 3 }),
                    receiver.getLocalAddress());
                Set<String> seen = new HashSet<>();
                long limit = System.nanoTime() + 3_000_000_000L;
                while (seen.size() != 3) {
                    require(System.nanoTime() < limit,
                        "mixed selection deadline");
                    selector.select(1000);
                    for (SelectionKey key : selector.selectedKeys()) {
                        ByteBuffer value = ByteBuffer.allocate(1);
                        String type = (String) key.attachment();
                        if (type.equals("tls")) {
                            require(pair.myServer.read(value) == 1 &&
                                value.get(0) == 1, "TLS readiness");
                        } else if (type.equals("pipe")) {
                            require(source.read(value) == 1 && value.get(0) ==
                                2, "pipe readiness");
                        } else {
                            require(receiver.receive(value) != null &&
                                value.get(0) == 3, "datagram readiness");
                        }
                        seen.add(type);
                        key.cancel();
                    }
                    selector.selectedKeys().clear();
                }
            }
        }
    }

    /** Verify one TLS channel registered with two selectors. */
      private static void
    multipleSelectors() throws Exception
    {
        try (Pair pair = new Pair();
            TlsSelector one = pair.myProvider.openSelector();
            TlsSelector two = pair.myProvider.openSelector()) {
            pair.myServer.configureBlocking(false);
            SelectionKey first =
                pair.myServer.register(one, SelectionKey.OP_READ);
            SelectionKey second =
                pair.myServer.register(two, SelectionKey.OP_READ);
            pair.myClient.write(ByteBuffer.wrap(new byte[] { 8 }));
            require(one.select(3000) > 0 && two.select(3000) > 0,
                "both registrations receive readiness");
            first.cancel();
            one.selectNow();
            require(pair.myServer.isRegistered() && second.isValid(),
                "one cancellation does not remove other registration");
            require(pair.myServer.read(ByteBuffer.allocate(1)) == 1,
                "read after cancellation");
            two.selectedKeys().clear();
            require(two.select(50) == 0, "other selector sees drained buffer");
        }
    }

    /** Verify nonblocking connect and scattering/gathering. */
      private static void
    nonblockingConnect() throws Exception
    {
        try (TlsProvider provider = new TlsProvider(theContext);
            TlsSelector selector = provider.openSelector();
            TlsServerSocketChannel listener =
                provider.openServerSocketChannel();
            TlsSocketChannel client = provider.openSocketChannel("localhost")) {
            listener.bind(loopback());
            client.configureBlocking(false);
            boolean immediate = client.connect(listener.getLocalAddress());
            SelectionKey key =
                client.register(selector, SelectionKey.OP_CONNECT);
            if (!immediate) {
                require(selector.select(3000) > 0 && key.isConnectable(),
                    "connect readiness");
                require(client.finishConnect(), "finishConnect");
            }
            key.interestOps(0);
            selector.selectedKeys().clear();
            try (TlsSocketChannel server = listener.accept()) {
                ByteBuffer[] buffers =
                    { ByteBuffer.wrap(new byte[] { 1, 2 }),
                    ByteBuffer.wrap(new byte[] { 3, 4 }) };
                require(client.write(buffers) == 4, "gathering write");
                ByteBuffer a = ByteBuffer.allocate(2);
                ByteBuffer b = ByteBuffer.allocate(2);
                long total = 0;
                while (total < 4) {
                    total += server.read(new ByteBuffer[] { a, b });
                }
                require(a.get(1) == 2 && b.get(1) == 4, "scattering read");
            }
        }
    }

    /**
     * Verify preexisting interruption preserves nonblocking connect and accept.
     */
      private static void
    nonblockingConnectInterrupt() throws Exception
    {
        try (ServerSocketChannel listener = ServerSocketChannel.open();
            SocketChannel client = SocketChannel.open()) {
            interruptedConnectAndAccept(listener, client);
        }
        try (TlsProvider provider = new TlsProvider(theContext);
            TlsServerSocketChannel listener =
                provider.openServerSocketChannel();
            TlsSocketChannel client = provider.openSocketChannel("localhost")) {
            interruptedConnectAndAccept(listener, client);
        }
    }

    /** Verify preexisting interruption does not close nonblocking I/O. */
      private static void
    nonblockingInterrupt() throws Exception
    {
        /*
         * Check the native implementation in the same JVM as the TLS contract.
         */
        try (ServerSocketChannel listener = ServerSocketChannel.open()) {
            listener.bind(loopback());
            try (SocketChannel client =
                SocketChannel.open(listener.getLocalAddress());
                SocketChannel server = listener.accept()) {
                require(server.isConnected(), "native reference accepted");
                interruptedNonblockingIO(client);
            }
        }
        try (Pair pair = new Pair()) {
            interruptedNonblockingIO(pair.myClient);
        }
    }

    /** Check that channel and Socket option access agree. */
      private static void
    options(SocketChannel channel) throws Exception
    {
        Socket socket = channel.socket();
        require(channel.supportedOptions()
            .containsAll(Set.of(StandardSocketOptions.SO_SNDBUF,
            StandardSocketOptions.SO_RCVBUF, StandardSocketOptions.SO_KEEPALIVE,
            StandardSocketOptions.SO_REUSEADDR, StandardSocketOptions.SO_LINGER,
            StandardSocketOptions.TCP_NODELAY)),
            "required Internet socket options");
        channel.setOption(StandardSocketOptions.TCP_NODELAY, true);
        require(socket.getTcpNoDelay(), "channel to socket option");
        socket.setTcpNoDelay(false);
        require(!channel.getOption(StandardSocketOptions.TCP_NODELAY),
            "socket to channel option");
        socket.setKeepAlive(true);
        require(channel.getOption(StandardSocketOptions.SO_KEEPALIVE),
            "keepalive");
        socket.setReuseAddress(true);
        require(channel.getOption(StandardSocketOptions.SO_REUSEADDR),
            "reuse address");
        socket.setSendBufferSize(16384);
        socket.setReceiveBufferSize(16384);
        require(socket.getSendBufferSize() > 0 &&
            socket.getReceiveBufferSize() > 0, "buffer size hints accepted");
        socket.setSoLinger(true, 2);
        require(channel.getOption(StandardSocketOptions.SO_LINGER) == 2,
            "positive linger option");
        channel.setOption(StandardSocketOptions.SO_LINGER, -1);
        require(socket.getSoLinger() == -1, "linger disabled");
    }

    /** Verify blocking-mode changes leave pending accepts unchanged. */
      private static void
    pendingAcceptMode() throws Exception
    {
        try (TlsProvider provider = new TlsProvider(theContext);
            TlsServerSocketChannel listener =
                provider.openServerSocketChannel()) {
            listener.bind(loopback());
            ExecutorService executor = Executors.newSingleThreadExecutor();
            try {
                Future<TlsSocketChannel> pending =
                    executor.submit(listener::accept);
                long limit = System.nanoTime() + 2_000_000_000L;
                while (!listener.myRaw.isRegistered() &&
                    System.nanoTime() < limit)
                {
                    Thread.sleep(1);
                }
                require(listener.myRaw.isRegistered(),
                    "accept entered its blocking selector wait");
                listener.configureBlocking(false);
                try {
                    pending.get(200, TimeUnit.MILLISECONDS);
                    throw new AssertionError(
                        "mode change altered pending accept");
                } catch (TimeoutException expected) {
                    /* remains blocking */
                }
                try (SocketChannel client =
                    SocketChannel.open(listener.getLocalAddress());
                    TlsSocketChannel accepted =
                        pending.get(2, TimeUnit.SECONDS)) {
                    require(client.isConnected() && accepted.isConnected(),
                        "pending accept receives connection");
                    require(listener.accept() == null,
                        "next accept is nonblocking");
                }
            } finally {
                executor.shutdownNow();
            }
        }
    }

    /** Verify blocking-mode changes leave pending reads unchanged. */
      private static void
    pendingReadMode() throws Exception
    {
        try (Pair pair = new Pair()) {
            ExecutorService executor = Executors.newSingleThreadExecutor();
            CountDownLatch started = new CountDownLatch(1);
            Thread[] readerThread = new Thread[1];
            try {
                Future<Integer> pending = executor.submit(() -> {
                    readerThread[0] = Thread.currentThread();
                    started.countDown();
                    return pair.myClient.read(ByteBuffer.allocate(1));
                });
                require(started.await(2, TimeUnit.SECONDS), "reader started");
                long limit = System.nanoTime() + 2_000_000_000L;
                while (readerThread[0].getState() != Thread.State.WAITING &&
                    System.nanoTime() < limit)
                {
                    Thread.sleep(1);
                }
                require(readerThread[0].getState() == Thread.State.WAITING,
                    "read entered blocking wait");
                pair.myClient.configureBlocking(false);
                /* independent write wakes channel state waiters */
                pair.myClient.write(ByteBuffer.wrap(new byte[] { 9 }));
                try {
                    pending.get(150, TimeUnit.MILLISECONDS);
                    throw new AssertionError(
                        "mode change altered pending read");
                } catch (TimeoutException expected) {
                    /* original operation remains blocking */
                }
                pair.myServer.write(ByteBuffer.wrap(new byte[] { 42 }));
                require(pending.get(2, TimeUnit.SECONDS) == 1,
                    "original read receives input");
                require(pair.myClient.read(ByteBuffer.allocate(1)) == 0,
                    "subsequent read is nonblocking");
            } finally {
                executor.shutdownNow();
            }
        }
    }

    /** Verify blocking-mode changes leave pending writes unchanged. */
      private static void
    pendingWriteMode() throws Exception
    {
        try (TlsProvider provider = new TlsProvider(theContext);
            ServerSocketChannel listener = ServerSocketChannel.open();
            TlsSocketChannel channel =
                provider.openSocketChannel("localhost")) {
            listener.bind(loopback());
            channel.connect(listener.getLocalAddress());
            try (SocketChannel peer = listener.accept()) {
                require(peer.isConnected(), "silent peer accepted");
                channel.configureBlocking(false);
                ByteBuffer fill = ByteBuffer.allocate(131072);
                while (channel.write(fill) != 0) {
                    /* bounded queue fills before authentication */
                }
                channel.configureBlocking(true);
                ExecutorService executor = Executors.newSingleThreadExecutor();
                CountDownLatch started = new CountDownLatch(1);
                Thread[] writer = new Thread[1];
                try {
                    Future<Integer> pending = executor.submit(() -> {
                        writer[0] = Thread.currentThread();
                        started.countDown();
                        return channel.write(ByteBuffer.wrap(
                            new byte[] { 42 }));
                    });
                    require(started.await(2, TimeUnit.SECONDS),
                        "writer started");
                    long limit = System.nanoTime() + 2_000_000_000L;
                    while (writer[0].getState() != Thread.State.WAITING &&
                        System.nanoTime() < limit)
                    {
                        Thread.sleep(1);
                    }
                    require(writer[0].getState() == Thread.State.WAITING,
                        "write entered blocking wait");
                    /* wake the pending write */
                    channel.configureBlocking(false);
                    /* wake the pending write */
                    channel.shutdownInput();
                    try {
                        pending.get(150, TimeUnit.MILLISECONDS);
                        throw new AssertionError(
                            "mode change altered pending write");
                    } catch (TimeoutException expected) {
                        /* remains blocking */
                    }
                    channel.abort();
                    try {
                        pending.get(2, TimeUnit.SECONDS);
                        throw new AssertionError(
                            "aborted pending write succeeded");
                    } catch (ExecutionException expected) {
                        require(expected.getCause(
                            ) instanceof AsynchronousCloseException,
                            "asynchronous writer close");
                    }
                } finally {
                    executor.shutdownNow();
                }
            }
        }
    }

    /** Verify plaintext registration, cancellation and wakeup. */
      private static void
    plaintext() throws Exception
    {
        try (TlsProvider provider = new TlsProvider(theContext);
            TlsSelector selector = provider.openSelector();
            ServerSocketChannel listener = ServerSocketChannel.open();
            SocketChannel client = SocketChannel.open()) {
            listener.configureBlocking(false);
            listener.bind(loopback());
            SelectionKey listenerKey =
                listener.register(selector, SelectionKey.OP_ACCEPT, "listener");
            client.connect(listener.getLocalAddress());
            require(selector.select(2000) == 1, "plaintext accept readiness");
            require(selector.selectedKeys().contains(listenerKey),
                "selected listener");
            selector.selectedKeys().clear();
            try (SocketChannel server = listener.accept()) {
                server.configureBlocking(false);
                SelectionKey key =
                    server.register(selector, SelectionKey.OP_READ, "payload");
                client.write(ByteBuffer.wrap(new byte[] { 7 }));
                require(selector.select(2000) == 1, "plaintext read readiness");
                require(key.isReadable(), "read ready bit");
                require(key.attachment().equals("payload"), "attachment");
                require(server.read(ByteBuffer.allocate(1)) == 1,
                    "plaintext read");
                key.cancel();
                selector.selectNow();
                require(!selector.keys().contains(key) &&
                    !server.isRegistered(), "deregistration");
            }
            listenerKey.cancel();
            selector.selectNow();
            selector.wakeup();
            long start = System.nanoTime();
            selector.select(2000);
            require(System.nanoTime() - start < 500_000_000L, "sticky wakeup");
            require(selector.keys().isEmpty(), "no leaked keys");
        }
    }

    /**
     * Verify positive linger is bounded without blocking shared TLS progress.
     * Closing on another thread is the behavior under test.
     */
    @SuppressWarnings("try")
      private static void
    positiveLinger() throws Exception
    {
        try (Pair pair = new Pair();
            ServerSocketChannel listener = ServerSocketChannel.open();
            TlsSocketChannel stalled =
                pair.myProvider.openSocketChannel("localhost")) {
            listener.bind(loopback());
            stalled.connect(listener.getLocalAddress());
            try (SocketChannel peer = listener.accept()) {
                require(peer.isConnected(), "stalled peer accepted");
                stalled.socket().setSoLinger(true, 1);
                require(stalled.getOption(StandardSocketOptions.SO_LINGER) == 1,
                    "adapter/channel linger agreement");
                stalled.write(ByteBuffer.wrap(new byte[] { 9 }));
                ExecutorService executor = Executors.newSingleThreadExecutor();
                try {
                    Future<?> closure = executor.submit(() -> {
                        stalled.close();
                        return null;
                    });
                    try {
                        closure.get(150, TimeUnit.MILLISECONDS);
                        throw new AssertionError(
                            "positive linger returned before stalled drain");
                    } catch (TimeoutException expected) {
                        /* close is waiting on this caller only */
                    }
                    pair.myClient.write(ByteBuffer.wrap(new byte[] { 42 }));
                    pair.myServer.socket().setSoTimeout(1000);
                    require(pair.myServer.socket().getInputStream().read() ==
                        42, "shared reactor progressed during linger");
                    closure.get(3, TimeUnit.SECONDS);
                    require(!stalled.myRaw.isOpen(),
                        "linger timeout closes transport");
                } finally {
                    executor.shutdownNow();
                }
            }
        }
    }

    /** Exchange application data using the specified TLS version. */
      private static void
    protocol(String protocol) throws Exception
    {
        try (TlsProvider provider = new TlsProvider(theContext);
            TlsServerSocketChannel listener =
                provider.openServerSocketChannel();
            TlsSocketChannel client = provider.openSocketChannel("localhost")) {
            provider.setEnabledProtocols(protocol);
            listener.bind(loopback());
            client.connect(listener.getLocalAddress());
            try (TlsSocketChannel server = listener.accept()) {
                client.write(ByteBuffer.wrap(new byte[] { 99 }));
                require(server.read(ByteBuffer.allocate(1)) == 1,
                    "protocol read");
                require(client.session().getProtocol().equals(protocol),
                    "negotiated protocol " + protocol);
            }
        }
    }

    /** Verify provider close releases all owned resources. */
      private static void
    providerClose() throws Exception
    {
        TlsProvider provider = new TlsProvider(theContext);
        try (TlsSocketChannel unconnected = provider.openSocketChannel();
            TlsServerSocketChannel listener =
                provider.openServerSocketChannel();
            TlsSelector selector = provider.openSelector();
            SocketChannel nativeChannel = SocketChannel.open()) {
            listener.bind(loopback());
            nativeChannel.configureBlocking(false);
            nativeChannel.register(selector, 0);
            provider.close();
            require(!unconnected.isOpen() && !listener.isOpen() &&
                !selector.isOpen(), "owned resources closed");
            require(nativeChannel.isOpen() && !nativeChannel.isRegistered(),
                "native caller resource preserved and deregistered");
            boolean rejected = false;
            try {
                provider.openSocketChannel();
            } catch (ClosedChannelException expected) {
                rejected = true;
            }
            require(rejected, "closed provider rejects new sockets");
        } finally {
            provider.close();
        }
    }

    /**
     * Verify registration racing selector close leaves no registration.
     * Explicit racing close is the behavior under test; try closes on failures.
     */
    @SuppressWarnings("try")
      private static void
    registrationCloseRace() throws Exception
    {
        try (TlsProvider provider = new TlsProvider(theContext)) {
            ExecutorService executor = Executors.newFixedThreadPool(2);
            try {
                for (int i = 0; i < 300; i++) {
                    try (TlsSelector selector = provider.openSelector();
                        SocketChannel channel = SocketChannel.open()) {
                        channel.configureBlocking(false);
                        CyclicBarrier start = new CyclicBarrier(2);
                        Future<?> registration = executor.submit(() -> {
                            start.await();
                            try {
                                channel.register(selector,
                                    SelectionKey.OP_READ);
                            } catch (ClosedSelectorException expected) {
                                /* closure won */
                            }
                            return null;
                        });
                        Future<?> closure = executor.submit(() -> {
                            start.await();
                            selector.close();
                            return null;
                        });
                        registration.get(3, TimeUnit.SECONDS);
                        closure.get(3, TimeUnit.SECONDS);
                        require(!channel.isRegistered(),
                            "closed selector retained registration " +
                                "at iteration " + i);
                    }
                }
            } finally {
                executor.shutdownNow();
            }
        }
    }

    /**
     * Verify that authentication fails for the supplied trust configuration or
     * peer name.
     */
      private static void
    rejection(SSLContext clientContext, String name) throws Exception
    {
        try (TlsProvider serverProvider = new TlsProvider(theContext);
            TlsProvider clientProvider = new TlsProvider(clientContext);
            TlsServerSocketChannel listener =
                serverProvider.openServerSocketChannel();
            TlsSocketChannel client = clientProvider.openSocketChannel(name)) {
            listener.bind(loopback());
            client.connect(listener.getLocalAddress());
            try (TlsSocketChannel server = listener.accept();
                TlsSelector selector = clientProvider.openSelector()) {
                client.configureBlocking(false);
                SelectionKey key =
                    client.register(selector, SelectionKey.OP_READ);
                require(selector.select(5000) > 0 && key.isReadable(),
                    "failure must wake interested readers");
                boolean rejected = false;
                try {
                    client.read(ByteBuffer.allocate(1));
                } catch (SSLException expected) {
                    rejected = true;
                }
                require(rejected, "certificate rejection");
                require(!client.handshakeComplete(), "not authenticated");
                require(server.isOpen(), "server wrapper still closeable");
            }
        }
    }

    /** Verify tLS 1.2 renegotiation with queued output. */
      private static void
    renegotiation() throws Exception
    {
        try (SSLServerSocket listener =
            (SSLServerSocket) theContext.getServerSocketFactory()
            .createServerSocket(0, 50, InetAddress.getLoopbackAddress());
            TlsProvider provider = new TlsProvider(theContext);
            TlsSocketChannel client = provider.openSocketChannel("localhost")) {
            listener.setEnabledProtocols(new String[] { "TLSv1.2" });
            provider.setEnabledProtocols("TLSv1.2");
            ExecutorService executor = Executors.newSingleThreadExecutor();
            byte[] payload = new byte[1024 * 1024];
            new Random(321).nextBytes(payload);
            try {
                Future<?> peer = executor.submit(() -> {
                    try (SSLSocket socket = (SSLSocket) listener.accept()) {
                        socket.setSoTimeout(5000);
                        InputStream input = socket.getInputStream();
                        require(input.read() == 7, "initial TLS 1.2 exchange");
                        socket.startHandshake();
                        require(Arrays.equals(input.readNBytes(payload.length),
                            payload), "renegotiated payload");
                        socket.getOutputStream().write(77);
                    }
                    return null;
                });
                client.connect(listener.getLocalSocketAddress());
                client.write(ByteBuffer.wrap(new byte[] { 7 }));
                ByteBuffer source = ByteBuffer.wrap(payload);
                while (source.hasRemaining()) {
                    client.write(source);
                }
                ByteBuffer response = ByteBuffer.allocate(1);
                require(client.read(response) == 1 && response.get(0) == 77,
                    "renegotiation response");
                peer.get(6, TimeUnit.SECONDS);
            } finally {
                executor.shutdownNow();
            }
        }
    }

    /**
     * Fail the scenario with its diagnostic message when an invariant is false.
     */
      private static void
    require(boolean value, String message)
    {
        if (!value) {
            throw new AssertionError(message);
        }
    }

    /** Verify selector callback receives TLS readiness. */
      private static void
    selectionCallback() throws Exception
    {
        try (Pair pair = new Pair();
            TlsSelector selector = pair.myProvider.openSelector()) {
            pair.myServer.configureBlocking(false);
            SelectionKey expected =
                pair.myServer.register(selector, SelectionKey.OP_READ,
                "callback");
            pair.myClient.write(ByteBuffer.wrap(new byte[] { 31 }));
            List<SelectionKey> callbacks = new ArrayList<>();
            int count = selector.select(key -> {
                require(key == expected && key.isReadable(),
                    "callback readiness and identity");
                callbacks.add(key);
            }, 3000);
            require(count == 1 && callbacks.size() == 1,
                "callback invoked once");
            require(selector.selectedKeys().isEmpty(),
                "callback does not retain selected key");
            require(pair.myServer.read(ByteBuffer.allocate(1)) == 1,
                "callback data");
        }
    }

    /** Verify interest changes apply on the next selection. */
      private static void
    selectionInterestSnapshot() throws Exception
    {
        try (Pair pair = new Pair();
            TlsSelector selector = pair.myProvider.openSelector()) {
            pair.myClient.write(ByteBuffer.wrap(new byte[] { 1 }));
            pair.myServer.read(ByteBuffer.allocate(1));
            pair.myClient.configureBlocking(false);
            SelectionKey key =
                pair.myClient.register(selector, SelectionKey.OP_READ);
            /* apply registration before the blocking selection */
            selector.selectNow();
            ExecutorService executor = Executors.newSingleThreadExecutor();
            try {
                Future<?> change = executor.submit(() -> {
                    Thread.sleep(150);
                    key.interestOps(SelectionKey.OP_WRITE);
                    selector.wakeup();
                    return null;
                });
                require(selector.select(3000) == 0,
                    "new write interest must not affect the " +
                    "pending selection");
                change.get(2, TimeUnit.SECONDS);
                require(selector.select(1000) == 1 && key.isWritable(),
                    "next selection applies changed interest");
            } finally {
                executor.shutdownNow();
            }
        }
    }

    /** Verify selector close releases pending selection. */
      private static void
    selectorClose() throws Exception
    {
        try (TlsProvider provider = new TlsProvider(theContext)) {
            TlsSelector selector = provider.openSelector();
            ExecutorService runner = Executors.newSingleThreadExecutor();
            try {
                CountDownLatch entering = new CountDownLatch(1);
                Future<Integer> selected = runner.submit(() -> {
                    entering.countDown();
                    try {
                        return selector.select();
                    } catch (ClosedSelectorException expected) {
                        return 0;
                    }
                });
                entering.await();
                selector.close();
                require(selected.get(2, TimeUnit.SECONDS) == 0,
                    "selector close releases select");
            } finally {
                selector.close();
                runner.shutdownNow();
            }
        }
    }

    /** Verify selector honors its public synchronization monitor. */
      private static void
    selectorMonitor() throws Exception
    {
        try (TlsProvider provider = new TlsProvider(theContext);
            TlsSelector selector = provider.openSelector()) {
            ExecutorService executor = Executors.newSingleThreadExecutor();
            try {
                Future<Integer> selection;
                CountDownLatch entered = new CountDownLatch(1);
                synchronized (selector) {
                    selection = executor.submit(() -> {
                        entered.countDown();
                        return selector.selectNow();
                    });
                    require(entered.await(2, TimeUnit.SECONDS),
                        "selection task started");
                    try {
                        selection.get(100, TimeUnit.MILLISECONDS);
                        throw new AssertionError(
                            "selection bypassed selector monitor");
                    } catch (TimeoutException expected) {
                        /* caller holds documented monitor */
                    }
                }
                require(selection.get(2, TimeUnit.SECONDS) == 0,
                    "selection proceeds after monitor release");
            } finally {
                executor.shutdownNow();
            }
        }
    }

    /** Verify server socket adapter timeout and secure stream. */
      private static void
    serverSocketAdapter() throws Exception
    {
        try (TlsProvider provider = new TlsProvider(theContext);
            TlsServerSocketChannel listener =
                provider.openServerSocketChannel();
            TlsSocketChannel client = provider.openSocketChannel("localhost")) {
            ServerSocket socket = listener.socket();
            socket.bind(loopback());
            socket.setSoTimeout(60);
            boolean timeout = false;
            try {
                socket.accept();
            } catch (SocketTimeoutException expected) {
                timeout = true;
            }
            require(timeout && listener.isOpen(),
                "accept timeout retains listener");
            client.socket().connect(socket.getLocalSocketAddress(), 2000);
            try (Socket peer = socket.accept()) {
                client.socket().getOutputStream().write(62);
                peer.setSoTimeout(3000);
                require(peer.getInputStream().read() == 62,
                    "server socket adapter uses TLS");
            }
        }
    }

    /** Check unbound and closed ServerSocket adapter failures. */
      private static void
    serverSocketErrors(ServerSocketChannel channel) throws Exception
    {
        ServerSocket socket = channel.socket();
        expectSocketError(socket::accept);
        socket.bind(loopback());
        expectSocketError(() -> socket.bind(loopback()));
        channel.close();
        expectIOError(socket::accept);
    }

    /** Verify socket adapters preserve Socket exception contracts. */
      private static void
    socketAdapterErrors() throws Exception
    {
        try (SocketChannel client = SocketChannel.open();
            ServerSocketChannel server = ServerSocketChannel.open()) {
            socketErrors(client);
            serverSocketErrors(server);
        }
        try (TlsProvider provider = new TlsProvider(theContext);
            TlsSocketChannel client = provider.openSocketChannel();
            TlsServerSocketChannel server =
                provider.openServerSocketChannel()) {
            socketErrors(client);
            serverSocketErrors(server);
        }
    }

    /** Verify socket retains connected state after close. */
      private static void
    socketConnectedAfterClose() throws Exception
    {
        try (Pair pair = new Pair()) {
            Socket socket = pair.myClient.socket();
            pair.myClient.close();
            require(socket.isConnected() && socket.isClosed() &&
                !pair.myClient.isConnected(),
                "Socket/channel connected-state distinction");
            require(socket.getLocalAddress().isAnyLocalAddress() &&
                ((InetSocketAddress) socket.getLocalSocketAddress())
                .getAddress().isAnyLocalAddress(),
                "closed socket local wildcard address");
            require(!socket.isInputShutdown() && !socket.isOutputShutdown(),
                "close does not invent explicit shutdown calls");
        }
    }

    /** Check unconnected, already-bound and closed Socket adapter failures. */
      private static void
    socketErrors(SocketChannel channel) throws Exception
    {
        Socket socket = channel.socket();
        expectSocketError(socket::getInputStream);
        expectSocketError(socket::getOutputStream);
        expectSocketError(socket::shutdownInput);
        expectSocketError(socket::shutdownOutput);
        socket.bind(loopback());
        expectSocketError(() -> socket.bind(loopback()));
        channel.close();
        expectSocketError(socket::getInputStream);
        expectSocketError(socket::getOutputStream);
        expectSocketError(() -> socket.setTcpNoDelay(true));
        expectSocketError(socket::getKeepAlive);
    }

    /** Verify channel and socket options agree. */
      private static void
    socketOptions() throws Exception
    {
        try (SocketChannel channel = SocketChannel.open()) {
            options(channel);
        }
        try (TlsProvider provider = new TlsProvider(theContext);
            TlsSocketChannel channel = provider.openSocketChannel()) {
            options(channel);
            /*
             * Socket's documented argument validation is stronger than some
             * native SocketChannel adapters; retain the documented contract.
             */
            try {
                channel.socket().setSoLinger(true, -1);
                throw new AssertionError("negative socket linger accepted");
            } catch (IllegalArgumentException expected) {
                /* Socket API validates enabled linger */
            }
        }
    }

    /** Verify socket streams support duplex and read timeout. */
      private static void
    socketStreams() throws Exception
    {
        try (Pair pair = new Pair()) {
            Socket socket = pair.myClient.socket();
            socket.setSoTimeout(80);
            socket.setTcpNoDelay(true);
            require(socket.getTcpNoDelay(), "socket option delegates");
            InputStream input = socket.getInputStream();
            boolean timedOut = false;
            try {
                input.read();
            } catch (SocketTimeoutException expected) {
                timedOut = true;
            }
            require(timedOut && pair.myClient.isOpen(),
                "read timeout retains connection");
            socket.setSoTimeout(3000);
            ExecutorService executor = Executors.newFixedThreadPool(2);
            try {
                Future<Integer> reply = executor.submit(() -> input.read());
                Future<Integer> peer = executor.submit(() -> {
                    int value = pair.myServer.socket().getInputStream().read();
                    pair.myServer.socket().getOutputStream().write(value);
                    return value;
                });
                socket.getOutputStream().write(93);
                require(reply.get(5, TimeUnit.SECONDS) == 93 && peer.get(5,
                    TimeUnit.SECONDS) == 93, "stream duplex");
            } finally {
                executor.shutdownNow();
            }
        }
    }

    /**
     * Check bounded failure when a peer stalls authentication or output
     * shutdown.
     */
      private static void
    stalledDeadline(boolean shutdown) throws Exception
    {
        try (TlsProvider provider = new TlsProvider(theContext);
            ServerSocketChannel listener = ServerSocketChannel.open();
            TlsSocketChannel client = provider.openSocketChannel("localhost");
            TlsSelector selector = provider.openSelector()) {
            if (shutdown) {
                provider.setShutdownTimeout(Duration.ofMillis(150));
            } else {
                provider.setHandshakeTimeout(Duration.ofMillis(150));
            }
            listener.bind(loopback());
            client.connect(listener.getLocalAddress());
            try (SocketChannel stalled = listener.accept()) {
                require(stalled.isConnected(), "stalled raw peer accepted");
                if (shutdown) {
                    client.write(ByteBuffer.wrap(new byte[] { 1 }));
                    client.shutdownOutput();
                }
                client.configureBlocking(false);
                client.register(selector, SelectionKey.OP_READ);
                require(selector.select(3000) == 1,
                    "deadline wakes application selector");
                boolean expired = false;
                try {
                    client.read(ByteBuffer.allocate(1));
                } catch (SocketTimeoutException expected) {
                    expired =
                        expected.getMessage()
                        .contains(shutdown ? "shutdown" : "handshake");
                }
                require(expired,
                    "deadline reported as timed-out TLS operation");
            }
        }
    }

    /** Verify positive linger completes a successful TLS drain. */
      private static void
    successfulLinger() throws Exception
    {
        try (Pair pair = new Pair()) {
            byte[] payload = new byte[60000];
            new Random(123).nextBytes(payload);
            pair.myClient.socket().setSoLinger(true, 5);
            ExecutorService executor = Executors.newSingleThreadExecutor();
            try {
                Future<byte[]> received = executor.submit(() -> {
                    pair.myServer.socket().setSoTimeout(4000);
                    byte[] bytes =
                        pair.myServer.socket().getInputStream().readAllBytes();
                    pair.myServer.close();
                    return bytes;
                });
                pair.myClient.socket().getOutputStream().write(payload);
                pair.myClient.close();
                require(Arrays.equals(payload, received.get(2,
                    TimeUnit.SECONDS)),
                    "linger delivered all accepted plaintext");
                require(!pair.myClient.myRaw.isOpen(),
                    "successful linger completed transport closure");
            } finally {
                executor.shutdownNow();
            }
        }
    }

    /** Verify bounded delegated tasks fail excess handshakes and recover. */
      private static void
    taskSaturation() throws Exception
    {
        SlowTrust trust = new SlowTrust();
        SSLContext slow = SSLContext.getInstance("TLS");
        slow.init(new KeyManager[0], new TrustManager[] { trust }, null);
        try (TlsProvider clients = new TlsProvider(slow, 32768, 1, 1);
            TlsProvider servers = new TlsProvider(theContext);
            TlsServerSocketChannel listener = servers.openServerSocketChannel();
            TlsSelector selector = clients.openSelector()) {
            listener.bind(loopback());
            List<TlsSocketChannel> outgoing = new ArrayList<>();
            List<TlsSocketChannel> incoming = new ArrayList<>();
            for (int i = 0; i < 8; i++) {
                TlsSocketChannel client =
                    clients.openSocketChannel("localhost");
                client.connect(listener.getLocalAddress());
                incoming.add(listener.accept());
                client.configureBlocking(false);
                client.register(selector, SelectionKey.OP_READ);
                outgoing.add(client);
                if (i == 0) {
                    require(trust.myEntered.await(3, TimeUnit.SECONDS),
                        "first verifier blocked");
                }
            }
            boolean rejected = false;
            long limit = System.nanoTime() + 3_000_000_000L;
            while (!rejected && System.nanoTime() < limit) {
                selector.select(1000);
                for (SelectionKey key : selector.selectedKeys()) {
                    try {
                        ((TlsSocketChannel) key.channel())
                            .read(ByteBuffer.allocate(1));
                    } catch (IOException error) {
                        for (Throwable cause = error; cause != null; cause =
                            cause.getCause())
                        {
                            if (cause instanceof RejectedExecutionException) {
                                rejected = true;
                            }
                        }
                        key.cancel();
                    }
                }
                selector.selectedKeys().clear();
            }
            require(rejected, "excess handshake fails instead of growing " +
                "the task queue");
            trust.myRelease.countDown();
            outgoing.get(0).write(ByteBuffer.wrap(new byte[] { 42 }));
            ByteBuffer received = ByteBuffer.allocate(1);
            require(incoming.get(0).read(received) == 1 && received.get(0) ==
                42, "admitted connection recovers after " +
                "verifier completes");
        } finally {
            trust.myRelease.countDown();
        }
    }

    /**
     * Run one scenario under a deadline and require its worker to terminate
     * afterward.
     */
      private static void
    test(String name, Checked action) throws Exception
    {
        ExecutorService runner = Executors.newSingleThreadExecutor();
        Future<Void> result = runner.submit(() -> {
            action.run();
            return null;
        });
        try {
            result.get(30, TimeUnit.SECONDS);
            theTests++;
            System.out.println("PASS " + name);
        } catch (ExecutionException error) {
            if (error.getCause() instanceof Exception exception) {
                throw exception;
            }
            if (error.getCause() instanceof Error failure) {
                throw failure;
            }
            throw new AssertionError(error);
        } finally {
            result.cancel(true);
            runner.shutdownNow();
            require(runner.awaitTermination(5, TimeUnit.SECONDS),
                "test thread leak: " + name);
        }
    }

    /** Verify tLS with write-only interests and buffered read readiness. */
      private static void
    tlsSelection() throws Exception
    {
        try (Pair pair = new Pair();
            TlsSelector selector = pair.myProvider.openSelector()) {
            pair.myClient.configureBlocking(false);
            pair.myServer.configureBlocking(false);
            SelectionKey clientKey =
                pair.myClient.register(selector, SelectionKey.OP_WRITE);
            SelectionKey serverKey = pair.myServer.register(selector, 0);
            long deadline = System.nanoTime() + 5_000_000_000L;
            while (!pair.myClient.handshakeComplete()) {
                require(System.nanoTime() < deadline,
                    "handshake must progress with server " +
                    "interests zero/client write only");
                selector.select(100);
                selector.selectedKeys().clear();
            }
            ByteBuffer message = ByteBuffer.wrap(new byte[] { 1, 2, 3, 4, 5 });
            require(pair.myClient.write(message) == 5, "TLS accepted write");
            clientKey.interestOps(0);
            serverKey.interestOps(SelectionKey.OP_READ);
            require(selector.select(3000) > 0 && serverKey.isReadable(),
                "decrypted readiness");
            selector.selectedKeys().clear();
            ByteBuffer first = ByteBuffer.allocate(1);
            require(pair.myServer.read(first) == 1 && first.get(0) == 1,
                "partial application read");
            require(selector.select(1000) > 0 && serverKey.isReadable(),
                "buffered readiness without new network bytes");
            ByteBuffer rest = ByteBuffer.allocate(4);
            require(pair.myServer.read(rest) == 4 && rest.get(3) == 5,
                "remaining plaintext");
            selector.selectedKeys().clear();
            require(selector.select(100) == 0, "no stale readability spin");
            pair.myClient.shutdownOutput();
            require(selector.select(2000) > 0, "close_notify readability");
            require(pair.myServer.read(ByteBuffer.allocate(1)) == -1,
                "orderly TLS EOF");
        }
    }

    /** Verify truncated TLS stream reports failure. */
      private static void
    truncatedStream() throws Exception
    {
        try (Pair pair = new Pair()) {
            pair.myClient.write(ByteBuffer.wrap(new byte[] { 1 }));
            require(pair.myServer.read(ByteBuffer.allocate(1)) == 1,
                "authenticated connection");
            pair.myClient.abort();
            boolean rejected = false;
            try {
                pair.myServer.read(ByteBuffer.allocate(1));
            } catch (SSLException | SocketException expected) {
                rejected = true;
            }
            require(rejected,
                "transport EOF without close_notify is not clean EOF");
        }
    }

    /** Verify hostname validation rejects wrong name. */
      private static void
    wrongHostname() throws Exception
    {
        rejection(theContext, "wrong.invalid");
    }

    /** Verify untrusted certificate rejection. */
      private static void
    wrongTrust() throws Exception
    {
        rejection(SSLContext.getDefault(), "localhost");
    }

    /** Verify zero linger explicitly aborts TLS. */
      private static void
    zeroLinger() throws Exception
    {
        try (Pair pair = new Pair()) {
            pair.myClient.write(ByteBuffer.wrap(new byte[] { 1 }));
            pair.myServer.read(ByteBuffer.allocate(1));
            pair.myClient.setOption(StandardSocketOptions.SO_LINGER, 0);
            pair.myClient.close();
            boolean failed = false;
            try {
                pair.myServer.read(ByteBuffer.allocate(1));
            } catch (SSLException | SocketException expected) {
                failed = true;
            }
            require(failed, "zero linger produces an abort rather than " +
                "clean TLS EOF");
        }
    }

    /**
     * Conformance action that can propagate checked failures to the test
     * runner.
     */
    @FunctionalInterface
    private interface Checked {

        /**
         * Execute one conformance action, allowing checked failures to reach
         * the test runner.
         */
          void
        run() throws Exception;
    }

    /** Two connected endpoints whose resources are released together. */
    private static final class Pair implements AutoCloseable {

        /** Provider owning both endpoints of the test connection. */
        private final TlsProvider myProvider;

        /** Client endpoint used by a conformance scenario. */
        private final TlsSocketChannel myClient;

        /** Accepted endpoint used by a conformance scenario. */
        private final TlsSocketChannel myServer;

        /**
         * Establish the client and server endpoints owned by a test provider.
         */
        Pair() throws Exception
        {
            this(null);
        }

        /**
         * Establish the client and server endpoints owned by a test provider.
         */
        Pair(String protocol) throws Exception
        {
            myProvider = new TlsProvider(theContext);
            if (protocol != null) {
                myProvider.setEnabledProtocols(protocol);
            }
            try (TlsServerSocketChannel listener =
                myProvider.openServerSocketChannel()) {
                listener.bind(loopback());
                myClient = myProvider.openSocketChannel("localhost");
                myClient.connect(listener.getLocalAddress());
                myServer = listener.accept();
            }
        }

        /** {@inheritDoc} */
        @Override
          public void
        close() throws IOException
        {
            myClient.close();
            myServer.close();
            myProvider.close();
        }
    }

    /**
     * Trust manager that stalls verification to exercise bounded task
     * admission.
     */
    private static final class SlowTrust extends X509ExtendedTrustManager {

        /**
         * Signals that the controlled trust check reached its blocking point.
         */
        private final CountDownLatch myEntered = new CountDownLatch(1);

        /**
         * Releases the controlled trust check after task saturation is
         * observed.
         */
        private final CountDownLatch myRelease = new CountDownLatch(1);

        /** {@inheritDoc} */
        @Override
          public void
        checkClientTrusted(X509Certificate[] chain,
            String type) throws CertificateException
        {
            theVerifier.checkClientTrusted(chain, type);
        }

        /** {@inheritDoc} */
        @Override
          public void
        checkClientTrusted(X509Certificate[] chain, String type,
            Socket socket) throws CertificateException
        {
            theVerifier.checkClientTrusted(chain, type, socket);
        }

        /** {@inheritDoc} */
        @Override
          public void
        checkClientTrusted(X509Certificate[] chain, String type,
            SSLEngine engine) throws CertificateException
        {
            theVerifier.checkClientTrusted(chain, type, engine);
        }

        /** {@inheritDoc} */
        @Override
          public void
        checkServerTrusted(X509Certificate[] chain,
            String type) throws CertificateException
        {
            theVerifier.checkServerTrusted(chain, type);
        }

        /** {@inheritDoc} */
        @Override
          public void
        checkServerTrusted(X509Certificate[] chain, String type,
            Socket socket) throws CertificateException
        {
            theVerifier.checkServerTrusted(chain, type, socket);
        }

        /** {@inheritDoc} */
        @Override
          public void
        checkServerTrusted(X509Certificate[] chain, String type,
            SSLEngine engine) throws CertificateException
        {
            myEntered.countDown();
            try {
                if (!myRelease.await(10, TimeUnit.SECONDS)) {
                    throw new CertificateException(
                        "test trust callback timeout");
                }
            } catch (InterruptedException error) {
                Thread.currentThread().interrupt();
                throw new CertificateException(error);
            }
            theVerifier.checkServerTrusted(chain, type, engine);
        }

        /** {@inheritDoc} */
        @Override
          public X509Certificate[]
        getAcceptedIssuers()
        {
            return theVerifier.getAcceptedIssuers();
        }
    }
}

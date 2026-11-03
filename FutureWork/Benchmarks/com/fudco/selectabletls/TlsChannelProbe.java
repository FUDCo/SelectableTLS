package com.fudco.selectabletls;

import java.io.IOException;
import java.lang.management.ManagementFactory;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;
import tlschannel.BufferAllocator;
import tlschannel.ClientTlsChannel;
import tlschannel.HeapBufferAllocator;
import tlschannel.NeedsReadException;
import tlschannel.NeedsWriteException;
import tlschannel.ServerTlsChannel;
import tlschannel.TlsChannel;
import tlschannel.WouldBlockException;

/** Optional TLS Channel 1.0.0 counterpart to the sequential ResourceProbe. */
public final class TlsChannelProbe {

    /** Readiness exceptions observed during the measured traffic interval. */
    private static long theFlowExceptions;

    /** Prevent construction of this utility class. */
      private
    TlsChannelProbe()
    {
    }

    /**
     * Sum allocation counters for live Java threads, or return -1 when
     * unavailable.
     */
      private static long
    allocated()
    {
        var bean = ManagementFactory.getThreadMXBean();
        if (!(bean instanceof com.sun.management.ThreadMXBean allocations) ||
            !allocations.isThreadAllocatedMemorySupported())
        {
            return -1;
        }
        long total = 0;
        for (long bytes : allocations.getThreadAllocatedBytes(
            bean.getAllThreadIds()))
        {
            total += Math.max(0, bytes);
        }
        return total;
    }

    /**
     * Establish the comparison population using TLS Channel's public
     * nonblocking API.
     */
      private static List<Pair>
    connect(SSLContext context, Selector selector, BufferAllocator allocator,
        int count) throws Exception
    {
        List<Pair> pairs = new ArrayList<>();
        List<Endpoint> endpoints = new ArrayList<>();
        try (ServerSocketChannel listener = ServerSocketChannel.open()) {
            listener.bind(new InetSocketAddress("127.0.0.1", 0));
            int port =
                ((InetSocketAddress) listener.getLocalAddress()).getPort();
            for (int i = 0; i < count; i++) {
                SocketChannel client =
                    SocketChannel.open(listener.getLocalAddress());
                SocketChannel server = listener.accept();
                client.configureBlocking(false);
                server.configureBlocking(false);
                Endpoint clientEndpoint =
                    new Endpoint(client, ClientTlsChannel.newBuilder(client,
                    engine(context, true, port))
                    .withPlainBufferAllocator(allocator)
                    .withEncryptedBufferAllocator(allocator)
                    .withReleaseBuffers(true).withRunTasks(true)
                    .withWaitForCloseConfirmation(false).build(), selector);
                Endpoint serverEndpoint =
                    new Endpoint(server, ServerTlsChannel.newBuilder(server,
                    context).withEngineFactory(sslContext -> engine(sslContext,
                    false, -1)).withPlainBufferAllocator(allocator)
                    .withEncryptedBufferAllocator(allocator)
                    .withReleaseBuffers(true).withRunTasks(true)
                    .withWaitForCloseConfirmation(false).build(), selector);
                pairs.add(new Pair(clientEndpoint, serverEndpoint));
                endpoints.add(clientEndpoint);
                endpoints.add(serverEndpoint);
            }
        }
        int pending = count * 2;
        for (Endpoint endpoint : endpoints) {
            if (endpoint.handshake()) {
                pending--;
            }
        }
        long deadline = System.nanoTime() + 30_000_000_000L;
        while (pending > 0) {
            if (System.nanoTime() > deadline) {
                throw new AssertionError(
                    "TLS Channel population handshake timed out");
            }
            selector.select(1000);
            for (SelectionKey key : selector.selectedKeys()) {
                Endpoint endpoint = (Endpoint) key.attachment();
                if (!endpoint.myAuthenticated && endpoint.handshake()) {
                    pending--;
                }
            }
            selector.selectedKeys().clear();
        }
        return pairs;
    }

    /**
     * Consume post-handshake control traffic without treating it as application
     * payload.
     */
      private static void
    controls(Endpoint endpoint, ByteBuffer scratch) throws IOException
    {
        scratch.clear();
        try {
            if (endpoint.myTLS.read(scratch) != 0) {
                throw new AssertionError(
                    "Unexpected data/EOF during idle setup");
            }
        } catch (WouldBlockException exception) {
            endpoint.needs(exception);
        }
    }

    /**
     * Sum CPU time for currently live Java threads when supported by the
     * runtime.
     */
      private static long
    cpu()
    {
        var bean = ManagementFactory.getThreadMXBean();
        if (!bean.isThreadCpuTimeSupported()) {
            return -1;
        }
        long total = 0;
        for (long id : bean.getAllThreadIds()) {
            total += Math.max(0, bean.getThreadCpuTime(id));
        }
        return total;
    }

    /**
     * Create the comparison engine with matching protocols and client endpoint
     * verification.
     */
      private static SSLEngine
    engine(SSLContext context, boolean client, int port)
    {
        SSLEngine engine =
            client ? context.createSSLEngine("localhost",
            port) : context.createSSLEngine();
        engine.setUseClientMode(client);
        SSLParameters parameters = engine.getSSLParameters();
        parameters.setProtocols(new String[] { "TLSv1.3", "TLSv1.2" });
        if (client) {
            parameters.setEndpointIdentificationAlgorithm("HTTPS");
        }
        engine.setSSLParameters(parameters);
        return engine;
    }

    /**
     * Request collection and sample retained heap after a short settling
     * interval.
     */
      private static long
    heap() throws InterruptedException
    {
        System.gc();
        Thread.sleep(200);
        return ManagementFactory.getMemoryMXBean().getHeapMemoryUsage()
            .getUsed();
    }

    /**
     * Run the TlsChannelProbe entry point with its documented command-line
     * arguments.
     */
      public static void
    main(String[] args) throws Exception
    {
        int count = args.length > 0 ? Integer.parseInt(args[0]) : 1000;
        int rounds = args.length > 1 ? Integer.parseInt(args[1]) : 10000;
        String mode = args.length > 2 ? args[2] : "heap";
        if (count < 1 || rounds < 1 || !(mode.equals("pooled") ||
            mode.equals("heap")))
        {
            throw new IllegalArgumentException(
                "positive pairs/rounds; allocation mode " + "pooled or heap");
        }
        BufferPool pool = new BufferPool(65536);
        BufferAllocator allocator =
            mode.equals("heap") ? new HeapBufferAllocator(
            ) : new BufferAllocator() {

            /** {@inheritDoc} */
            @Override
              public ByteBuffer
            allocate(int size)
            {
                return pool.acquire(size);
            }

            /** {@inheritDoc} */
            @Override
              public void
            free(ByteBuffer buffer)
            {
                pool.release(buffer);
            }
        };
        Path credentials =
            Files.createTempDirectory("SelectableTLS-TlsChannelProbe-");
        try {
            SSLContext context =
                ConformanceTest.certificateContext(credentials);
            try (Selector selector = Selector.open()) {
                List<Pair> warmup = connect(context, selector, allocator, 32);
                for (int i = 0; i < 500; i++) {
                    roundTrip(warmup.get(i % warmup.size()), selector);
                }
                for (Pair pair : warmup) {
                    pair.close();
                }
                selector.selectNow();
                selector.selectedKeys().clear();
                long baseHeap = heap();
                int baseThreads =
                    ManagementFactory.getThreadMXBean().getThreadCount();
                long setup = System.nanoTime();
                List<Pair> pairs = connect(context, selector, allocator, count);
                long setupNanos = System.nanoTime() - setup;
                settle(pairs, selector);
                long idleHeap = heap();
                int idleThreads =
                    ManagementFactory.getThreadMXBean().getThreadCount();
                long idleCPUStart = cpu();
                Thread.sleep(1000);
                long idleCPU = cpu() - idleCPUStart;
                long[] latencies = new long[rounds];
                long allocationStart = allocated();
                long exceptionsStart = theFlowExceptions;
                long start = System.nanoTime();
                for (int i = 0; i < rounds; i++) {
                    latencies[i] =
                        roundTrip(pairs.get(i % Math.min(count, 64)), selector);
                }
                long traffic = System.nanoTime() - start;
                long allocation = allocated() - allocationStart;
                Arrays.sort(latencies);
                System.out.printf(Locale.ROOT,
                    ("library=tls-channel-1.0.0 allocator=%s " +
                    "tasks=inline java=%s os=%s arch=%s%n") +
                    ("pairs=%d endpoints=%d warmup_pairs=32 " +
                    "active_pairs=%d rounds=%d payload_bytes=32 " +
                    "protocol=%s%n") +
                    ("setup_ms=%.3f heap_baseline_bytes=%d " +
                    "heap_idle_bytes=%d incremental_heap_bytes_" +
                    "per_endpoint=%.1f%n") +
                    ("threads_baseline=%d threads_idle=%d " +
                    "idle_one_second_thread_cpu_ms=%.3f%n") +
                    ("round_trips_per_second=%.1f p50_us=%.3f " +
                    "p95_us=%.3f p99_us=%.3f " +
                    "allocated_bytes_per_round_trip=%.1f " +
                    "traffic_flow_exceptions=%d%n"), mode,
                    System.getProperty("java.version"),
                    System.getProperty("os.name"),
                    System.getProperty("os.arch"), count, count * 2,
                    Math.min(count, 64), rounds, pairs.get(0)
                    .client.myTLS.getSslEngine().getSession().getProtocol(),
                    setupNanos / 1e6, baseHeap, idleHeap,
                    (idleHeap - baseHeap) / (count * 2.0), baseThreads,
                    idleThreads, idleCPU / 1e6, rounds * 1e9 / traffic,
                    latencies[rounds / 2] / 1e3,
                    latencies[(int) (rounds * .95)] / 1e3,
                    latencies[(int) (rounds * .99)] / 1e3,
                    allocation / (double) rounds,
                    theFlowExceptions - exceptionsStart);
                for (Pair pair : pairs) {
                    pair.close();
                }
            }
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

    /**
     * Read the remaining response bytes, waiting for readiness under a bounded
     * deadline.
     */
      private static void
    receive(Endpoint endpoint, Selector selector,
        ByteBuffer bytes) throws IOException
    {
        long deadline = System.nanoTime() + 5_000_000_000L;
        while (bytes.hasRemaining()) {
            try {
                if (endpoint.myTLS.read(bytes) < 0) {
                    throw new AssertionError("Unexpected EOF");
                }
            } catch (WouldBlockException exception) {
                endpoint.needs(exception);
                if (System.nanoTime() > deadline) {
                    throw new AssertionError("Reply timed out");
                }
                selector.select(1000);
                selector.selectedKeys().clear();
            }
        }
    }

    /**
     * Measure one verified 32-byte request and echo through the selected pair.
     */
      private static long
    roundTrip(Pair pair, Selector selector) throws IOException
    {
        ByteBuffer outgoing = ByteBuffer.allocate(32);
        outgoing.putLong(0, 0x123456789abcdefL);
        ByteBuffer echoed = ByteBuffer.allocate(32);
        pair.client.myKey.interestOps(SelectionKey.OP_READ);
        pair.server.myKey.interestOps(SelectionKey.OP_READ);
        long start = System.nanoTime();
        if (pair.client.myTLS.write(outgoing) != 32) {
            throw new AssertionError("Short diagnostic request");
        }
        receive(pair.server, selector, echoed);
        echoed.flip();
        if (pair.server.myTLS.write(echoed) != 32) {
            throw new AssertionError("Short diagnostic reply");
        }
        outgoing.clear();
        receive(pair.client, selector, outgoing);
        long elapsed = System.nanoTime() - start;
        if (outgoing.getLong(0) != 0x123456789abcdefL) {
            throw new AssertionError("Payload mismatch");
        }
        pair.client.myKey.interestOps(0);
        pair.server.myKey.interestOps(0);
        return elapsed;
    }

    /**
     * Drive post-handshake traffic to quiescence before the idle-memory
     * snapshot.
     */
      private static void
    settle(List<Pair> pairs, Selector selector) throws IOException
    {
        /*
         * Drive post-handshake records before measuring idle buffers.
         * SelectableTLS does this automatically; TLS Channel's caller must
         * perform the reads.
         */
        ByteBuffer scratch = ByteBuffer.allocate(1);
        for (Pair pair : pairs) {
            controls(pair.client, scratch);
            controls(pair.server, scratch);
        }
        long deadline = System.nanoTime() + 5_000_000_000L;
        while (selector.select(25) > 0) {
            if (System.nanoTime() > deadline) {
                throw new AssertionError(
                    "Idle TLS control processing did not settle");
            }
            for (SelectionKey key : selector.selectedKeys()) {
                controls((Endpoint) key.attachment(), scratch);
            }
            selector.selectedKeys().clear();
        }
        for (Pair pair : pairs) {
            pair.client.myKey.interestOps(0);
            pair.server.myKey.interestOps(0);
        }
        selector.selectedKeys().clear();
    }

    /**
     * Comparison endpoint translating TLS Channel readiness requests to
     * selector interests.
     */
    private static final class Endpoint implements AutoCloseable {

        /** Native nonblocking channel used by the comparison library. */
        private final SocketChannel myRaw;

        /** TLS Channel adapter layered over this endpoint's transport. */
        private final TlsChannel myTLS;

        /**
         * Native selector registration used to satisfy TLS Channel readiness
         * requests.
         */
        private final SelectionKey myKey;

        /** Whether this endpoint's initial handshake has completed. */
        private boolean myAuthenticated;

        /**
         * Associate a TLS Channel endpoint with its native readiness
         * registration.
         */
        Endpoint(SocketChannel raw, TlsChannel tls,
            Selector selector) throws IOException
        {
            myRaw = raw;
            myTLS = tls;
            myKey = raw.register(selector, 0, this);
        }

        /** {@inheritDoc} */
        @Override
          public void
        close() throws IOException
        {
            try {
                myTLS.close();
            } finally {
                myRaw.close();
            }
        }

        /**
         * Advance authentication until complete or a native readiness
         * dependency is reported.
         */
          boolean
        handshake() throws IOException
        {
            try {
                myTLS.handshake();
                myAuthenticated = true;
                myKey.interestOps(0);
                return true;
            } catch (WouldBlockException exception) {
                needs(exception);
                return false;
            }
        }

        /**
         * Translate TLS Channel's readiness exception into native selector
         * interests.
         */
          void
        needs(WouldBlockException exception) throws IOException
        {
            theFlowExceptions++;
            if (exception instanceof NeedsReadException) {
                myKey.interestOps(SelectionKey.OP_READ);
            } else if (exception instanceof NeedsWriteException) {
                myKey.interestOps(SelectionKey.OP_WRITE);
            } else {
                throw exception;
            }
        }
    }

    /** Two connected endpoints whose resources are released together. */
    private record Pair(Endpoint client,
        Endpoint server) implements AutoCloseable {

        /** {@inheritDoc} */
        @Override
          public void
        close() throws IOException
        {
            try {
                client.close();
            } finally {
                server.close();
            }
        }
    }
}

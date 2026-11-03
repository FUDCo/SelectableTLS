package com.fudco.selectabletls;

import java.lang.management.ManagementFactory;
import java.net.InetSocketAddress;
import java.net.SocketTimeoutException;
import java.nio.ByteBuffer;
import java.nio.channels.SelectionKey;
import java.nio.channels.SocketChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLSessionContext;

/**
 * Bounded concurrent traffic, idle-population and connection-churn
 * qualification.
 */
public final class StressProbe {

    /** Prevent construction of this utility class. */
      private
    StressProbe()
    {
    }

    /**
     * Fail the diagnostic when a required protocol or resource invariant is
     * false.
     */
      private static void
    check(boolean condition, String message)
    {
        if (!condition) {
            throw new AssertionError(message);
        }
    }

    /**
     * Read aggregate collector count and elapsed-time counters, reporting
     * unavailable metrics as -1.
     */
      private static long[]
    collections()
    {
        long count = 0;
        long millis = 0;
        for (var collector : ManagementFactory.getGarbageCollectorMXBeans()) {
            if (collector.getCollectionCount() < 0 ||
                collector.getCollectionTime() < 0)
            {
                return new long[] { -1, -1 };
            }
            count += collector.getCollectionCount();
            millis += collector.getCollectionTime();
        }
        return new long[] { count, millis };
    }

    /**
     * Read the open-descriptor count on supported Unix runtimes, or return -1.
     */
      private static long
    descriptors()
    {
        var bean = ManagementFactory.getOperatingSystemMXBean();
        return bean instanceof com.sun.management.UnixOperatingSystemMXBean unix
            ? unix.getOpenFileDescriptorCount() : -1;
    }

    /**
     * Inject malformed or silent peers, then require failure notification and
     * complete transport cleanup.
     */
      private static void
    failures(TlsProvider provider, TlsSelector selector,
        TlsServerSocketChannel listener, SelectionKey acceptKey, int count,
        boolean silent) throws Exception
    {
        List<SocketChannel> peers = new ArrayList<>();
        List<TlsSocketChannel> servers = new ArrayList<>();
        provider.setHandshakeTimeout(Duration.ofMillis(150));
        try {
            long limit = System.nanoTime() + 5_000_000_000L;
            for (int i = 0; i < count; i++) {
                SocketChannel peer =
                    SocketChannel.open(listener.getLocalAddress());
                peers.add(peer);
                TlsSocketChannel server;
                while (true) {
                    server = listener.accept();
                    if (server != null) {
                        break;
                    }
                    check(System.nanoTime() < limit,
                        "fault peer accept timed out");
                    Thread.sleep(1);
                }
                servers.add(server);
                server.configureBlocking(false);
                server.register(selector, SelectionKey.OP_READ);
                if (!silent) {
                    ByteBuffer invalid =
                        ByteBuffer.wrap(new byte[] { 'n', 'o', 't', 'T', 'L',
                        'S', '!', '!' });
                    while (invalid.hasRemaining()) {
                        peer.write(invalid);
                    }
                }
            }
            int failed = 0;
            while (failed < count) {
                check(System.nanoTime() < limit,
                    "fault wave did not terminate");
                selector.select(1000);
                for (Iterator<SelectionKey> iterator = selector.selectedKeys()
                    .iterator(); iterator.hasNext(); )
                {
                    SelectionKey key = iterator.next();
                    iterator.remove();
                    if (key == acceptKey || !key.isValid()) {
                        continue;
                    }
                    TlsSocketChannel server = (TlsSocketChannel) key.channel();
                    try {
                        int read = server.read(ByteBuffer.allocate(1));
                        check(read == 0,
                            "invalid peer exposed data or clean EOF");
                    } catch (java.io.IOException failure) {
                        check(
                            silent ? failure instanceof SocketTimeoutException :
                            failure instanceof SSLException,
                            "unexpected fault type: " + failure);
                        server.close();
                        failed++;
                    }
                }
            }
            selector.selectNow();
            selector.selectedKeys().clear();
            check(selector.keys().size() == 1 && selector.keys()
                .contains(acceptKey), "fault wave retained keys");
            for (TlsSocketChannel server : servers) {
                check(!server.myRaw.isOpen(), "failed peer retained transport");
            }
        } finally {
            for (SocketChannel peer : peers) {
                peer.close();
            }
            for (TlsSocketChannel server : servers) {
                server.abort();
            }
            provider.setHandshakeTimeout(Duration.ofSeconds(30));
        }
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
     * Run the StressProbe entry point with its documented command-line
     * arguments.
     */
      public static void
    main(String[] args) throws Exception
    {
        int pairs = args.length > 0 ? Integer.parseInt(args[0]) : 256;
        int active = args.length > 1 ? Integer.parseInt(args[1]) : 32;
        int rounds = args.length > 2 ? Integer.parseInt(args[2]) : 1000;
        int waves = args.length > 3 ? Integer.parseInt(args[3]) : 16;
        int sessionCache = args.length > 4 ? Integer.parseInt(args[4]) : -1;
        if (pairs < 1 || pairs > 10000 || active < 1 || active > pairs ||
            rounds < 1 || waves < 1)
        {
            throw new IllegalArgumentException(
                "pairs 1..10000, active 1..pairs, positive " +
                "rounds and waves");
        }
        Path credentials = Files.createTempDirectory("SelectableTLS-Stress-");
        try {
            var context = ConformanceTest.certificateContext(credentials);
            if (sessionCache >= 0) {
                context.getClientSessionContext()
                    .setSessionCacheSize(sessionCache);
                context.getServerSessionContext()
                    .setSessionCacheSize(sessionCache);
            }
            try (TlsProvider provider = new TlsProvider(context);
                TlsSelector selector = provider.openSelector();
                TlsServerSocketChannel listener =
                    provider.openServerSocketChannel()) {
                listener.bind(new InetSocketAddress("127.0.0.1", 0),
                    Math.max(128, pairs));
                listener.configureBlocking(false);
                SelectionKey acceptKey =
                    listener.register(selector, SelectionKey.OP_ACCEPT);
                Stats stats = new Stats();
                wave(provider, selector, listener, acceptKey, pairs, active,
                    Math.min(rounds, 100), new Stats());
                long baselineHeap = heap();
                long baselineDescriptors = descriptors();
                int baselineClientSessions =
                    sessions(context.getClientSessionContext());
                int baselineServerSessions =
                    sessions(context.getServerSessionContext());
                int baselineThreads =
                    ManagementFactory.getThreadMXBean().getThreadCount();
                long[] baselineCollections = collections();
                long baselineCPU = processCPU();
                long started = System.nanoTime();
                for (int i = 0; i < waves; i++) {
                    wave(provider, selector, listener, acceptKey, pairs, active,
                        rounds, stats);
                    if (i == 0 || (i + 1) % 8 == 0 || i + 1 == waves) {
                        System.out.println("WAVE_PASS wave=" + (i + 1) +
                            " replies=" + stats.myReplies + " descriptors=" +
                            descriptors());
                    }
                }
                double seconds = (System.nanoTime() - started) / 1e9;
                long[] trafficCollections = collections();
                long trafficCPU = processCPU();
                int faults = Math.min(pairs, 64);
                for (int i = 0; i < 8; i++) {
                    failures(provider, selector, listener, acceptKey, faults,
                        false);
                    failures(provider, selector, listener, acceptKey, faults,
                        true);
                }
                wave(provider, selector, listener, acceptKey, 32, 8, 10,
                    new Stats());
                System.out.println("FAULT_RECOVERY_PASS malformed=" +
                    (faults * 8) + " stalled=" + (faults * 8));
                System.out.println("TRAFFIC_RESOURCES process_cpu_ms=" +
                    (baselineCPU < 0 ||
                    trafficCPU < 0 ? -1 : (
                    trafficCPU - baselineCPU) / 1_000_000) + " gc_count=" +
                    (baselineCollections[0] < 0 ||
                    trafficCollections[0] < 0 ? -1 : trafficCollections[0] -
                    baselineCollections[0]) + " gc_time_ms=" +
                    (baselineCollections[1] < 0 ||
                    trafficCollections[1] < 0 ? -1 : trafficCollections[1] -
                    baselineCollections[1]));
                long finalHeap = heap();
                long finalDescriptors = descriptors();
                Arrays.sort(stats.mySamples, 0, stats.mySampled);
                System.out.printf(Locale.ROOT,
                    ("STRESS_PASS java=%s os=%s arch=%s pairs=%d " +
                    "active=%d rounds=%d waves=%d " +
                    "connections=%d replies=%d seconds=%.3f%n") +
                    ("heap_before_bytes=%d heap_after_bytes=%d " +
                    "descriptors_before=%d descriptors_after=%d " +
                    "threads_before=%d threads_after=%d%n") +
                    ("client_sessions_before=%d " +
                    "client_sessions_after=%d " + "server_sessions_before=%d " +
                    "server_sessions_after=%d " + "client_cache_limit=%d " +
                    "server_cache_limit=%d%n") +
                    ("round_trips_per_second=%.1f " +
                    "latency_samples=%d p50_us=%.3f p95_us=%.3f " +
                    "p99_us=%.3f%n"), System.getProperty("java.version"),
                    System.getProperty("os.name"),
                    System.getProperty("os.arch"), pairs, active, rounds, waves,
                    (long) pairs * waves, stats.myReplies, seconds,
                    baselineHeap, finalHeap, baselineDescriptors,
                    finalDescriptors, baselineThreads,
                    ManagementFactory.getThreadMXBean().getThreadCount(),
                    baselineClientSessions,
                    sessions(context.getClientSessionContext()),
                    baselineServerSessions,
                    sessions(context.getServerSessionContext()),
                    context.getClientSessionContext().getSessionCacheSize(),
                    context.getServerSessionContext().getSessionCacheSize(),
                    stats.myReplies / seconds, stats.mySampled,
                    stats.mySamples[stats.mySampled / 2] / 1e3,
                    stats.mySamples[(int) (stats.mySampled * .95)] / 1e3,
                    stats.mySamples[(int) (stats.mySampled * .99)] / 1e3);
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
     * Read process CPU time, including workers and garbage collection, when the
     * runtime supports it.
     */
      private static long
    processCPU()
    {
        var bean = ManagementFactory.getOperatingSystemMXBean();
        return bean instanceof com.sun.management.OperatingSystemMXBean
            operating ? operating.getProcessCpuTime() : -1;
    }

    /** Count entries currently retained by the supplied JSSE session cache. */
      private static int
    sessions(SSLSessionContext context)
    {
        int count = 0;
        for (Enumeration<byte[]> ids = context.getIds(); ids.hasMoreElements();
            ids.nextElement())
        {
            count++;
        }
        return count;
    }

    /**
     * Drive concurrent request/echo traffic, retain idle peers and verify all
     * transports are released between waves.
     */
      private static void
    wave(TlsProvider provider, TlsSelector selector,
        TlsServerSocketChannel listener, SelectionKey acceptKey, int pairs,
        int active, int rounds, Stats stats) throws Exception
    {
        List<Exchange> clients = new ArrayList<>();
        List<TlsSocketChannel> channels = new ArrayList<>();
        int accepted = 0;
        int completed = 0;
        int activeFinished = 0;
        long limit = System.nanoTime() + 60_000_000_000L;
        try {
            for (int i = 0; i < pairs; i++) {
                TlsSocketChannel channel =
                    provider.openSocketChannel("localhost");
                channels.add(channel);
                channel.configureBlocking(false);
                Exchange exchange = new Exchange(channel, i, true, i < active);
                exchange.request();
                clients.add(exchange);
                boolean connected = channel.connect(listener.getLocalAddress());
                exchange.myKey =
                    channel.register(selector,
                    connected ? SelectionKey.OP_WRITE : SelectionKey.OP_CONNECT,
                    exchange);
            }
            while (completed < pairs * 2) {
                check(System.nanoTime() < limit,
                    "stress wave exceeded 60 seconds: completed=" + completed);
                selector.select(1000);
                for (Iterator<SelectionKey> iterator = selector.selectedKeys()
                    .iterator(); iterator.hasNext(); )
                {
                    SelectionKey key = iterator.next();
                    iterator.remove();
                    if (!key.isValid()) {
                        continue;
                    }
                    if (key == acceptKey) {
                        TlsSocketChannel channel;
                        while (true) {
                            channel = listener.accept();
                            if (channel == null) {
                                break;
                            }
                            channels.add(channel);
                            channel.configureBlocking(false);
                            Exchange exchange =
                                new Exchange(channel, accepted++, false, false);
                            exchange.myKey =
                                channel.register(selector, SelectionKey.OP_READ,
                                exchange);
                        }
                        check(accepted <= pairs,
                            "unexpected accepted connection");
                        continue;
                    }
                    Exchange exchange = (Exchange) key.attachment();
                    TlsSocketChannel channel = exchange.myChannel;
                    if (key.isConnectable()) {
                        if (channel.finishConnect()) {
                            key.interestOps(SelectionKey.OP_WRITE);
                        }
                        continue;
                    }
                    if (!exchange.myWriting) {
                        int read = channel.read(exchange.myBytes);
                        if (read < 0) {
                            check(!exchange.myClient || exchange.myEnding,
                                "client received premature EOF");
                            check(exchange.myBytes.position() == 0,
                                "EOF interrupted a message");
                            channel.close();
                            completed++;
                            continue;
                        }
                        if (read == 0) {
                            continue;
                        }
                        if (exchange.myClient) {
                            if (exchange.myBytes.hasRemaining()) {
                                continue;
                            }
                            exchange.myBytes.flip();
                            check(exchange.myBytes.getInt() == exchange.myID &&
                                exchange.myBytes.getInt() ==
                                exchange.mySequence,
                                "misrouted or out-of-order response");
                            while (exchange.myBytes.hasRemaining()) {
                                check(exchange.myBytes.get() == (byte) 0x5a,
                                    "corrupted payload");
                            }
                            stats.reply(System.nanoTime() - exchange.mySent);
                            exchange.mySequence++;
                            if (exchange.mySequence ==
                                (exchange.myActive ? rounds : 1))
                            {
                                exchange.myBytes.clear();
                                if (exchange.myActive) {
                                    activeFinished++;
                                    exchange.end();
                                } else if (activeFinished == active) {
                                    exchange.end();
                                } else {
                                    /*
                                     * retain idle established connections
                                     * during active traffic
                                     */
                                    key.interestOps(0);
                                }
                                if (activeFinished == active) {
                                    for (Exchange idle : clients) {
                                        if (!idle.myActive && idle.mySequence ==
                                            1)
                                        {
                                            idle.end();
                                        }
                                    }
                                }
                                continue;
                            }
                            exchange.request();
                        } else {
                            exchange.myBytes.flip();
                            exchange.myWriting = true;
                        }
                    }
                    channel.write(exchange.myBytes);
                    if (exchange.myBytes.hasRemaining()) {
                        key.interestOps(SelectionKey.OP_WRITE);
                    } else {
                        exchange.myBytes.clear();
                        exchange.myWriting = false;
                        key.interestOps(SelectionKey.OP_READ);
                    }
                }
            }
            check(accepted == pairs, "all clients accepted");
            /*
             * Application close is asynchronous. Verify actual transport
             * release before starting the next population, not merely key
             * cancellation.
             */
            long drainLimit = System.nanoTime() + 5_000_000_000L;
            while (channels.stream().anyMatch(channel ->
                channel.myRaw.isOpen()))
            {
                check(System.nanoTime() < drainLimit,
                    "closed wave retained native transports");
                Thread.sleep(1);
            }
            selector.selectNow();
            selector.selectedKeys().clear();
            check(selector.keys().size() == 1 && selector.keys()
                .contains(acceptKey), "wave retained selection keys");
        } finally {
            for (TlsSocketChannel channel : channels) {
                channel.abort();
            }
        }
    }

    /**
     * Bounded state for one endpoint of a verified request and echo exchange.
     */
    private static final class Exchange {

        /**
         * TLS endpoint whose request, echo and shutdown state is tracked here.
         */
        private final TlsSocketChannel myChannel;

        /**
         * Bounded request or echo buffer, with mode determined by the exchange
         * phase.
         */
        private final ByteBuffer myBytes = ByteBuffer.allocate(32);

        /** Connection identifier carried in each verified payload. */
        private final int myID;

        /**
         * Whether this endpoint originates requests rather than echoing them.
         */
        private final boolean myClient;

        /** Whether this pair participates in the sustained active workload. */
        private final boolean myActive;

        /**
         * Application registration controlling this endpoint's readiness
         * interests.
         */
        private SelectionKey myKey;

        /** Next message sequence number for this connection. */
        private int mySequence;

        /** Whether this endpoint is currently draining its output buffer. */
        private boolean myWriting;

        /** Whether output shutdown has begun for this endpoint. */
        private boolean myEnding;

        /**
         * Monotonic timestamp used to measure the current request's latency.
         */
        private long mySent;

        /** Initialize the per-connection payload and exchange state. */
        Exchange(TlsSocketChannel channel, int id, boolean client,
            boolean active)
        {
            myChannel = channel;
            myID = id;
            myClient = client;
            myActive = active;
        }

        /**
         * Begin orderly output shutdown once the exchange has completed its
         * traffic.
         */
          void
        end() throws Exception
        {
            if (myEnding) {
                return;
            }
            myEnding = true;
            myBytes.clear();
            myChannel.shutdownOutput();
            myKey.interestOps(SelectionKey.OP_READ);
        }

        /**
         * Prepare the next payload with this connection's identifier and
         * sequence.
         */
          void
        request()
        {
            myBytes.clear();
            myBytes.putInt(myID).putInt(mySequence);
            while (myBytes.hasRemaining()) {
                myBytes.put((byte) 0x5a);
            }
            myBytes.flip();
            myWriting = true;
            mySent = System.nanoTime();
        }
    }

    /** Counts completed replies and retains a bounded latency sample. */
    private static final class Stats {

        /**
         * Bounded storage for the first million observed round-trip latencies.
         */
        private final long[] mySamples = new long[1_000_000];

        /** Total number of payloads verified during the traffic interval. */
        private long myReplies;

        /** Number of populated entries in the latency sample array. */
        private int mySampled;

        /**
         * Count a verified reply and retain its latency while sample capacity
         * remains.
         */
          void
        reply(long latency)
        {
            myReplies++;
            if (mySampled < mySamples.length) {
                mySamples[mySampled++] = latency;
            }
        }
    }
}

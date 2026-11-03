package com.fudco.selectabletls;

import java.io.IOException;
import java.lang.management.ManagementFactory;
import java.net.InetSocketAddress;
import java.net.StandardSocketOptions;
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

/** Small reproducible diagnostic, not a capacity or cross-library benchmark. */
public final class ResourceProbe {

    /** Maximum connection pairs admitted before waiting for handshakes. */
    private static int theAdmissionBatch = Integer.MAX_VALUE;

    /** Whether the harness reuses source ports across distinct destinations. */
    private static boolean theReusePorts;

    /** Source ports reserved by this probe for optional batch reuse. */
    private static final List<Integer> SOURCE_PORTS = new ArrayList<>();

    /** Prevent construction of this utility class. */
      private
    ResourceProbe()
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
     * Admit the requested population in bounded batches and retain every
     * established pair.
     */
      private static List<Pair>
    connect(TlsProvider provider, Selector selector, int count) throws Exception
    {
        List<Pair> pairs = new ArrayList<>();
        while (pairs.size() < count) {
            try {
                pairs.addAll(connectBatch(provider, selector,
                    Math.min(theAdmissionBatch, count - pairs.size())));
            } catch (Exception error) {
                System.err.println("POPULATION_SETUP_FAILED completed_pairs=" +
                    pairs.size() + " target=" + count);
                throw error;
            }
            if (count >= 10000 && pairs.size() % 8192 == 0) {
                System.out.println("POPULATION_READY pairs=" + pairs.size());
            }
        }
        return pairs;
    }

    /**
     * Establish one batch and wait for all TLS handshakes before measuring idle
     * resources.
     */
      private static List<Pair>
    connectBatch(TlsProvider provider, Selector selector,
        int count) throws Exception
    {
        List<Pair> pairs = new ArrayList<>();
        try (ServerSocketChannel listener =
            provider ==
            null ? ServerSocketChannel.open(
            ) : provider.openServerSocketChannel()) {
            listener.bind(new InetSocketAddress("127.0.0.1", 0));
            for (int i = 0; i < count; i++) {
                SocketChannel client =
                    provider ==
                    null ? SocketChannel.open() : provider.openSocketChannel(
                    "localhost");
                if (theReusePorts) {
                    /*
                     * Reuse only this probe's source ports, against distinct
                     * per-batch listeners. Avoid host-wide ephemeral-port
                     * changes.
                     */
                    client.setOption(StandardSocketOptions.SO_REUSEADDR, true);
                    client.bind(new InetSocketAddress("127.0.0.1",
                        i < SOURCE_PORTS.size() ? SOURCE_PORTS.get(i) : 0));
                    if (i == SOURCE_PORTS.size()) {
                        SOURCE_PORTS.add(((
                            InetSocketAddress) client.getLocalAddress())
                            .getPort());
                    }
                }
                client.connect(listener.getLocalAddress());
                SocketChannel server = listener.accept();
                client.configureBlocking(false);
                server.configureBlocking(false);
                client.register(selector, SelectionKey.OP_WRITE);
                server.register(selector, SelectionKey.OP_WRITE);
                pairs.add(new Pair(client, server));
            }
        }
        int pending = count * 2;
        long deadline = System.nanoTime() + 30_000_000_000L;
        while (pending > 0) {
            if (System.nanoTime() > deadline) {
                throw new AssertionError("Handshake population timed out");
            }
            selector.select(1000);
            for (SelectionKey key : selector.selectedKeys()) {
                SocketChannel channel = (SocketChannel) key.channel();
                if (channel instanceof TlsSocketChannel tls &&
                    !tls.handshakeComplete())
                {
                    /* surface asynchronous failure */
                    channel.read(ByteBuffer.allocate(1));
                    throw new AssertionError(
                        "Unfinished handshake selected writable");
                }
                key.interestOps(0);
                pending--;
            }
            selector.selectedKeys().clear();
        }
        return pairs;
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
     * Run the ResourceProbe entry point with its documented command-line
     * arguments.
     */
      public static void
    main(String[] args) throws Exception
    {
        int count = args.length == 0 ? 256 : Integer.parseInt(args[0]);
        int rounds = args.length < 2 ? 2000 : Integer.parseInt(args[1]);
        String mode = args.length < 3 ? "tls" : args[2];
        if (!mode.equals("tls") && !mode.equals("plain")) {
            throw new IllegalArgumentException("mode must be tls or plain");
        }
        boolean tls = mode.equals("tls");
        theAdmissionBatch =
            args.length < 4 ? Integer.MAX_VALUE : Integer.parseInt(args[3]);
        if (theAdmissionBatch < 1) {
            throw new IllegalArgumentException(
                "positive admission batch required");
        }
        theReusePorts = args.length > 4 && args[4].equals("reuse-ports");
        if (count < 1 || rounds < 1) {
            throw new IllegalArgumentException("positive counts required");
        }
        Path credentials = Files.createTempDirectory("SelectableTLS-Probe-");
        try {
            SSLContext context =
                tls ? ConformanceTest.certificateContext(credentials) : null;
            try (TlsProvider provider = tls ? new TlsProvider(context) : null;
                Selector selector =
                    tls ? provider.openSelector() : Selector.open()) {
                List<Pair> warmup = connect(provider, selector, 32);
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
                List<Pair> pairs = connect(provider, selector, count);
                long setupNanos = System.nanoTime() - setup;
                long idleHeap = heap();
                int idleThreads =
                    ManagementFactory.getThreadMXBean().getThreadCount();
                long idleCPUStart = cpu();
                Thread.sleep(1000);
                long idleCPU = cpu() - idleCPUStart;
                long[] latencies = new long[rounds];
                long allocationStart = allocated();
                long start = System.nanoTime();
                for (int i = 0; i < rounds; i++) {
                    latencies[i] =
                        roundTrip(pairs.get(i % Math.min(count, 64)), selector);
                }
                long traffic = System.nanoTime() - start;
                long allocation = allocated() - allocationStart;
                Arrays.sort(latencies);
                System.out.printf(Locale.ROOT,
                    ("java=%s os=%s arch=%s processors=%d " +
                    "max_heap_bytes=%d%n") +
                    ("transport=%s pairs=%d endpoints=%d " +
                    "warmup_pairs=32 active_pairs=%d rounds=%d " +
                    "payload_bytes=32 admission_batch=%d " +
                    "reuse_source_ports=%s%n") +
                    ("setup_ms=%.3f heap_baseline_bytes=%d " +
                    "heap_idle_bytes=%d incremental_heap_bytes_" +
                    "per_endpoint=%.1f%n") +
                    ("threads_baseline=%d threads_idle=%d " +
                    "idle_one_second_thread_cpu_ms=%.3f%n") +
                    ("round_trips_per_second=%.1f p50_us=%.3f " +
                    "p95_us=%.3f p99_us=%.3f " +
                    "allocated_bytes_per_round_trip=%.1f%n"),
                    System.getProperty("java.version"),
                    System.getProperty("os.name"),
                    System.getProperty("os.arch"), Runtime.getRuntime()
                    .availableProcessors(), Runtime.getRuntime().maxMemory(),
                    mode, count, count * 2, Math.min(count, 64), rounds,
                    Math.min(count, theAdmissionBatch), theReusePorts,
                    setupNanos / 1e6, baseHeap, idleHeap,
                    (idleHeap - baseHeap) / (count * 2.0), baseThreads,
                    idleThreads, idleCPU / 1e6, rounds * 1e9 / traffic,
                    latencies[rounds / 2] / 1e3, latencies[Math.min(rounds - 1,
                    (int) (rounds * .95))] / 1e3, latencies[Math.min(rounds - 1,
                    (int) (rounds * .99))] / 1e3, allocation / (double) rounds);
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
    receive(SocketChannel channel, Selector selector,
        ByteBuffer bytes) throws IOException
    {
        long deadline = System.nanoTime() + 5_000_000_000L;
        while (bytes.hasRemaining()) {
            int read = channel.read(bytes);
            if (read < 0) {
                throw new AssertionError("Unexpected EOF");
            }
            if (read == 0) {
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
        pair.client.keyFor(selector).interestOps(SelectionKey.OP_READ);
        pair.server.keyFor(selector).interestOps(SelectionKey.OP_READ);
        long start = System.nanoTime();
        if (pair.client.write(outgoing) != 32) {
            throw new AssertionError("Short diagnostic request");
        }
        receive(pair.server, selector, echoed);
        echoed.flip();
        if (pair.server.write(echoed) != 32) {
            throw new AssertionError("Short diagnostic reply");
        }
        outgoing.clear();
        receive(pair.client, selector, outgoing);
        long elapsed = System.nanoTime() - start;
        if (outgoing.getLong(0) != 0x123456789abcdefL) {
            throw new AssertionError("Payload mismatch");
        }
        pair.client.keyFor(selector).interestOps(0);
        pair.server.keyFor(selector).interestOps(0);
        return elapsed;
    }

    /** Two connected endpoints whose resources are released together. */
    private record Pair(SocketChannel client,
        SocketChannel server) implements AutoCloseable {

        /** {@inheritDoc} */
        @Override
          public void
        close() throws IOException
        {
            client.close();
            server.close();
        }
    }
}

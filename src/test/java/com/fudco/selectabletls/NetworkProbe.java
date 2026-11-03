package com.fudco.selectabletls;

import java.io.InputStream;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.SelectionKey;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.util.Iterator;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

/** Bounded two-process/host TLS echo qualification using only selectors. */
public final class NetworkProbe {

    /** Prevent construction of this utility class. */
      private
    NetworkProbe()
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
     * Drive bounded concurrent exchanges against the remote server and verify
     * ordered payloads and clean EOF.
     */
      private static void
    client(String host, int port, Path certificate, int count,
        int rounds) throws Exception
    {
        try (TlsProvider provider = new TlsProvider(trust(certificate));
            TlsSelector selector = provider.openSelector()) {
            for (int i = 0; i < count; i++) {
                TlsSocketChannel channel =
                    provider.openSocketChannel("localhost");
                channel.connect(new InetSocketAddress(host, port));
                channel.configureBlocking(false);
                Exchange exchange = new Exchange(i);
                exchange.request();
                channel.register(selector, SelectionKey.OP_WRITE, exchange);
            }
            int completed = 0;
            long replies = 0;
            long started = System.nanoTime();
            long limit = started + 60_000_000_000L;
            while (completed < count) {
                deadline(limit);
                selector.select(1000);
                for (Iterator<SelectionKey> iterator = selector.selectedKeys()
                    .iterator(); iterator.hasNext(); )
                {
                    SelectionKey key = iterator.next();
                    iterator.remove();
                    TlsSocketChannel channel = (TlsSocketChannel) key.channel();
                    Exchange exchange = (Exchange) key.attachment();
                    if (exchange.myWriting) {
                        channel.write(exchange.myBytes);
                        if (!exchange.myBytes.hasRemaining()) {
                            exchange.myBytes.clear();
                            exchange.myWriting = false;
                            key.interestOps(SelectionKey.OP_READ);
                        }
                    } else {
                        int read = channel.read(exchange.myBytes);
                        if (read < 0) {
                            check(exchange.mySequence == rounds, "early EOF");
                            channel.close();
                            completed++;
                            continue;
                        }
                        if (exchange.myBytes.hasRemaining()) {
                            continue;
                        }
                        exchange.myBytes.flip();
                        check(exchange.myBytes.getInt() == exchange.myID &&
                            exchange.myBytes.getInt() == exchange.mySequence,
                            "out-of-order response");
                        while (exchange.myBytes.hasRemaining()) {
                            check(exchange.myBytes.get() == (byte) 0x5a,
                                "corrupted payload");
                        }
                        replies++;
                        exchange.mySequence++;
                        if (exchange.mySequence == rounds) {
                            exchange.myBytes.clear();
                            channel.shutdownOutput();
                        } else {
                            exchange.request();
                            key.interestOps(SelectionKey.OP_WRITE);
                        }
                    }
                }
            }
            System.out.println("CLIENT_PASS connections=" + completed +
                " replies=" + replies + " payload_bytes=" + (replies * 32) +
                " elapsed_ms=" + (System.nanoTime() - started) / 1_000_000L);
        }
    }

    /** Fail the two-host probe when its global monotonic deadline expires. */
      private static void
    deadline(long limit)
    {
        check(System.nanoTime() < limit, "network probe exceeded 60 seconds");
    }

    /**
     * Run the NetworkProbe entry point with its documented command-line
     * arguments.
     */
      public static void
    main(String[] args) throws Exception
    {
        if (args.length == 4 && args[0].equals("server")) {
            server(Path.of(args[1]), args[2], Integer.parseInt(args[3]));
        } else if (args.length == 6 && args[0].equals("client")) {
            client(args[1], Integer.parseInt(args[2]), Path.of(args[3]),
                Integer.parseInt(args[4]), Integer.parseInt(args[5]));
        } else {
            throw new IllegalArgumentException(
                "server DIRECTORY BIND CONNECTIONS | client " +
                "HOST PORT CERTIFICATE CONNECTIONS ROUNDS");
        }
    }

    /**
     * Echo bounded per-peer buffers using selectors and retain the provider
     * until clients confirm clean closure.
     */
      private static void
    server(Path directory, String bind, int count) throws Exception
    {
        Files.createDirectories(directory);
        SSLContext context = ConformanceTest.certificateContext(directory);
        try (TlsProvider provider = new TlsProvider(context);
            TlsSelector selector = provider.openSelector();
            TlsServerSocketChannel listener =
                provider.openServerSocketChannel()) {
            listener.bind(new InetSocketAddress(bind, 0));
            listener.configureBlocking(false);
            SelectionKey acceptKey =
                listener.register(selector, SelectionKey.OP_ACCEPT);
            int port =
                ((InetSocketAddress) listener.getLocalAddress()).getPort();
            Files.writeString(directory.resolve("port"),
                Integer.toString(port));
            System.out.println("READY " + port);
            int accepted = 0;
            int completed = 0;
            long bytes = 0;
            long limit = System.nanoTime() + 60_000_000_000L;
            while (completed < count) {
                deadline(limit);
                selector.select(1000);
                for (Iterator<SelectionKey> iterator = selector.selectedKeys()
                    .iterator(); iterator.hasNext(); )
                {
                    SelectionKey key = iterator.next();
                    iterator.remove();
                    if (key == acceptKey) {
                        TlsSocketChannel channel;
                        while (accepted < count) {
                            channel = listener.accept();
                            if (channel == null) {
                                break;
                            }
                            channel.configureBlocking(false);
                            channel.register(selector, SelectionKey.OP_READ,
                                new Exchange(accepted++));
                        }
                        if (accepted == count) {
                            acceptKey.interestOps(0);
                        }
                        continue;
                    }
                    TlsSocketChannel channel = (TlsSocketChannel) key.channel();
                    Exchange exchange = (Exchange) key.attachment();
                    if (!exchange.myWriting) {
                        int read = channel.read(exchange.myBytes);
                        if (read < 0) {
                            channel.close();
                            completed++;
                            continue;
                        }
                        if (read == 0) {
                            continue;
                        }
                        bytes += read;
                        exchange.myBytes.flip();
                        exchange.myWriting = true;
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
            /*
             * The peer has already received every echoed byte. Await its clean
             * EOF after our close_notify, rather than aborting via provider
             * close.
             */
            long drainLimit = System.nanoTime() + 5_000_000_000L;
            while (!selector.keys().isEmpty() &&
                System.nanoTime() < drainLimit)
            {
                selector.selectNow();
                /*
                 * Keys are cancelled immediately at channel.close. Transport
                 * drain is asynchronous; clients independently verify orderly
                 * EOF.
                 */
                if (selector.keys().size() == 1) {
                    break;
                }
            }
            System.out.println("SERVER_PASS connections=" + completed +
                " echoed_bytes=" + bytes);
            /*
             * Keep the provider alive briefly while clients consume
             * close_notify; test completion is communicated through a file, not
             * a per-peer thread.
             */
            Path done = directory.resolve("client-done");
            while (!Files.exists(done)) {
                deadline(limit);
                Thread.sleep(10);
            }
        }
    }

    /**
     * Create a trust context containing only the supplied public test
     * certificate.
     */
      private static SSLContext
    trust(Path certificate) throws Exception
    {
        KeyStore store = KeyStore.getInstance("PKCS12");
        store.load(null, null);
        try (InputStream input = Files.newInputStream(certificate)) {
            store.setCertificateEntry("server",
                CertificateFactory.getInstance("X.509")
                .generateCertificate(input));
        }
        TrustManagerFactory manager =
            TrustManagerFactory.getInstance(
            TrustManagerFactory.getDefaultAlgorithm());
        manager.init(store);
        SSLContext context = SSLContext.getInstance("TLS");
        context.init(null, manager.getTrustManagers(), null);
        return context;
    }

    /**
     * Bounded state for one endpoint of a verified request and echo exchange.
     */
    private static final class Exchange {

        /**
         * Bounded request or echo buffer, with mode determined by the exchange
         * phase.
         */
        private final ByteBuffer myBytes = ByteBuffer.allocate(32);

        /** Connection identifier carried in each verified payload. */
        private final int myID;

        /** Next message sequence number for this connection. */
        private int mySequence;

        /** Whether this endpoint is currently draining its output buffer. */
        private boolean myWriting;

        /** Initialize the per-connection payload and exchange state. */
        Exchange(int id)
        {
            myID = id;
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
        }
    }
}

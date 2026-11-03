package com.fudco.selectabletls.examples;

import com.fudco.selectabletls.TlsProvider;
import com.fudco.selectabletls.TlsSelector;
import com.fudco.selectabletls.TlsServerSocketChannel;
import com.fudco.selectabletls.TlsSocketChannel;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.SelectionKey;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Iterator;
import javax.net.ssl.SSLContext;

/**
 * Small selector server and blocking client using ordinary JSSE key/trust
 * stores.
 */
public final class TlsEcho {

    /** Prevent construction of this utility class. */
      private
    TlsEcho()
    {
    }

    /**
     * Send one bounded message, verify the echo and consume clean TLS EOF
     * before closing the provider.
     */
      private static void
    client(String host, int port, String message) throws Exception
    {
        byte[] expected = message.getBytes(StandardCharsets.UTF_8);
        if (expected.length > 4096) {
            throw new IllegalArgumentException(
                "Example message must fit in 4096 bytes");
        }
        try (TlsProvider provider = new TlsProvider(SSLContext.getDefault());
            TlsSocketChannel channel = provider.openSocketChannel(host)) {
            channel.socket().connect(new InetSocketAddress(host, port), 5000);
            channel.socket().setSoTimeout(5000);
            channel.socket().getOutputStream().write(expected);
            byte[] reply =
                channel.socket().getInputStream().readNBytes(expected.length);
            if (!Arrays.equals(reply, expected)) {
                throw new IOException("Echo mismatch");
            }
            channel.shutdownOutput();
            if (channel.socket().getInputStream().read() != -1) {
                throw new IOException("Unexpected trailing data");
            }
            System.out.println("ECHO " + new String(reply,
                StandardCharsets.UTF_8));
            /*
             * Peer EOF confirms the TLS close exchange before provider
             * shutdown.
             */
        }
    }

    /**
     * Run the TlsEcho entry point with its documented command-line arguments.
     */
      public static void
    main(String[] args) throws Exception
    {
        if (args.length == 2 && args[0].equals("server")) {
            server(Integer.parseInt(args[1]));
        } else if (args.length == 4 && args[0].equals("client")) {
            client(args[1], Integer.parseInt(args[2]), args[3]);
        } else {
            throw new IllegalArgumentException(
                "server PORT | client HOST PORT MESSAGE");
        }
    }

    /**
     * Echo with one bounded buffer per peer, suspending reads while output is
     * pending.
     */
      private static void
    server(int port) throws Exception
    {
        try (TlsProvider provider = new TlsProvider(SSLContext.getDefault());
            TlsSelector selector = provider.openSelector();
            TlsServerSocketChannel listener =
                provider.openServerSocketChannel()) {
            listener.bind(new InetSocketAddress("127.0.0.1", port));
            listener.configureBlocking(false);
            SelectionKey accept =
                listener.register(selector, SelectionKey.OP_ACCEPT);
            System.out.println("READY " +
                ((InetSocketAddress) listener.getLocalAddress()).getPort());
            while (!Thread.currentThread().isInterrupted()) {
                selector.select();
                for (Iterator<SelectionKey> iterator = selector.selectedKeys()
                    .iterator(); iterator.hasNext(); )
                {
                    SelectionKey key = iterator.next();
                    iterator.remove();
                    if (key == accept) {
                        TlsSocketChannel channel;
                        while (true) {
                            channel = listener.accept();
                            if (channel == null) {
                                break;
                            }
                            channel.configureBlocking(false);
                            /*
                             * At most one application buffer per peer. Stop
                             * reading while echo output is pending to apply
                             * backpressure.
                             */
                            channel.register(selector, SelectionKey.OP_READ,
                                ByteBuffer.allocate(4096));
                        }
                        continue;
                    }
                    TlsSocketChannel channel = (TlsSocketChannel) key.channel();
                    ByteBuffer bytes = (ByteBuffer) key.attachment();
                    try {
                        if (key.isReadable()) {
                            int count = channel.read(bytes);
                            if (count < 0) {
                                channel.close();
                                continue;
                            }
                            if (count == 0) {
                                continue;
                            }
                            bytes.flip();
                        }
                        channel.write(bytes);
                        if (bytes.hasRemaining()) {
                            key.interestOps(SelectionKey.OP_WRITE);
                        } else {
                            bytes.clear();
                            key.interestOps(SelectionKey.OP_READ);
                        }
                    } catch (IOException failure) {
                        System.err.println("Peer closed: " + failure);
                        channel.abort();
                    }
                }
            }
        }
    }
}

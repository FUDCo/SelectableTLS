package com.fudco.selectabletls;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.nio.channels.AlreadyBoundException;
import java.nio.channels.AlreadyConnectedException;
import java.nio.channels.AsynchronousCloseException;
import java.nio.channels.ClosedChannelException;
import java.nio.channels.ConnectionPendingException;
import java.nio.channels.NotYetBoundException;
import java.nio.channels.NotYetConnectedException;
import java.nio.channels.UnresolvedAddressException;

/**
 * Translate channel-state failures at the Socket/ServerSocket adapter boundary.
 */
final class SocketErrors {

    /** Prevent construction of this utility class. */
      private
    SocketErrors()
    {
    }

    /**
     * Translate channel connect failures, preserving unresolved names as
     * UnknownHostException.
     */
      static IOException
    connect(Exception cause, SocketAddress address)
    {
        if (cause instanceof UnresolvedAddressException &&
            address instanceof InetSocketAddress inet)
        {
            UnknownHostException error =
                new UnknownHostException(inet.getHostString());
            error.initCause(cause);
            return error;
        }
        return io(cause);
    }

    /**
     * Map channel state failures to Socket exceptions while preserving
     * interruption and TLS errors.
     */
      static IOException
    io(Exception cause)
    {
        String message;
        if (cause instanceof AsynchronousCloseException) {
            return (IOException) cause;
        }
        if (cause instanceof ClosedChannelException) {
            message = "Socket closed";
        } else if (cause instanceof NotYetConnectedException) {
            message = "Socket is not connected";
        } else if (cause instanceof AlreadyConnectedException) {
            message = "Socket is already connected";
        } else if (cause instanceof ConnectionPendingException) {
            message = "Connection is pending";
        } else if (cause instanceof AlreadyBoundException) {
            message = "Socket is already bound";
        } else if (cause instanceof NotYetBoundException) {
            message = "Socket is not bound";
        } else if (cause instanceof UnresolvedAddressException) {
            message = "Unresolved address";
        } else if (cause instanceof IOException io) {
            return io;
        } else if (cause instanceof RuntimeException runtime) {
            throw runtime;
        } else {
            throw new AssertionError(cause);
        }
        SocketException error = new SocketException(message);
        error.initCause(cause);
        return error;
    }
}

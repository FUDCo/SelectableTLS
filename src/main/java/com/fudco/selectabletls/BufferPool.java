package com.fudco.selectabletls;

import java.nio.ByteBuffer;
import java.util.concurrent.ConcurrentLinkedDeque;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Bounded provider-local reuse; empty connections retain no transport buffers.
 */
final class BufferPool {

    /** Maximum number of idle buffers retained in each size bucket. */
    private static final int CACHED_PER_SIZE = 64;

    /** Pool for the smallest supported TLS record buffer. */
    private final Bucket myRecord = new Bucket(32768);

    /** Pool sized for the configured application output queue. */
    private final Bucket myApplication;

    /** Create bounded record and application-queue buffer caches. */
    BufferPool(int queueLimit)
    {
        myApplication =
            queueLimit == myRecord.mySize ? myRecord : new Bucket(queueLimit);
    }

    /**
     * Obtain a buffer with at least the requested capacity within the
     * configured bound.
     */
      ByteBuffer
    acquire(int minimum)
    {
        if (minimum <= myRecord.mySize) {
            return myRecord.acquire();
        }
        if (minimum <= myApplication.mySize) {
            return myApplication.acquire();
        }
        throw new IllegalArgumentException(
            "TLS buffer requirement exceeds configured bound");
    }

    /**
     * Return a supported buffer to its bounded cache, accepting null for absent
     * buffers.
     */
      void
    release(ByteBuffer buffer)
    {
        if (buffer == null) {
            return;
        }
        if (buffer.capacity() == myRecord.mySize) {
            myRecord.release(buffer);
        } else if (buffer.capacity() == myApplication.mySize) {
            myApplication.release(buffer);
        }
    }

    /** Concurrent bounded cache for one fixed buffer capacity. */
    private static final class Bucket {

        /** Capacity shared by every buffer in this bucket. */
        private final int mySize;

        /** Idle buffers available for reuse by concurrent connections. */
        private final ConcurrentLinkedDeque<ByteBuffer> myBuffers =
            new ConcurrentLinkedDeque<>();

        /** Reserved cache slots, including concurrent returns in progress. */
        private final AtomicInteger myCached = new AtomicInteger();

        /** Create an initially empty cache for one buffer capacity. */
        Bucket(int size)
        {
            mySize = size;
        }

        /** Take an idle buffer or allocate one when this bucket is empty. */
          ByteBuffer
        acquire()
        {
            ByteBuffer buffer = myBuffers.poll();
            if (buffer == null) {
                return ByteBuffer.allocate(mySize);
            }
            myCached.decrementAndGet();
            buffer.clear();
            return buffer;
        }

        /**
         * Reserve an idle cache slot if capacity permits; otherwise discard the
         * buffer.
         */
          void
        release(ByteBuffer buffer)
        {
            if (myCached.getAndIncrement() < CACHED_PER_SIZE) {
                myBuffers.offer(buffer);
            } else {
                myCached.decrementAndGet();
            }
        }
    }
}

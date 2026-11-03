package com.fudco.selectabletls;

import java.io.IOException;
import java.nio.channels.ClosedChannelException;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.util.Comparator;
import java.util.IdentityHashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.NavigableSet;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

/** Sole owner of transport selection and engine progression. */
final class Reactor implements AutoCloseable {

    /** Native selector owned exclusively by the transport thread. */
    private final Selector mySelector = Selector.open();

    /** Connections awaiting a bounded turn of engine progression. */
    private final ConcurrentLinkedQueue<TlsSocketChannel> myChanged =
        new ConcurrentLinkedQueue<>();

    /** Connections owned by this reactor until transport release. */
    private final Set<TlsSocketChannel> myChannels =
        ConcurrentHashMap.newKeySet();

    /**
     * Only the reactor touches these structures. Removal is logarithmic and
     * does not retain completed/closed handshakes until an arbitrary timer
     * expires.
     */
    private final NavigableSet<Deadline> myDeadlines =
        new TreeSet<>(Comparator.comparingLong(Deadline::time)
            .thenComparingLong(Deadline::sequence));

    /** Current expiry entry for each connection with a deadline. */
    private final Map<TlsSocketChannel, Deadline> myTimers =
        new IdentityHashMap<>();

    /** Tie breaker for equal deadlines in the ordered queue. */
    private long myTimerSequence;

    /** Bounded executor for potentially blocking JSSE delegated tasks. */
    private final ThreadPoolExecutor myTasks;

    /** Single daemon responsible for transport and engine progress. */
    private final Thread myThread;

    /** Shutdown flag visible to callers and the transport thread. */
    private volatile boolean myClosed;

    /**
     * Start the shared transport thread with bounded delegated-task resources.
     */
    Reactor(int taskThreads, int queuedTasks) throws IOException
    {
        myTasks =
            new ThreadPoolExecutor(taskThreads, taskThreads, 0,
            TimeUnit.MILLISECONDS, new ArrayBlockingQueue<>(queuedTasks),
            runnable -> {
                Thread worker = new Thread(runnable, "SelectableTLS-task");
                worker.setDaemon(true);
                return worker;
            }, new ThreadPoolExecutor.AbortPolicy());
        myThread = new Thread(this::run, "SelectableTLS-transport");
        myThread.setDaemon(true);
        myThread.start();
    }

    /** Admit a connection and schedule its initial transport progression. */
      void
    add(TlsSocketChannel channel) throws IOException
    {
        ensureOpen();
        myChannels.add(channel);
        if (myClosed) {
            myChannels.remove(channel);
            throw new ClosedChannelException();
        }
        signal(channel);
    }

    /** {@inheritDoc} */
    @Override
      public void
    close() throws IOException
    {
        myClosed = true;
        mySelector.wakeup();
        myTasks.shutdownNow();
        if (Thread.currentThread() != myThread) {
            try {
                myThread.join(5000);
            } catch (InterruptedException error) {
                Thread.currentThread().interrupt();
                throw new IOException(error);
            }
            if (myThread.isAlive()) {
                throw new IOException("TLS reactor did not terminate");
            }
        }
    }

    /** Reject new work after the reactor has stopped. */
      void
    ensureOpen() throws ClosedChannelException
    {
        if (myClosed) {
            throw new ClosedChannelException();
        }
    }

    /** Progress expired connections without scanning the idle population. */
      private void
    expireDeadlines()
    {
        long now = System.nanoTime();
        while (!myDeadlines.isEmpty() && now - myDeadlines.first().time >= 0) {
            Deadline deadline = myDeadlines.pollFirst();
            myTimers.remove(deadline.channel);
            update(deadline.channel);
        }
    }

    /**
     * Release transport ownership and schedule removal of its selector state.
     */
      void
    forget(TlsSocketChannel channel)
    {
        myChannels.remove(channel);
        signal(channel);
    }

    /** Replace a connection's expiry entry when its next deadline changes. */
      private void
    reschedule(TlsSocketChannel channel)
    {
        long next = channel.nextDeadline();
        Deadline previous = myTimers.get(channel);
        if (previous != null && previous.time == next) {
            return;
        }
        if (previous != null) {
            myDeadlines.remove(previous);
            myTimers.remove(channel);
        }
        if (next != 0) {
            Deadline deadline = new Deadline(channel, next, myTimerSequence++);
            myDeadlines.add(deadline);
            myTimers.put(channel, deadline);
        }
    }

    /**
     * Drive bounded update batches, timer expiry and native readiness until
     * shutdown.
     */
      private void
    run()
    {
        try {
            while (!myClosed) {
                /*
                 * A bounded batch prevents a busy producer from starving native
                 * events.
                 */
                for (int i = 0; i < 1024; i++) {
                    TlsSocketChannel channel = myChanged.poll();
                    if (channel == null) {
                        break;
                    }
                    channel.myScheduled.set(false);
                    update(channel);
                }
                expireDeadlines();
                if (!myChanged.isEmpty()) {
                    mySelector.selectNow();
                } else if (myDeadlines.isEmpty()) {
                    mySelector.select();
                } else {
                    mySelector.select(Math.max(1, (myDeadlines.first()
                        .time - System.nanoTime() + 999999) / 1_000_000L));
                }
                Iterator<SelectionKey> iterator =
                    mySelector.selectedKeys().iterator();
                while (iterator.hasNext()) {
                    SelectionKey key = iterator.next();
                    iterator.remove();
                    if (key.isValid()) {
                        update((TlsSocketChannel) key.attachment());
                    }
                }
            }
        } catch (IOException | RuntimeException error) {
            for (TlsSocketChannel channel : myChannels) {
                channel.fail(error);
            }
        } finally {
            myClosed = true;
            for (TlsSocketChannel channel : myChannels) {
                try {
                    channel.abort();
                } catch (IOException ignored) {
                    /* transport already failed */
                }
            }
            try {
                mySelector.close();
            } catch (IOException ignored) {
                /* shutting down */
            }
            myTasks.shutdownNow();
            myDeadlines.clear();
            myTimers.clear();
            myChanged.clear();
            myChannels.clear();
        }
    }

    /** Deduplicate a connection update and wake the transport selector. */
      void
    signal(TlsSocketChannel channel)
    {
        if (myClosed) {
            return;
        }
        if (channel.myScheduled.compareAndSet(false, true)) {
            myChanged.add(channel);
        }
        mySelector.wakeup();
    }

    /**
     * Submit engine tasks to the bounded executor and report completion or
     * rejection.
     */
      void
    tasks(TlsSocketChannel channel, List<Runnable> batch)
    {
        try {
            myTasks.execute(() -> {
                Throwable failure = null;
                try {
                    for (Runnable task : batch) {
                        task.run();
                    }
                } catch (Throwable error) {
                    failure = error;
                }
                channel.taskCompleted(failure);
            });
        } catch (RejectedExecutionException error) {
            channel.taskCompleted(error);
        }
    }

    /**
     * Progress one connection, refresh its native interests and reschedule
     * expiry.
     */
      private void
    update(TlsSocketChannel channel)
    {
        try {
            if (!channel.isTransportOpen()) {
                SelectionKey key = channel.myRaw.keyFor(mySelector);
                if (key != null) {
                    key.cancel();
                }
                myChannels.remove(channel);
                return;
            }
            channel.checkDeadline(System.nanoTime());
            channel.pump();
            if (!channel.isTransportOpen()) {
                SelectionKey key = channel.myRaw.keyFor(mySelector);
                if (key != null) {
                    key.cancel();
                }
                myChannels.remove(channel);
                return;
            }
            int ops = channel.transportInterests();
            SelectionKey key = channel.myRaw.keyFor(mySelector);
            if (key == null) {
                channel.myRaw.register(mySelector, ops, channel);
            } else if (key.isValid()) {
                key.interestOps(ops);
            }
        } catch (IOException | RuntimeException error) {
            channel.fail(error);
        } finally {
            reschedule(channel);
        }
    }

    /** Connection expiry ordered by monotonic time and a unique tie breaker. */
    private record Deadline(TlsSocketChannel channel, long time,
        long sequence) {
    }
}

package com.fudco.selectabletls;

import java.io.IOException;
import java.nio.channels.CancelledKeyException;
import java.nio.channels.ClosedChannelException;
import java.nio.channels.ClosedSelectorException;
import java.nio.channels.SelectableChannel;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.spi.AbstractSelectableChannel;
import java.nio.channels.spi.AbstractSelectionKey;
import java.nio.channels.spi.AbstractSelector;
import java.util.AbstractSet;
import java.util.ArrayDeque;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Selector combining native plaintext channels and application-level TLS
 * readiness.
 */
public final class TlsSelector extends AbstractSelector {

    /** Native selector for plaintext readiness and reactor wakeups. */
    private final Selector myDelegate;

    /** Provider that owns this selector's lifecycle. */
    private final TlsProvider myOwner;

    /** All registered application keys, including pending cancellations. */
    private final Set<SelectionKey> myKeys = ConcurrentHashMap.newKeySet();

    /** Keys published to the application's selected-key set. */
    private final Set<SelectionKey> mySelected = new HashSet<>();

    /** TLS keys that may currently satisfy their selection interests. */
    private final Set<Key> myReadyTLS = new HashSet<>();

    /** Deduplicated readiness updates plus finite-pass boundary markers. */
    private final ConcurrentLinkedQueue<Object> myChanges =
        new ConcurrentLinkedQueue<>();

    /** Sentinel limiting each pass through concurrent readiness updates. */
    private final Object myChangeBoundary = new Object();

    /**
     * Interest changes are applied once, at the start of a selection. TLS state
     * changes must still be processed while that selection waits for readiness.
     */
    private final ArrayDeque<Key> myConfigurations = new ArrayDeque<>();

    /** Pending application wakeup, distinct from internal notifications. */
    private final AtomicBoolean myExplicitWakeup = new AtomicBoolean();

    /** Coordinates registration and configuration with selector closure. */
    private final Object myRegistrationLock = new Object();

    /** Whether the current collection saw readiness, even for retained keys. */
    private boolean myObservedReady;

    /** Public set whose monitor protects selected-key operations. */
    private final Set<SelectionKey> mySelectedView = new AbstractSet<>() {

        /** {@inheritDoc} */
        @Override
          public void
        clear()
        {
            mySelected.clear();
        }

        /** {@inheritDoc} */
        @Override
          public Iterator<SelectionKey>
        iterator()
        {
            return mySelected.iterator();
        }

        /** {@inheritDoc} */
        @Override
          public boolean
        remove(Object key)
        {
            return mySelected.remove(key);
        }

        /** {@inheritDoc} */
        @Override
          public int
        size()
        {
            return mySelected.size();
        }
    };

    /**
     * Combine native selection with provider-driven application TLS readiness.
     */
    TlsSelector(TlsProvider provider, Selector delegate)
    {
        super(provider);
        myOwner = provider;
        myDelegate = delegate;
    }

    /**
     * Snapshot queued interest changes once at the start of a selection
     * operation.
     */
      private void
    applyConfigurations()
    {
        synchronized (myRegistrationLock) {
            Key key;
            while (true) {
                key = myConfigurations.poll();
                if (key == null) {
                    break;
                }
                key.myConfigurationQueued = false;
                key.mySelectionInterests = key.myInterests;
                changed(key);
            }
        }
    }

    /**
     * Remove cancelled registrations from application sets, native selection
     * and channel bookkeeping.
     */
      private void
    cancellations()
    {
        synchronized (cancelledKeys()) {
            for (SelectionKey item : cancelledKeys()) {
                Key key = (Key) item;
                if (key.myNativeKey != null) {
                    key.myNativeKey.cancel();
                }
                if (key.myChannel instanceof TlsSocketChannel tls) {
                    tls.removeKey(key);
                }
                myKeys.remove(key);
                mySelected.remove(key);
                myReadyTLS.remove(key);
                deregister(key);
            }
            cancelledKeys().clear();
        }
    }

    /**
     * Queue at most one readiness update per key and wake the delegate
     * selector.
     */
      void
    changed(Key key)
    {
        if (!isOpen()) {
            return;
        }
        if (key.myQueued.compareAndSet(false, true)) {
            myChanges.add(key);
        }
        myDelegate.wakeup();
    }

    /** Reject selection and key-set queries after closure. */
      private void
    checkOpen()
    {
        if (!isOpen()) {
            throw new ClosedSelectorException();
        }
    }

    /**
     * Publish TLS and native readiness, counting keys whose selected state
     * gained ready bits.
     */
      private int
    collect()
    {
        int count = 0;
        myObservedReady = false;
        for (Iterator<Key> it = myReadyTLS.iterator(); it.hasNext(); ) {
            Key key = it.next();
            if (!key.isValid()) {
                it.remove();
                continue;
            }
            int ready =
                ((TlsSocketChannel) key.myChannel)
                .readyOps() & key.mySelectionInterests;
            if (ready == 0) {
                it.remove();
            } else {
                myObservedReady = true;
                count += publish(key, ready);
            }
        }
        for (Iterator<SelectionKey> it = myDelegate.selectedKeys().iterator();
            it.hasNext(); )
        {
            SelectionKey nativeKey = it.next();
            it.remove();
            if (nativeKey.isValid()) {
                Key key = (Key) nativeKey.attachment();
                int ready = nativeKey.readyOps() & key.mySelectionInterests;
                if (ready != 0 && key.isValid()) {
                    myObservedReady = true;
                }
                count += publish(key, ready);
            }
        }
        return count;
    }

    /**
     * Queue new interests for the next selection without altering the active
     * snapshot.
     */
      private void
    configure(Key key, int interests)
    {
        synchronized (myRegistrationLock) {
            key.myInterests = interests;
            if (!isOpen()) {
                return;
            }
            if (!key.myConfigurationQueued) {
                key.myConfigurationQueued = true;
                myConfigurations.add(key);
            }
        }
        myDelegate.wakeup();
    }

    /**
     * Apply a finite prefix of readiness updates so continuous producers cannot
     * starve native events.
     */
      private void
    drainChanges() throws IOException
    {
        /*
         * A finite queue prefix prevents continuous producers from starving
         * native events or a selectNow caller. Only this selecting thread
         * drains.
         */
        myChanges.add(myChangeBoundary);
        Object change;
        while (true) {
            change = myChanges.poll();
            if (change == myChangeBoundary) {
                break;
            }
            Key key = (Key) change;
            key.myQueued.set(false);
            if (!key.isValid()) {
                continue;
            }
            if (key.myChannel instanceof TlsSocketChannel tls) {
                if ((tls.readyOps() & key.mySelectionInterests) != 0) {
                    myReadyTLS.add(key);
                } else {
                    myReadyTLS.remove(key);
                }
            } else {
                SelectableChannel raw =
                    key.myChannel instanceof TlsServerSocketChannel server ?
                    server.myRaw : key.myChannel;
                try {
                    if (key.myNativeKey == null) {
                        key.myNativeKey =
                            raw.register(myDelegate, key.mySelectionInterests,
                            key);
                    } else {
                        key.myNativeKey.interestOps(key.mySelectionInterests);
                    }
                } catch (ClosedChannelException | CancelledKeyException ex) {
                    key.cancel();
                }
            }
        }
    }

    /** {@inheritDoc} */
    @Override
      protected void
    implCloseSelector() throws IOException
    {
        try {
            myDelegate.wakeup();
            synchronized (this) {
                synchronized (mySelectedView) {
                    /*
                     * Registration holds the channel's registration lock. Do
                     * not retain registrationLock while deregistering from
                     * channels.
                     */
                    synchronized (myRegistrationLock) {
                        for (SelectionKey key : myKeys) {
                            key.cancel();
                        }
                        myConfigurations.clear();
                    }
                    cancellations();
                    myDelegate.close();
                    myChanges.clear();
                }
            }
        } finally {
            myOwner.released(this);
        }
    }

    /** {@inheritDoc} */
    @Override
      public Set<SelectionKey>
    keys()
    {
        checkOpen();
        return Collections.unmodifiableSet(myKeys);
    }

    /**
     * Add newly ready bits while retaining the selected-key semantics required
     * by NIO.
     */
      private int
    publish(Key key, int ops)
    {
        if (!key.isValid() || ops == 0) {
            return 0;
        }
        if (mySelected.add(key)) {
            key.myReady = ops;
            return 1;
        }
        int added = ops & ~key.myReady;
        key.myReady |= ops;
        return added != 0 ? 1 : 0;
    }

    /** {@inheritDoc} */
    @Override
      protected SelectionKey
    register(AbstractSelectableChannel channel, int ops, Object attachment)
    {
        synchronized (myRegistrationLock) {
            checkOpen();
            Key key = new Key(channel, this, ops);
            key.attach(attachment);
            myKeys.add(key);
            if (channel instanceof TlsSocketChannel tls) {
                tls.addKey(key);
            }
            configure(key, ops);
            return key;
        }
    }

    /** {@inheritDoc} */
    @Override
      public int
    select(long timeout) throws IOException
    {
        if (timeout < 0) {
            throw new IllegalArgumentException("timeout");
        }
        return selectInternal(timeout, false);
    }

    /** {@inheritDoc} */
    @Override
      public int
    select() throws IOException
    {
        return select(0);
    }

    /**
     * Coordinate cancellation, interest snapshots, readiness, timeouts and
     * application wakeups.
     */
      private int
    selectInternal(long timeout, boolean now) throws IOException
    {
        synchronized (this) {
            synchronized (mySelectedView) {
                checkOpen();
                applyConfigurations();
                long started = System.nanoTime();
                long duration = TimeUnit.MILLISECONDS.toNanos(timeout);
                for (; ; ) {
                    cancellations();
                    drainChanges();
                    myDelegate.selectNow();
                    /*
                     * selectNow consumes native wakeups. A TLS state change can
                     * arrive after the first drain but before that call;
                     * process it before deciding whether it is safe to block
                     * again.
                     */
                    drainChanges();
                    int count = collect();
                    if (!isOpen()) {
                        return 0;
                    }
                    boolean awakened = myExplicitWakeup.getAndSet(false);
                    if (myObservedReady || now || awakened ||
                        Thread.currentThread().isInterrupted())
                    {
                        return count;
                    }
                    long remaining =
                        timeout ==
                        0 ? Long.MAX_VALUE : duration - (System.nanoTime(
                        ) - started);
                    if (remaining <= 0) {
                        return 0;
                    }
                    if (!isOpen()) {
                        return 0;
                    }
                    if (!myChanges.isEmpty()) {
                        continue;
                    }
                    try {
                        begin();
                        if (timeout == 0) {
                            myDelegate.select();
                        } else {
                            myDelegate.select(remaining / 1_000_000L +
                                (remaining % 1_000_000L == 0 ? 0 : 1));
                        }
                    } finally {
                        end();
                    }
                    if (!isOpen()) {
                        return 0;
                    }
                    cancellations();
                    drainChanges();
                    count = collect();
                    awakened = myExplicitWakeup.getAndSet(false);
                    if (myObservedReady || awakened || Thread.currentThread()
                        .isInterrupted())
                    {
                        return count;
                    }
                }
            }
        }
    }

    /** {@inheritDoc} */
    @Override
      public int
    selectNow() throws IOException
    {
        return selectInternal(0, true);
    }

    /** {@inheritDoc} */
    @Override
      public Set<SelectionKey>
    selectedKeys()
    {
        checkOpen();
        return mySelectedView;
    }

    /** {@inheritDoc} */
    @Override
      public Selector
    wakeup()
    {
        myExplicitWakeup.set(true);
        myDelegate.wakeup();
        return this;
    }

    /**
     * Application registration separating requested interests from selection
     * snapshots.
     */
    static final class Key extends AbstractSelectionKey {

        /** Application channel represented by this registration. */
        final AbstractSelectableChannel myChannel;

        /** TLS selector to notify when this key's readiness changes. */
        final TlsSelector mySelector;

        /** Whether a readiness update for this key is already queued. */
        final AtomicBoolean myQueued = new AtomicBoolean();

        /** Most recent interests requested by the application. */
        volatile int myInterests;

        /**
         * Interest snapshot used throughout the current selection operation.
         */
        int mySelectionInterests;

        /** Whether the next selection must apply updated interests. */
        boolean myConfigurationQueued;

        /** Ready bits published by the most recent selection of this key. */
        volatile int myReady;

        /** Delegate registration for a native channel or TLS listener. */
        SelectionKey myNativeKey;

        /**
         * Associate a channel and initial interests with its application
         * selector.
         */
        Key(AbstractSelectableChannel channel, TlsSelector selector,
            int interests)
        {
            myChannel = channel;
            mySelector = selector;
            myInterests = interests;
        }

        /** {@inheritDoc} */
        @Override
          public SelectableChannel
        channel()
        {
            return myChannel;
        }

        /** Reject operations on a cancelled selection key. */
          void
        checkValid()
        {
            if (!isValid()) {
                throw new CancelledKeyException();
            }
        }

        /** {@inheritDoc} */
        @Override
          public int
        interestOps()
        {
            checkValid();
            return myInterests;
        }

        /** {@inheritDoc} */
        @Override
          public synchronized SelectionKey
        interestOps(int ops)
        {
            checkValid();
            if ((ops & ~myChannel.validOps()) != 0) {
                throw new IllegalArgumentException("interest bits");
            }
            mySelector.configure(this, ops);
            return this;
        }

        /** {@inheritDoc} */
        @Override
          public int
        readyOps()
        {
            checkValid();
            return myReady;
        }

        /** {@inheritDoc} */
        @Override
          public Selector
        selector()
        {
            return mySelector;
        }
    }
}

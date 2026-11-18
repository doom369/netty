/*
 * Copyright 2026 The Netty Project
 *
 * The Netty Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package io.netty.handler.ssl;

import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReferenceArray;

/**
 * EXPERIMENT: storage candidates for the session cache.
 */
final class SessionCacheCandidates {
    private SessionCacheCandidates() { }

    static OpenSslSessionCache create(String name, OpenSslEngineMap engines) {
        if ("LOCKED".equals(name)) {
            return new OpenSslSessionCache(engines);
        }
        if ("CHM_QUEUE".equals(name)) {
            return new ChmQueue(engines);
        }
        if ("CHM_RING".equals(name)) {
            return new ChmRing(engines);
        }
        if ("ASSOC_TABLE".equals(name)) {
            return new AssocTable(engines);
        }
        if ("STRIPED_LOCK".equals(name)) {
            return new Striped(engines);
        }
        throw new IllegalArgumentException(name);
    }

    /** ConcurrentHashMap for lookups + ConcurrentLinkedQueue keeping the insertion order for eviction. */
    static final class ChmQueue extends LockFreeOpenSslSessionCache {
        private final ConcurrentHashMap<OpenSslSessionId, NativeSslSession> map =
                new ConcurrentHashMap<OpenSslSessionId, NativeSslSession>();
        private final ConcurrentLinkedQueue<NativeSslSession> order = new ConcurrentLinkedQueue<NativeSslSession>();

        ChmQueue(OpenSslEngineMap engines) {
            super(engines);
        }

        @Override
        NativeSslSession lookup(OpenSslSessionId id) {
            return map.get(id);
        }

        @Override
        void insert(NativeSslSession session) {
            NativeSslSession old = map.put(session.sessionId(), session);
            if (old != null) {
                old.retire();
            }
            order.add(session);
            int max = getSessionCacheSize();
            while (map.size() > max) {
                NativeSslSession eldest = order.poll();
                if (eldest == null) {
                    break;
                }
                unlinkAndRetire(eldest);
            }
        }

        @Override
        boolean unlink(NativeSslSession session) {
            return map.remove(session.sessionId(), session);
        }

        @Override
        void expunge(long now) {
            for (;;) {
                NativeSslSession eldest = order.peek();
                if (eldest == null || eldest.isValid(now)) {
                    return;
                }
                if (order.remove(eldest)) {
                    unlinkAndRetire(eldest);
                }
            }
        }

        @Override
        void collect(List<NativeSslSession> out) {
            out.addAll(map.values());
        }

        @Override
        void resize(int maxSize) {
            // NOOP
        }

        @Override
        void clear() {
            super.clear();
            order.clear();
        }
    }

    /** ConcurrentHashMap for lookups + a ring of slots; a new session overwrites (evicts) the oldest slot. */
    static final class ChmRing extends LockFreeOpenSslSessionCache {
        private static final class Ring {
            final AtomicReferenceArray<NativeSslSession> slots;
            final AtomicLong head = new AtomicLong();
            final AtomicLong tail = new AtomicLong();

            Ring(int capacity) {
                slots = new AtomicReferenceArray<NativeSslSession>(capacity);
            }
        }

        private final ConcurrentHashMap<OpenSslSessionId, NativeSslSession> map =
                new ConcurrentHashMap<OpenSslSessionId, NativeSslSession>();
        private volatile Ring ring;

        ChmRing(OpenSslEngineMap engines) {
            super(engines);
            ring = new Ring(Math.max(1, getSessionCacheSize()));
        }

        @Override
        NativeSslSession lookup(OpenSslSessionId id) {
            return map.get(id);
        }

        @Override
        void insert(NativeSslSession session) {
            Ring r = ring;
            NativeSslSession old = map.put(session.sessionId(), session);
            if (old != null) {
                old.retire();
            }
            int idx = (int) (r.head.getAndIncrement() % r.slots.length());
            NativeSslSession evicted = r.slots.getAndSet(idx, session);
            if (evicted != null) {
                unlinkAndRetire(evicted);
            }
            if (r != ring) {
                unlinkAndRetire(session);
            }
        }

        @Override
        boolean unlink(NativeSslSession session) {
            return map.remove(session.sessionId(), session);
        }

        @Override
        void expunge(long now) {
            Ring r = ring;
            int capacity = r.slots.length();
            for (;;) {
                long head = r.head.get();
                long tail = r.tail.get();
                long from = Math.max(tail, head - capacity);
                if (from >= head) {
                    return;
                }
                int idx = (int) (from % capacity);
                NativeSslSession eldest = r.slots.get(idx);
                if (eldest != null && eldest.isValid(now)) {
                    return;
                }
                if (r.tail.compareAndSet(tail, from + 1) && eldest != null && r.slots.compareAndSet(idx, eldest, null)) {
                    unlinkAndRetire(eldest);
                }
            }
        }

        @Override
        void collect(List<NativeSslSession> out) {
            out.addAll(map.values());
        }

        @Override
        void resize(int maxSize) {
            Ring old = ring;
            if (old == null || old.slots.length() == Math.max(1, maxSize)) {
                return;
            }
            ring = new Ring(Math.max(1, maxSize));
            for (int i = 0; i < old.slots.length(); i++) {
                NativeSslSession session = old.slots.getAndSet(i, null);
                if (session != null) {
                    unlinkAndRetire(session);
                }
            }
        }
    }

    /**
     * No map at all: a flat array split in buckets of {@link #WAYS} slots. The session id picks the bucket,
     * every operation is a scan of that bucket and a CAS. A full bucket evicts its oldest session.
     */
    static final class AssocTable extends LockFreeOpenSslSessionCache {
        private static final int WAYS = 8;
        private volatile AtomicReferenceArray<NativeSslSession> table;
        private final AtomicBoolean sweeping = new AtomicBoolean();

        AssocTable(OpenSslEngineMap engines) {
            super(engines);
            table = newTable(getSessionCacheSize());
        }

        private static AtomicReferenceArray<NativeSslSession> newTable(int maxSize) {
            int buckets = Math.max(1, (maxSize + WAYS - 1) / WAYS);
            return new AtomicReferenceArray<NativeSslSession>(buckets * WAYS);
        }

        private static int bucketStart(AtomicReferenceArray<NativeSslSession> t, OpenSslSessionId id) {
            int buckets = t.length() / WAYS;
            int h = id.hashCode() * 0x9E3779B9;
            return (int) (((h & 0xFFFFFFFFL) * buckets) >>> 32) * WAYS;
        }

        @Override
        NativeSslSession lookup(OpenSslSessionId id) {
            AtomicReferenceArray<NativeSslSession> t = table;
            int start = bucketStart(t, id);
            for (int i = start; i < start + WAYS; i++) {
                NativeSslSession s = t.get(i);
                if (s != null && s.sessionId().equals(id)) {
                    return s;
                }
            }
            return null;
        }

        @Override
        void insert(NativeSslSession session) {
            AtomicReferenceArray<NativeSslSession> t = table;
            OpenSslSessionId id = session.sessionId();
            int start = bucketStart(t, id);
            long now = System.currentTimeMillis();
            for (;;) {
                int same = -1;
                int empty = -1;
                int oldest = -1;
                long oldestTime = Long.MAX_VALUE;
                for (int i = start; i < start + WAYS; i++) {
                    NativeSslSession s = t.get(i);
                    if (s == null) {
                        if (empty < 0) {
                            empty = i;
                        }
                    } else if (s.sessionId().equals(id)) {
                        same = i;
                        break;
                    } else {
                        long time = s.isValid(now) ? s.getCreationTime() : Long.MIN_VALUE;
                        if (time < oldestTime) {
                            oldestTime = time;
                            oldest = i;
                        }
                    }
                }
                int target = same >= 0 ? same : empty >= 0 ? empty : oldest;
                NativeSslSession victim = target == empty ? null : t.get(target);
                if (victim == null && target != empty) {
                    continue;
                }
                if (t.compareAndSet(target, victim, session)) {
                    if (victim != null) {
                        victim.retire();
                    }
                    break;
                }
            }
            if (t != table) {
                unlinkAndRetire(session);
            }
        }

        @Override
        boolean unlink(NativeSslSession session) {
            AtomicReferenceArray<NativeSslSession> t = table;
            int start = bucketStart(t, session.sessionId());
            for (int i = start; i < start + WAYS; i++) {
                if (t.get(i) == session) {
                    return t.compareAndSet(i, session, null);
                }
            }
            return false;
        }

        @Override
        void expunge(long now) {
            if (!sweeping.compareAndSet(false, true)) {
                return;
            }
            try {
                AtomicReferenceArray<NativeSslSession> t = table;
                for (int i = 0; i < t.length(); i++) {
                    NativeSslSession s = t.get(i);
                    if (s != null && !s.isValid(now) && t.compareAndSet(i, s, null)) {
                        s.retire();
                    }
                }
            } finally {
                sweeping.set(false);
            }
        }

        @Override
        void collect(List<NativeSslSession> out) {
            AtomicReferenceArray<NativeSslSession> t = table;
            for (int i = 0; i < t.length(); i++) {
                NativeSslSession s = t.get(i);
                if (s != null) {
                    out.add(s);
                }
            }
        }

        @Override
        void resize(int maxSize) {
            AtomicReferenceArray<NativeSslSession> old = table;
            if (old == null) {
                return;
            }
            AtomicReferenceArray<NativeSslSession> t = newTable(maxSize);
            if (t.length() == old.length()) {
                return;
            }
            table = t;
            for (int i = 0; i < old.length(); i++) {
                NativeSslSession s = old.getAndSet(i, null);
                if (s != null) {
                    s.retire();
                }
            }
        }
    }

    /** Not lock-free, the reference point: the existing LinkedHashMap split in independently locked stripes. */
    static final class Striped extends LockFreeOpenSslSessionCache {
        private static final int STRIPES = 16;
        private final LinkedHashMap<OpenSslSessionId, NativeSslSession>[] stripes;

        @SuppressWarnings("unchecked")
        Striped(OpenSslEngineMap engines) {
            super(engines);
            stripes = new LinkedHashMap[STRIPES];
            for (int i = 0; i < STRIPES; i++) {
                stripes[i] = new LinkedHashMap<OpenSslSessionId, NativeSslSession>();
            }
        }

        private LinkedHashMap<OpenSslSessionId, NativeSslSession> stripe(OpenSslSessionId id) {
            int h = id.hashCode() * 0x9E3779B9;
            return stripes[h >>> 28];
        }

        @Override
        NativeSslSession lookup(OpenSslSessionId id) {
            LinkedHashMap<OpenSslSessionId, NativeSslSession> stripe = stripe(id);
            synchronized (stripe) {
                return stripe.get(id);
            }
        }

        @Override
        void insert(NativeSslSession session) {
            LinkedHashMap<OpenSslSessionId, NativeSslSession> stripe = stripe(session.sessionId());
            int max = Math.max(1, getSessionCacheSize() / STRIPES);
            NativeSslSession old;
            NativeSslSession eldest = null;
            synchronized (stripe) {
                old = stripe.put(session.sessionId(), session);
                if (stripe.size() > max) {
                    Iterator<Map.Entry<OpenSslSessionId, NativeSslSession>> it = stripe.entrySet().iterator();
                    eldest = it.next().getValue();
                    it.remove();
                }
            }
            if (old != null) {
                old.retire();
            }
            if (eldest != null) {
                eldest.retire();
            }
        }

        @Override
        boolean unlink(NativeSslSession session) {
            LinkedHashMap<OpenSslSessionId, NativeSslSession> stripe = stripe(session.sessionId());
            synchronized (stripe) {
                return stripe.remove(session.sessionId(), session);
            }
        }

        @Override
        void expunge(long now) {
            for (LinkedHashMap<OpenSslSessionId, NativeSslSession> stripe : stripes) {
                synchronized (stripe) {
                    Iterator<NativeSslSession> it = stripe.values().iterator();
                    while (it.hasNext()) {
                        NativeSslSession s = it.next();
                        if (s.isValid(now)) {
                            break;
                        }
                        it.remove();
                        s.retire();
                    }
                }
            }
        }

        @Override
        void collect(List<NativeSslSession> out) {
            for (LinkedHashMap<OpenSslSessionId, NativeSslSession> stripe : stripes) {
                synchronized (stripe) {
                    out.addAll(stripe.values());
                }
            }
        }

        @Override
        void resize(int maxSize) {
            // NOOP
        }
    }
}

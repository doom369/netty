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

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * EXPERIMENT: shared protocol logic of the lock-free candidates. The storage is provided by sub-classes.
 */
abstract class LockFreeOpenSslSessionCache extends OpenSslSessionCache {
    private final OpenSslEngineMap engines;
    private final AtomicInteger sessionCounter = new AtomicInteger();

    LockFreeOpenSslSessionCache(OpenSslEngineMap engines) {
        super(engines);
        this.engines = engines;
    }

    /** Returns the session stored for the id or {@code null}. */
    abstract NativeSslSession lookup(OpenSslSessionId id);

    /** Stores the session, retiring whatever it replaces or evicts. */
    abstract void insert(NativeSslSession session);

    /** Unlinks exactly this session, returns {@code true} if this call unlinked it. */
    abstract boolean unlink(NativeSslSession session);

    /** Retires sessions that timed out. */
    abstract void expunge(long now);

    abstract void collect(List<NativeSslSession> out);

    abstract void resize(int maxSize);

    final void unlinkAndRetire(NativeSslSession session) {
        if (unlink(session)) {
            session.retire();
        }
    }

    @Override
    void setSessionTimeout(int seconds) {
        super.setSessionTimeout(seconds);
    }

    @Override
    void setSessionCacheSize(int size) {
        super.setSessionCacheSize(size);
        resize(size);
    }

    @Override
    public boolean sessionCreated(long ssl, long sslSession) {
        ReferenceCountedOpenSslEngine engine = engines.get(ssl);
        if (engine == null) {
            return false;
        }
        OpenSslInternalSession openSslSession = (OpenSslInternalSession) engine.getSession();
        NativeSslSession session = new NativeSslSession(sslSession, engine.getPeerHost(), engine.getPeerPort(),
                getSessionTimeout() * 1000L, openSslSession.keyValueStorage());
        openSslSession.setSessionDetails(
                session.getCreationTime(), session.getLastAccessedTime(), session.sessionId(), session.keyValueStorage);
        if ((sessionCounter.incrementAndGet() & 0xFF) == 0) {
            expunge(System.currentTimeMillis());
        }
        if (getSessionCacheSize() == 0) {
            session.close();
            return false;
        }
        insert(session);
        return true;
    }

    @Override
    public long getSession(long ssl, byte[] sessionId) {
        NativeSslSession session = lookup(new OpenSslSessionId(sessionId));
        if (session == null) {
            return -1;
        }
        if (!session.isValid()) {
            unlinkAndRetire(session);
            return -1;
        }
        if (!session.acquire()) {
            return -1;
        }
        final boolean upRef;
        final boolean singleUse;
        final long pointer;
        try {
            upRef = session.upRef();
            singleUse = upRef && session.shouldBeSingleUse();
            pointer = session.session();
        } finally {
            session.release();
        }
        if (!upRef) {
            unlinkAndRetire(session);
            return -1;
        }
        if (singleUse) {
            unlinkAndRetire(session);
        }
        session.setLastAccessedTime(System.currentTimeMillis());
        ReferenceCountedOpenSslEngine engine = engines.get(ssl);
        if (engine != null) {
            OpenSslInternalSession sslSession = (OpenSslInternalSession) engine.getSession();
            sslSession.setSessionDetails(session.getCreationTime(),
                    session.getLastAccessedTime(), session.sessionId(), session.keyValueStorage);
        }
        return pointer;
    }

    @Override
    void removeSessionWithId(OpenSslSessionId id) {
        NativeSslSession session = lookup(id);
        if (session != null) {
            unlinkAndRetire(session);
        }
    }

    @Override
    boolean containsSessionWithId(OpenSslSessionId id) {
        return lookup(id) != null;
    }

    @Override
    OpenSslInternalSession getSession(OpenSslSessionId id) {
        NativeSslSession session = lookup(id);
        if (session != null && !session.isValid()) {
            unlinkAndRetire(session);
            return null;
        }
        return session;
    }

    @Override
    List<OpenSslSessionId> getIds() {
        List<NativeSslSession> all = new ArrayList<NativeSslSession>();
        collect(all);
        List<OpenSslSessionId> ids = new ArrayList<OpenSslSessionId>(all.size());
        for (NativeSslSession session : all) {
            if (session.isValid()) {
                ids.add(session.sessionId());
            }
        }
        return ids;
    }

    @Override
    void clear() {
        List<NativeSslSession> all = new ArrayList<NativeSslSession>();
        collect(all);
        for (NativeSslSession session : all) {
            unlinkAndRetire(session);
        }
    }
}

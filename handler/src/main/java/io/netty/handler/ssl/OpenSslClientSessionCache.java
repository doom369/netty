/*
 * Copyright 2021 The Netty Project
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

import io.netty.internal.tcnative.SSL;
import io.netty.util.AsciiString;

import java.util.Arrays;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * {@link OpenSslSessionCache} that is used by the client-side.
 */
final class OpenSslClientSessionCache extends OpenSslSessionCache {
    // The arrays are never modified, a new one is created whenever a session is added or removed. This allows to
    // go through the sessions of a host without any synchronization. Usually the server does not provide too many
    // sessions per hostPort mapping, so these stay small.
    private final ConcurrentMap<HostPort, NativeSslSession[]> sessions =
            new ConcurrentHashMap<HostPort, NativeSslSession[]>();

    OpenSslClientSessionCache(OpenSslEngineMap engines) {
        super(engines);
    }

    @Override
    protected boolean sessionCreated(NativeSslSession session) {
        HostPort hostPort = keyFor(session.getPeerHost(), session.getPeerPort());
        if (hostPort == null) {
            return false;
        }
        for (;;) {
            NativeSslSession[] sessionsForHost = sessions.get(hostPort);
            if (sessionsForHost == null) {
                if (sessions.putIfAbsent(hostPort, new NativeSslSession[] { session }) == null) {
                    return true;
                }
            } else {
                NativeSslSession[] added = Arrays.copyOf(sessionsForHost, sessionsForHost.length + 1);
                added[sessionsForHost.length] = session;
                if (sessions.replace(hostPort, sessionsForHost, added)) {
                    return true;
                }
            }
        }
    }

    @Override
    protected void sessionRemoved(NativeSslSession session) {
        HostPort hostPort = keyFor(session.getPeerHost(), session.getPeerPort());
        if (hostPort == null) {
            return;
        }
        for (;;) {
            NativeSslSession[] sessionsForHost = sessions.get(hostPort);
            if (sessionsForHost == null) {
                return;
            }
            int idx = indexOf(sessionsForHost, session);
            if (idx < 0) {
                return;
            }
            if (sessionsForHost.length == 1) {
                if (sessions.remove(hostPort, sessionsForHost)) {
                    return;
                }
            } else {
                NativeSslSession[] removed = new NativeSslSession[sessionsForHost.length - 1];
                System.arraycopy(sessionsForHost, 0, removed, 0, idx);
                System.arraycopy(sessionsForHost, idx + 1, removed, idx, removed.length - idx);
                if (sessions.replace(hostPort, sessionsForHost, removed)) {
                    return;
                }
            }
        }
    }

    private static int indexOf(NativeSslSession[] sessions, NativeSslSession session) {
        for (int i = 0; i < sessions.length; i++) {
            if (sessions[i] == session) {
                return i;
            }
        }
        return -1;
    }

    @Override
    boolean setSession(long ssl, OpenSslInternalSession session, String host, int port) {
        HostPort hostPort = keyFor(host, port);
        if (hostPort == null) {
            return false;
        }
        NativeSslSession[] sessionsForHost = sessions.get(hostPort);
        if (sessionsForHost == null) {
            // There is no session that we can use.
            return false;
        }

        // Loop through all the sessions that might be usable and check if we can use one of these.
        for (NativeSslSession nativeSslSession : sessionsForHost) {
            if (!nativeSslSession.isValid()) {
                // Remove everything that is not valid anymore
                remove(nativeSslSession);
                continue;
            }
            // Pin the session so the underlying SSL_SESSION* can not be freed while we hand it over.
            if (!nativeSslSession.acquire()) {
                // The session was removed from the cache in the meantime.
                continue;
            }
            final boolean reused;
            boolean singleUsed = false;
            try {
                // Try to set the session, if true is returned OpenSSL incremented the reference count
                // of the underlying SSL_SESSION*.
                reused = SSL.setSession(ssl, nativeSslSession.session());
                if (reused) {
                    singleUsed = nativeSslSession.shouldBeSingleUse();
                }
            } finally {
                nativeSslSession.release();
            }

            if (reused) {
                if (singleUsed) {
                    // Should only be used once
                    nativeSslSession.invalidate();
                    session.invalidate();
                }
                nativeSslSession.setLastAccessedTime(System.currentTimeMillis());
                session.setSessionDetails(nativeSslSession.getCreationTime(), nativeSslSession.getLastAccessedTime(),
                        nativeSslSession.sessionId(), nativeSslSession.keyValueStorage);
            }
            return reused;
        }
        // Couldn't find a valid session that could be used.
        return false;
    }

    private static HostPort keyFor(String host, int port) {
        if (host == null && port < 1) {
            return null;
        }
        return new HostPort(host, port);
    }

    /**
     * Host / Port tuple used to find a {@link OpenSslInternalSession} in the cache.
     */
    private static final class HostPort {
        private final int hash;
        private final String host;
        private final int port;

        HostPort(String host, int port) {
            this.host = host;
            this.port = port;
            // Calculate a hashCode that does ignore case.
            this.hash = 31 * AsciiString.hashCode(host) + port;
        }

        @Override
        public int hashCode() {
            return hash;
        }

        @Override
        public boolean equals(Object obj) {
            if (!(obj instanceof HostPort)) {
                return false;
            }
            HostPort other = (HostPort) obj;
            return port == other.port && host.equalsIgnoreCase(other.host);
        }

        @Override
        public String toString() {
            return "HostPort{" +
                    "host='" + host + '\'' +
                    ", port=" + port +
                    '}';
        }
    }
}

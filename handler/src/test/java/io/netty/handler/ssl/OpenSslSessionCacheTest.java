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

import io.netty.buffer.UnpooledByteBufAllocator;
import io.netty.handler.ssl.util.InsecureTrustManagerFactory;
import io.netty.internal.tcnative.SSLContext;
import io.netty.internal.tcnative.SSLSession;
import io.netty.internal.tcnative.SSLSessionCache;
import io.netty.pkitesting.CertificateBuilder;
import io.netty.pkitesting.X509Bundle;
import io.netty.util.ReferenceCountUtil;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLEngineResult.HandshakeStatus;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import java.util.concurrent.Callable;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

public class OpenSslSessionCacheTest {
    private static final ByteBuffer EMPTY = ByteBuffer.allocate(0);
    private static final int SESSIONS = 32;

    private SslContext serverContext;
    private SslContext clientContext;
    private OpenSslSessionCache cache;
    private final List<Long> sessions = new ArrayList<Long>();
    private final List<OpenSslSessionId> ids = new ArrayList<OpenSslSessionId>();
    private final List<ReferenceCountedOpenSslEngine> engines = new ArrayList<ReferenceCountedOpenSslEngine>();

    @BeforeAll
    public static void checkOpenSsl() {
        OpenSsl.ensureAvailability();
        assumeTrue(OpenSsl.isSessionCacheSupported());
    }

    @BeforeEach
    public void setUp() throws Exception {
        X509Bundle cert = new CertificateBuilder()
                .subject("cn=localhost")
                .setIsCertificateAuthority(true)
                .buildSelfSigned();
        serverContext = SslContextBuilder.forServer(cert.toKeyManagerFactory())
                .sslProvider(SslProvider.OPENSSL)
                .protocols(SslProtocols.TLS_v1_2)
                .build();
        clientContext = SslContextBuilder.forClient()
                .sslProvider(SslProvider.OPENSSL)
                .protocols(SslProtocols.TLS_v1_2)
                .trustManager(InsecureTrustManagerFactory.INSTANCE)
                .build();
        ((OpenSslSessionContext) clientContext.sessionContext()).setSessionCacheEnabled(false);

        // Collect real SSL_SESSION* by doing full handshakes, we own the reference of each of them.
        ReferenceCountedOpenSslContext context = (ReferenceCountedOpenSslContext) serverContext;
        SSLContext.setSSLSessionCache(context.ctx, new SSLSessionCache() {
            @Override
            public boolean sessionCreated(long ssl, long sslSession) {
                sessions.add(sslSession);
                ids.add(new OpenSslSessionId(SSLSession.getSessionId(sslSession)));
                return true;
            }

            @Override
            public long getSession(long ssl, byte[] sessionId) {
                return -1;
            }
        });
        while (sessions.size() < SESSIONS) {
            SSLEngine clientEngine = clientContext.newEngine(UnpooledByteBufAllocator.DEFAULT);
            SSLEngine serverEngine = serverContext.newEngine(UnpooledByteBufAllocator.DEFAULT);
            try {
                handshake(clientEngine, serverEngine);
            } finally {
                ReferenceCountUtil.release(clientEngine);
                ReferenceCountUtil.release(serverEngine);
            }
        }
        cache = new OpenSslSessionCache(context.engines);
    }

    @AfterEach
    public void tearDown() {
        cache.clear();
        for (long session : sessions) {
            SSLSession.free(session);
        }
        for (ReferenceCountedOpenSslEngine engine : engines) {
            ReferenceCountUtil.release(engine);
        }
        ReferenceCountUtil.release(serverContext);
        ReferenceCountUtil.release(clientContext);
    }

    @Test
    public void storedSessionIsFound() {
        long ssl = newEngine().sslPointer();
        assertThat(store(ssl, 0)).isTrue();

        assertThat(cache.containsSessionWithId(ids.get(0))).isTrue();
        assertThat(cache.getSession(ids.get(0))).isNotNull();
        assertThat(cache.getIds()).containsExactly(ids.get(0));
        assertThat(lookup(ssl, 0)).isTrue();
        assertThat(lookup(ssl, 1)).isFalse();
    }

    @Test
    public void removedSessionIsNotFound() {
        long ssl = newEngine().sslPointer();
        store(ssl, 0);
        store(ssl, 1);

        cache.removeSessionWithId(ids.get(0));

        assertThat(lookup(ssl, 0)).isFalse();
        assertThat(lookup(ssl, 1)).isTrue();
        assertThat(cache.getIds()).containsExactly(ids.get(1));
    }

    @Test
    public void sessionsAreEvictedOnceFull() {
        cache.setSessionCacheSize(4);
        long ssl = newEngine().sslPointer();
        for (int i = 0; i < 10; i++) {
            assertThat(store(ssl, i)).isTrue();
        }

        List<OpenSslSessionId> cached = cache.getIds();
        assertThat(cached).hasSizeBetween(1, 4);
        assertThat(ids.subList(0, 10)).containsAll(cached);
        assertThat(cached).contains(ids.get(9));
        for (int i = 0; i < 10; i++) {
            assertThat(lookup(ssl, i)).isEqualTo(cached.contains(ids.get(i)));
        }
    }

    @Test
    public void storingTheSameSessionAgainKeepsOneEntry() {
        cache.setSessionCacheSize(4);
        long ssl = newEngine().sslPointer();
        for (int i = 0; i < 10; i++) {
            assertThat(store(ssl, 0)).isTrue();
        }

        assertThat(cache.getIds()).containsExactly(ids.get(0));
        assertThat(lookup(ssl, 0)).isTrue();
    }

    @Test
    public void nothingIsCachedWithSizeZero() {
        cache.setSessionCacheSize(0);
        long ssl = newEngine().sslPointer();

        store(ssl, 0);

        assertThat(cache.getIds()).isEmpty();
        assertThat(lookup(ssl, 0)).isFalse();
    }

    @Test
    public void loweringTheSizeDrainsTheCache() {
        long ssl = newEngine().sslPointer();
        store(ssl, 0);

        cache.setSessionCacheSize(8);

        assertThat(cache.getIds()).isEmpty();
        assertThat(lookup(ssl, 0)).isFalse();
    }

    @Test
    public void loweringTheTimeoutDrainsTheCache() {
        long ssl = newEngine().sslPointer();
        store(ssl, 0);

        cache.setSessionTimeout(10);

        assertThat(cache.getIds()).isEmpty();
        assertThat(lookup(ssl, 0)).isFalse();
    }

    @Test
    @Timeout(60)
    public void concurrentStoreLookupAndRemove() throws Exception {
        // Way smaller than the number of sessions, so sessions are evicted and freed all the time while other
        // threads look them up.
        cache.setSessionCacheSize(8);
        final int threads = 4;
        final CyclicBarrier start = new CyclicBarrier(threads);
        ExecutorService executor = Executors.newFixedThreadPool(threads);
        try {
            List<Future<Void>> futures = new ArrayList<Future<Void>>();
            for (int t = 0; t < threads; t++) {
                final long ssl = newEngine().sslPointer();
                final long seed = t;
                futures.add(executor.submit(new Callable<Void>() {
                    @Override
                    public Void call() throws Exception {
                        Random random = new Random(seed);
                        start.await();
                        for (int i = 0; i < 50000; i++) {
                            int session = random.nextInt(SESSIONS);
                            switch (random.nextInt(8)) {
                                case 0:
                                    cache.removeSessionWithId(ids.get(session));
                                    break;
                                case 1:
                                case 2:
                                case 3:
                                    store(ssl, session);
                                    break;
                                default:
                                    lookup(ssl, session);
                                    break;
                            }
                        }
                        return null;
                    }
                }));
            }
            for (Future<Void> future : futures) {
                future.get();
            }
        } finally {
            executor.shutdown();
            assertThat(executor.awaitTermination(30, TimeUnit.SECONDS)).isTrue();
        }

        assertThat(cache.getIds()).hasSizeLessThanOrEqualTo(8);
        cache.clear();
        assertThat(cache.getIds()).isEmpty();
    }

    private ReferenceCountedOpenSslEngine newEngine() {
        ReferenceCountedOpenSslEngine engine =
                (ReferenceCountedOpenSslEngine) serverContext.newEngine(UnpooledByteBufAllocator.DEFAULT);
        engines.add(engine);
        return engine;
    }

    /**
     * Hands the session over the same way the native code does, which gives up one reference if it is cached.
     */
    private boolean store(long ssl, int session) {
        long pointer = sessions.get(session);
        SSLSession.upRef(pointer);
        if (cache.sessionCreated(ssl, pointer)) {
            return true;
        }
        SSLSession.free(pointer);
        return false;
    }

    /**
     * Looks the session up the same way the native code does, which takes over one reference if it is found.
     */
    private boolean lookup(long ssl, int session) {
        long pointer = cache.getSession(ssl, ids.get(session).cloneBytes());
        if (pointer == -1) {
            return false;
        }
        assertThat(pointer).isEqualTo(sessions.get(session));
        SSLSession.free(pointer);
        return true;
    }

    private static void handshake(SSLEngine clientEngine, SSLEngine serverEngine) throws Exception {
        ByteBuffer cTOs = ByteBuffer.allocateDirect(clientEngine.getSession().getPacketBufferSize());
        ByteBuffer sTOc = ByteBuffer.allocateDirect(serverEngine.getSession().getPacketBufferSize());
        ByteBuffer app = ByteBuffer.allocateDirect(serverEngine.getSession().getApplicationBufferSize());
        clientEngine.beginHandshake();
        serverEngine.beginHandshake();
        boolean clientDone = false;
        boolean serverDone = false;
        while (!clientDone || !serverDone) {
            if (!clientDone) {
                clientDone = finished(clientEngine.wrap(EMPTY, cTOs), clientEngine);
            }
            if (!serverDone) {
                serverDone = finished(serverEngine.wrap(EMPTY, sTOc), serverEngine);
            }
            cTOs.flip();
            sTOc.flip();
            if (!clientDone) {
                app.clear();
                clientDone = finished(clientEngine.unwrap(sTOc, app), clientEngine);
            }
            if (!serverDone) {
                app.clear();
                serverDone = finished(serverEngine.unwrap(cTOs, app), serverEngine);
            }
            cTOs.compact();
            sTOc.compact();
        }
    }

    private static boolean finished(SSLEngineResult result, SSLEngine engine) {
        if (result.getHandshakeStatus() == HandshakeStatus.NEED_TASK) {
            Runnable task;
            while ((task = engine.getDelegatedTask()) != null) {
                task.run();
            }
        }
        return result.getHandshakeStatus() == HandshakeStatus.FINISHED;
    }
}

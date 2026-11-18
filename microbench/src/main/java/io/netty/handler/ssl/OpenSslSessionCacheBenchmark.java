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

import io.netty.buffer.ByteBufAllocator;
import io.netty.buffer.UnpooledByteBufAllocator;
import io.netty.handler.ssl.util.InsecureTrustManagerFactory;
import io.netty.handler.ssl.util.SelfSignedCertificate;
import io.netty.internal.tcnative.SSLContext;
import io.netty.internal.tcnative.SSLSession;
import io.netty.internal.tcnative.SSLSessionCache;
import io.netty.util.ReferenceCountUtil;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Level;
import org.openjdk.jmh.annotations.Measurement;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Param;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.TearDown;
import org.openjdk.jmh.annotations.Warmup;
import org.openjdk.jmh.infra.ThreadParams;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLEngineResult.HandshakeStatus;
import java.nio.ByteBuffer;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.TimeUnit;

/**
 * Drives the server-side {@link OpenSslSessionCache} callbacks directly with real {@code SSL_SESSION}s, leaving the
 * handshake crypto out, to show how the cache itself behaves when many event loops hit it at once.
 */
@State(Scope.Benchmark)
@Fork(1)
@Warmup(iterations = 3, time = 2)
@Measurement(iterations = 5, time = 2)
@BenchmarkMode(Mode.Throughput)
@OutputTimeUnit(TimeUnit.MICROSECONDS)
public class OpenSslSessionCacheBenchmark {
    private static final ByteBuffer EMPTY = ByteBuffer.allocate(0);
    private static final int POOL = 32768;
    private static final int CACHE_SIZE = 20480;
    private static final int PREFILL = 16384;

    @Param({ "LOCKED", "STRIPED_LOCK", "CHM_QUEUE", "CHM_RING", "ASSOC_TABLE" })
    public String impl;

    private final ByteBufAllocator allocator = UnpooledByteBufAllocator.DEFAULT;
    private SelfSignedCertificate cert;
    private SslContext serverContext;
    private SslContext clientContext;
    private OpenSslSessionCache cache;
    private long[] sessions;
    private byte[][] ids;

    @Setup(Level.Trial)
    public void setup() throws Exception {
        cert = new SelfSignedCertificate("localhost", "EC", 256);
        serverContext = SslContextBuilder.forServer(cert.key(), cert.cert())
                .sslProvider(SslProvider.OPENSSL_REFCNT)
                .protocols("TLSv1.2")
                .build();
        clientContext = SslContextBuilder.forClient()
                .sslProvider(SslProvider.OPENSSL_REFCNT)
                .protocols("TLSv1.2")
                .trustManager(InsecureTrustManagerFactory.INSTANCE)
                .build();
        ((OpenSslSessionContext) clientContext.sessionContext()).setSessionCacheEnabled(false);
        ReferenceCountedOpenSslContext context = (ReferenceCountedOpenSslContext) serverContext;

        sessions = new long[POOL];
        ids = new byte[POOL][];
        final int[] harvested = new int[1];
        SSLContext.setSSLSessionCache(context.ctx, new SSLSessionCache() {
            @Override
            public boolean sessionCreated(long ssl, long sslSession) {
                sessions[harvested[0]] = sslSession;
                ids[harvested[0]++] = SSLSession.getSessionId(sslSession);
                return true;
            }

            @Override
            public long getSession(long ssl, byte[] sessionId) {
                return -1;
            }
        });
        ByteBuffer cTOs = ByteBuffer.allocateDirect(1 << 15);
        ByteBuffer sTOc = ByteBuffer.allocateDirect(1 << 15);
        ByteBuffer app = ByteBuffer.allocateDirect(1 << 15);
        while (harvested[0] < POOL) {
            SSLEngine clientEngine = clientContext.newEngine(allocator);
            SSLEngine serverEngine = serverContext.newEngine(allocator);
            handshake(clientEngine, serverEngine, cTOs, sTOc, app);
            ReferenceCountUtil.release(clientEngine);
            ReferenceCountUtil.release(serverEngine);
        }

        cache = SessionCacheCandidates.create(impl, context.engines);
        cache.setSessionCacheSize(CACHE_SIZE);
        ReferenceCountedOpenSslEngine engine = (ReferenceCountedOpenSslEngine) serverContext.newEngine(allocator);
        for (int i = 0; i < PREFILL; i++) {
            SSLSession.upRef(sessions[i]);
            cache.sessionCreated(engine.sslPointer(), sessions[i]);
        }
        int hits = 0;
        for (int i = 0; i < PREFILL; i++) {
            long session = cache.getSession(engine.sslPointer(), ids[i]);
            if (session != -1) {
                hits++;
                SSLSession.free(session);
            }
        }
        ReferenceCountUtil.release(engine);
        System.out.println("prefilled " + PREFILL + ", retained " + hits);
    }

    @TearDown(Level.Trial)
    public void tearDown() {
        cache.clear();
        for (long session : sessions) {
            SSLSession.free(session);
        }
        ReferenceCountUtil.release(serverContext);
        ReferenceCountUtil.release(clientContext);
        cert.delete();
    }

    @State(Scope.Thread)
    public static class EventLoop {
        ReferenceCountedOpenSslEngine engine;
        long ssl;
        int from;
        int length;
        int next;

        @Setup(Level.Trial)
        public void setup(OpenSslSessionCacheBenchmark benchmark, ThreadParams params) {
            engine = (ReferenceCountedOpenSslEngine) benchmark.serverContext.newEngine(benchmark.allocator);
            ssl = engine.sslPointer();
            length = POOL / params.getThreadCount();
            from = length * params.getThreadIndex();
        }

        @TearDown(Level.Trial)
        public void tearDown() {
            ReferenceCountUtil.release(engine);
        }
    }

    /** Resumption storm: every handshake looks a session up. */
    @Benchmark
    public long lookup(EventLoop loop) {
        return lookup(loop, PREFILL);
    }

    /** Full handshake storm: every handshake stores a new session and evicts an old one. */
    @Benchmark
    public boolean store(EventLoop loop) {
        long session = sessions[loop.from + loop.next++ % loop.length];
        SSLSession.upRef(session);
        if (cache.sessionCreated(loop.ssl, session)) {
            return true;
        }
        SSLSession.free(session);
        return false;
    }

    /** Reconnect storm: 4 of 5 handshakes try to resume, 1 of 5 stores a new session. */
    @Benchmark
    public long mixed(EventLoop loop) {
        if (loop.next % 5 == 0) {
            return store(loop) ? 1 : 0;
        }
        loop.next++;
        return lookup(loop, POOL);
    }

    private long lookup(EventLoop loop, int bound) {
        long session = cache.getSession(loop.ssl, ids[ThreadLocalRandom.current().nextInt(bound)]);
        if (session != -1) {
            SSLSession.free(session);
        }
        return session;
    }

    private static void handshake(SSLEngine clientEngine, SSLEngine serverEngine,
                                  ByteBuffer cTOs, ByteBuffer sTOc, ByteBuffer app) throws Exception {
        cTOs.clear();
        sTOc.clear();
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

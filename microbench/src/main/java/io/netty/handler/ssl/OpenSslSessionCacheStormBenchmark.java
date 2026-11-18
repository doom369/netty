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
import io.netty.util.ReferenceCountUtil;
import org.openjdk.jmh.annotations.AuxCounters;
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
import java.util.concurrent.TimeUnit;

/**
 * A TLS 1.2 connection storm against one server {@link SslContext}: every benchmark thread plays a set of clients
 * that connect, handshake and disconnect in a loop. Session tickets are off (the default), so every handshake goes
 * through the server-side {@link OpenSslSessionCache}:
 * <ul>
 *   <li>{@code FULL}: clients never resume, every handshake stores a new session (and evicts once full).</li>
 *   <li>{@code RESUME}: clients reconnect with their session id, every handshake is a cache lookup.</li>
 * </ul>
 */
@State(Scope.Benchmark)
@Fork(1)
@Warmup(iterations = 3, time = 3)
@Measurement(iterations = 5, time = 3)
@BenchmarkMode(Mode.Throughput)
@OutputTimeUnit(TimeUnit.SECONDS)
public class OpenSslSessionCacheStormBenchmark {
    private static final ByteBuffer EMPTY = ByteBuffer.allocate(0);
    private static final int CLIENTS_PER_THREAD = 1024;

    @Param({ "FULL", "RESUME" })
    public String mode;

    private final ByteBufAllocator allocator = UnpooledByteBufAllocator.DEFAULT;
    private SelfSignedCertificate cert;
    private SslContext serverContext;

    @Setup(Level.Trial)
    public void setup() throws Exception {
        cert = new SelfSignedCertificate("localhost", "EC", 256);
        serverContext = SslContextBuilder.forServer(cert.key(), cert.cert())
                .sslProvider(SslProvider.OPENSSL_REFCNT)
                .protocols("TLSv1.2")
                .build();
    }

    @TearDown(Level.Trial)
    public void tearDown() {
        ReferenceCountUtil.release(serverContext);
        cert.delete();
    }

    @State(Scope.Thread)
    @AuxCounters(AuxCounters.Type.EVENTS)
    public static class Client {
        SslContext clientContext;
        ByteBuffer clientToServer;
        ByteBuffer serverToClient;
        ByteBuffer app;
        int port;
        int next;
        public long resumed;

        @Setup(Level.Trial)
        public void setup(OpenSslSessionCacheStormBenchmark benchmark, ThreadParams params) throws Exception {
            clientContext = SslContextBuilder.forClient()
                    .sslProvider(SslProvider.OPENSSL_REFCNT)
                    .protocols("TLSv1.2")
                    .trustManager(InsecureTrustManagerFactory.INSTANCE)
                    .build();
            ((OpenSslSessionContext) clientContext.sessionContext())
                    .setSessionCacheEnabled("RESUME".equals(benchmark.mode));
            port = 10000 + params.getThreadIndex();
            clientToServer = ByteBuffer.allocateDirect(1 << 15);
            serverToClient = ByteBuffer.allocateDirect(1 << 15);
            app = ByteBuffer.allocateDirect(1 << 15);
        }

        @TearDown(Level.Trial)
        public void tearDown() {
            ReferenceCountUtil.release(clientContext);
        }
    }

    @Benchmark
    public boolean handshake(Client client) throws Exception {
        String host = "client-" + (client.next++ & CLIENTS_PER_THREAD - 1);
        ReferenceCountedOpenSslEngine clientEngine =
                (ReferenceCountedOpenSslEngine) client.clientContext.newEngine(allocator, host, client.port);
        SSLEngine serverEngine = serverContext.newEngine(allocator);
        try {
            handshake(clientEngine, serverEngine, client);
            boolean reused = clientEngine.isSessionReused();
            if (reused) {
                client.resumed++;
            }
            return reused;
        } finally {
            ReferenceCountUtil.release(clientEngine);
            ReferenceCountUtil.release(serverEngine);
        }
    }

    private static void handshake(SSLEngine clientEngine, SSLEngine serverEngine, Client client) throws Exception {
        ByteBuffer cTOs = client.clientToServer;
        ByteBuffer sTOc = client.serverToClient;
        ByteBuffer app = client.app;
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

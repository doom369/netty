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
package io.netty.microbench.handler.ssl;

import io.netty.buffer.ByteBuf;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.Param;

/**
 * Benchmarks the common "one {@code writeAndFlush(...)} per message" pattern: the client {@link
 * io.netty.handler.ssl.SslHandler} writes and flushes {@code numMessages} small messages (each flush produces its own
 * TLS record, and so its own {@code SSLEngine.wrap(...)} call), and the server {@link io.netty.handler.ssl.SslHandler}
 * then receives all of them in a single {@code channelRead(...)}.
 * <p>
 * Run with {@code -prof gc} to see the allocation rate per operation.
 */
public class SslHandlerWriteAndFlushBenchmark extends AbstractSslHandlerThroughputBenchmark {
    @Param({ "1", "5", "10" })
    public int numMessages;

    @Benchmark
    public ByteBuf writeAndFlushThenRead() throws Exception {
        clientCtx.releaseCumulation();

        for (int i = 0; i < numMessages; ++i) {
            clientSslHandler.write(clientCtx, wrapSrcBuffer.retainedSlice(), clientCtx.voidPromise());
            clientSslHandler.flush(clientCtx);
        }
        ByteBuf src = clientCtx.cumulation().retainedSlice();

        do {
            serverSslHandler.channelRead(serverCtx, src);
        } while (src.isReadable());

        assert !src.isReadable() && src.refCnt() == 1 : "src: " + src + " src.refCnt(): " + src.refCnt();

        return src;
    }
}

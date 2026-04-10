/*
 * Copyright 2024 The Netty Project
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

package io.netty.microbench.channel;

import io.netty.channel.DefaultChannelId;
import io.netty.microbench.util.AbstractMicrobenchmark;
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
import org.openjdk.jmh.annotations.Warmup;

import java.util.Arrays;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

@State(Scope.Benchmark)
@BenchmarkMode(Mode.Throughput)
@OutputTimeUnit(TimeUnit.MILLISECONDS)
@Fork(2)
@Warmup(iterations = 5, time = 1)
@Measurement(iterations = 8, time = 1)
public class DefaultChannelIdBenchmark extends AbstractMicrobenchmark {

    @Param({ "false", "true" })
    private boolean noUnsafe;

    private DefaultChannelId channelId1;
    private DefaultChannelId channelId2;
    private OldDefaultChannelId oldChannelId1;
    private OldDefaultChannelId oldChannelId2;

    @Setup(Level.Trial)
    public void setup() {
        System.setProperty("io.netty.noUnsafe", Boolean.valueOf(noUnsafe).toString());
        channelId1 = DefaultChannelId.newInstance();
        channelId2 = DefaultChannelId.newInstance();
        oldChannelId1 = OldDefaultChannelId.newInstance();
        oldChannelId2 = OldDefaultChannelId.newInstance();
    }

    @Benchmark
    public DefaultChannelId newInstance() {
        return DefaultChannelId.newInstance();
    }

    @Benchmark
    public OldDefaultChannelId oldNewInstance() {
        return OldDefaultChannelId.newInstance();
    }

    @Benchmark
    public boolean equalsDifferent() {
        return channelId1.equals(channelId2);
    }

    @Benchmark
    public boolean oldEqualsDifferent() {
        return oldChannelId1.equals(oldChannelId2);
    }

    @Benchmark
    public int hashCodeBenchmark() {
        return channelId1.hashCode();
    }

    @Benchmark
    public int oldHashCodeBenchmark() {
        return oldChannelId1.hashCode();
    }

    /**
     * Old byte[]-based DefaultChannelId implementation for comparison.
     */
    static final class OldDefaultChannelId {

        private static final byte[] MACHINE_ID = new byte[8];
        private static final int PROCESS_ID = ThreadLocalRandom.current().nextInt();
        private static final AtomicInteger nextSequence = new AtomicInteger();

        static OldDefaultChannelId newInstance() {
            return new OldDefaultChannelId(MACHINE_ID,
                    PROCESS_ID,
                    nextSequence.getAndIncrement(),
                    Long.reverse(System.nanoTime()) ^ System.currentTimeMillis(),
                    ThreadLocalRandom.current().nextInt());
        }

        private final byte[] data;
        private final int hashCode;

        OldDefaultChannelId(final byte[] machineId, final int processId, final int sequence,
                            final long timestamp, final int random) {
            final byte[] data = new byte[machineId.length + 4 + 4 + 8 + 4];
            int i = 0;

            System.arraycopy(machineId, 0, data, i, machineId.length);
            i += machineId.length;

            data[i]     = (byte) (processId >>> 24);
            data[i + 1] = (byte) (processId >>> 16);
            data[i + 2] = (byte) (processId >>> 8);
            data[i + 3] = (byte) processId;
            i += 4;

            data[i]     = (byte) (sequence >>> 24);
            data[i + 1] = (byte) (sequence >>> 16);
            data[i + 2] = (byte) (sequence >>> 8);
            data[i + 3] = (byte) sequence;
            i += 4;

            data[i]     = (byte) (timestamp >>> 56);
            data[i + 1] = (byte) (timestamp >>> 48);
            data[i + 2] = (byte) (timestamp >>> 40);
            data[i + 3] = (byte) (timestamp >>> 32);
            data[i + 4] = (byte) (timestamp >>> 24);
            data[i + 5] = (byte) (timestamp >>> 16);
            data[i + 6] = (byte) (timestamp >>> 8);
            data[i + 7] = (byte) timestamp;
            i += 8;

            data[i]     = (byte) (random >>> 24);
            data[i + 1] = (byte) (random >>> 16);
            data[i + 2] = (byte) (random >>> 8);
            data[i + 3] = (byte) random;

            this.data = data;
            hashCode = Arrays.hashCode(data);
        }

        @Override
        public int hashCode() {
            return hashCode;
        }

        @Override
        public boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            if (!(obj instanceof OldDefaultChannelId)) {
                return false;
            }
            OldDefaultChannelId other = (OldDefaultChannelId) obj;
            return hashCode == other.hashCode && Arrays.equals(data, other.data);
        }
    }

}

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

import io.netty.handler.ssl.ZlibCertificateCompressionAlgorithm;
import io.netty.handler.ssl.util.SelfSignedCertificate;
import io.netty.microbench.util.AbstractMicrobenchmark;
import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Param;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;

import java.util.concurrent.TimeUnit;

/**
 * Measures compressing the same certificate over and over, as a server does on every TLS 1.3 handshake with a
 * client that negotiated certificate compression.
 */
@State(Scope.Benchmark)
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.NANOSECONDS)
public class ZlibCertificateCompressionBenchmark extends AbstractMicrobenchmark {

    @Param({ "RSA", "EC" })
    public String algorithm;

    private byte[] certificate;

    @Setup
    public void setup() throws Exception {
        SelfSignedCertificate selfSigned = new SelfSignedCertificate("localhost", algorithm,
                "RSA".equals(algorithm) ? 2048 : 256);
        try {
            certificate = selfSigned.cert().getEncoded();
        } finally {
            selfSigned.delete();
        }
    }

    @Benchmark
    public byte[] compress() {
        return ZlibCertificateCompressionAlgorithm.INSTANCE.compress(null, certificate);
    }
}

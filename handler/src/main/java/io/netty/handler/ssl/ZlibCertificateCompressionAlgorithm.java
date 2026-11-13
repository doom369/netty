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

import java.io.ByteArrayOutputStream;
import java.util.Arrays;
import java.util.zip.DataFormatException;
import java.util.zip.Deflater;
import java.util.zip.Inflater;
import javax.net.ssl.SSLEngine;

/**
 * The zlib certificate compression algorithm (ID 1) as defined by
 * <a href="https://datatracker.ietf.org/doc/html/rfc8879">RFC 8879</a>.
 * <p>
 * This is the default algorithm used by {@link OpenSslCertificateCompressionConfig}. Use it to keep zlib when
 * supplying a custom configuration. The singleton is thread-safe.
 */
public final class ZlibCertificateCompressionAlgorithm implements OpenSslCertificateCompressionAlgorithm {
    /**
     * The shared instance.
     */
    public static final ZlibCertificateCompressionAlgorithm INSTANCE = new ZlibCertificateCompressionAlgorithm();

    // The zlib algorithm identifier assigned by RFC 8879.
    private static final int ALGORITHM_ID = 1;
    private static final int BUFFER_SIZE = 8192;
    private static final int MAX_UNCOMPRESSED_CERTIFICATE_LENGTH = 0xFFFFFF;

    // The same certificate message is sent on every handshake that uses the same certificate chain, and deflating
    // is deterministic, so the result is remembered. Only the certificates of this side are ever compressed, so a
    // handful of entries is the common case and a linear scan over an immutable array is cheaper than hashing the
    // whole message. Both limits bound the memory the cache can retain: once it is full the oldest entry is replaced.
    private static final int MAX_CACHED_CERTIFICATES = 16;
    private static final int MAX_CACHED_CERTIFICATE_LENGTH = 32 * 1024;

    // Copy-on-write: the array is never modified after it was published.
    private volatile CachedCertificate[] cache = new CachedCertificate[0];
    // Guarded by synchronized (this).
    private int nextReplaced;

    private ZlibCertificateCompressionAlgorithm() { }

    @Override
    public byte[] compress(SSLEngine engine, byte[] uncompressedCertificate) {
        for (CachedCertificate cached : cache) {
            if (Arrays.equals(cached.uncompressed, uncompressedCertificate)) {
                return cached.compressed.clone();
            }
        }
        byte[] compressed = deflate(uncompressedCertificate);
        if (uncompressedCertificate.length <= MAX_CACHED_CERTIFICATE_LENGTH) {
            add(new CachedCertificate(uncompressedCertificate.clone(), compressed.clone()));
        }
        return compressed;
    }

    private synchronized void add(CachedCertificate certificate) {
        CachedCertificate[] current = cache;
        for (CachedCertificate cached : current) {
            if (Arrays.equals(cached.uncompressed, certificate.uncompressed)) {
                // Another thread compressed the same certificate concurrently.
                return;
            }
        }
        CachedCertificate[] updated;
        if (current.length < MAX_CACHED_CERTIFICATES) {
            updated = Arrays.copyOf(current, current.length + 1);
            updated[current.length] = certificate;
        } else {
            updated = current.clone();
            updated[nextReplaced] = certificate;
            nextReplaced = (nextReplaced + 1) % MAX_CACHED_CERTIFICATES;
        }
        cache = updated;
    }

    private static byte[] deflate(byte[] uncompressedCertificate) {
        Deflater deflater = new Deflater();
        try {
            deflater.setInput(uncompressedCertificate);
            deflater.finish();
            ByteArrayOutputStream output = new ByteArrayOutputStream(uncompressedCertificate.length);
            byte[] buffer = new byte[BUFFER_SIZE];
            while (!deflater.finished()) {
                int length = deflater.deflate(buffer);
                output.write(buffer, 0, length);
            }
            return output.toByteArray();
        } finally {
            deflater.end();
        }
    }

    @Override
    public byte[] decompress(SSLEngine engine, int uncompressedLen, byte[] compressedCertificate)
            throws DataFormatException {
        if (uncompressedLen < 0 || uncompressedLen > MAX_UNCOMPRESSED_CERTIFICATE_LENGTH) {
            throw new DataFormatException("uncompressed length must be between 0 and " +
                    MAX_UNCOMPRESSED_CERTIFICATE_LENGTH);
        }

        Inflater inflater = new Inflater();
        try {
            inflater.setInput(compressedCertificate);
            byte[] output = new byte[uncompressedLen];
            int offset = 0;
            while (!inflater.finished() && offset < output.length) {
                int length = inflater.inflate(output, offset, output.length - offset);
                if (length == 0) {
                    break;
                }
                offset += length;
            }
            if (!inflater.finished() || offset != uncompressedLen || inflater.getRemaining() != 0) {
                throw new DataFormatException("decompressed certificate length does not match uncompressed length");
            }
            return output;
        } finally {
            inflater.end();
        }
    }

    @Override
    public int algorithmId() {
        return ALGORITHM_ID;
    }

    private static final class CachedCertificate {
        final byte[] uncompressed;
        final byte[] compressed;

        CachedCertificate(byte[] uncompressed, byte[] compressed) {
            this.uncompressed = uncompressed;
            this.compressed = compressed;
        }
    }
}

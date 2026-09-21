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

import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLEngineResult.HandshakeStatus;
import javax.net.ssl.SSLEngineResult.Status;

/**
 * A mutable, reusable equivalent of {@link SSLEngineResult}.
 * <p>
 * {@link SSLEngineResult} is immutable and so a new instance has to be allocated on every
 * {@link javax.net.ssl.SSLEngine#wrap} / {@link javax.net.ssl.SSLEngine#unwrap} call. {@link SslHandler} performs
 * one such call per TLS record it sends and (at least) one per read it receives, which makes {@link SSLEngineResult}
 * one of the top allocation sources of a TLS heavy application. This class allows netty's own
 * {@link ReferenceCountedOpenSslEngine} to report the result of a {@code wrap} / {@code unwrap} operation to
 * {@link SslHandler} without any allocation.
 * <p>
 * Instances are <strong>not</strong> thread-safe and their content is only valid until the next {@code wrap} /
 * {@code unwrap} call that writes into the same instance. Callers must copy the fields they are interested in before
 * calling into anything that may trigger another {@code wrap} / {@code unwrap} (for example the
 * {@link io.netty.channel.ChannelPipeline}).
 */
final class MutableSslEngineResult {

    private static final Status[] STATUSES = Status.values();
    private static final HandshakeStatus[] HANDSHAKE_STATUSES = HandshakeStatus.values();

    /**
     * Cached {@link SSLEngineResult}s for all combinations of {@link Status} and {@link HandshakeStatus} where
     * nothing was consumed and nothing was produced. These are very common (for example during the handshake) and
     * are shared to avoid allocations when converting to a {@link SSLEngineResult}.
     * <p>
     * Indexed by {@link #emptyResultIndex(Status, HandshakeStatus)}.
     */
    private static final SSLEngineResult[] EMPTY_RESULTS =
            new SSLEngineResult[STATUSES.length * HANDSHAKE_STATUSES.length];

    static {
        for (Status status : STATUSES) {
            for (HandshakeStatus handshakeStatus : HANDSHAKE_STATUSES) {
                EMPTY_RESULTS[emptyResultIndex(status, handshakeStatus)] =
                        new SSLEngineResult(status, handshakeStatus, 0, 0);
            }
        }
    }

    private static int emptyResultIndex(Status status, HandshakeStatus handshakeStatus) {
        return status.ordinal() * HANDSHAKE_STATUSES.length + handshakeStatus.ordinal();
    }

    private Status status = Status.OK;
    private HandshakeStatus handshakeStatus = HandshakeStatus.NOT_HANDSHAKING;
    private int bytesConsumed;
    private int bytesProduced;

    /**
     * Set all fields and return {@code this}.
     */
    MutableSslEngineResult set(Status status, HandshakeStatus handshakeStatus, int bytesConsumed, int bytesProduced) {
        this.status = status;
        this.handshakeStatus = handshakeStatus;
        this.bytesConsumed = bytesConsumed;
        this.bytesProduced = bytesProduced;
        return this;
    }

    /**
     * Copy all fields of the given {@link MutableSslEngineResult} and return {@code this}.
     */
    MutableSslEngineResult set(MutableSslEngineResult result) {
        return set(result.status, result.handshakeStatus, result.bytesConsumed, result.bytesProduced);
    }

    /**
     * Copy all fields of the given {@link SSLEngineResult} and return {@code this}.
     */
    MutableSslEngineResult set(SSLEngineResult result) {
        return set(result.getStatus(), result.getHandshakeStatus(), result.bytesConsumed(), result.bytesProduced());
    }

    /**
     * See {@link SSLEngineResult#getStatus()}.
     */
    Status status() {
        return status;
    }

    /**
     * See {@link SSLEngineResult#getHandshakeStatus()}.
     */
    HandshakeStatus handshakeStatus() {
        return handshakeStatus;
    }

    /**
     * See {@link SSLEngineResult#bytesConsumed()}.
     */
    int bytesConsumed() {
        return bytesConsumed;
    }

    /**
     * See {@link SSLEngineResult#bytesProduced()}.
     */
    int bytesProduced() {
        return bytesProduced;
    }

    /**
     * Convert to an (immutable) {@link SSLEngineResult}. This only allocates if something was consumed or produced.
     */
    SSLEngineResult toSSLEngineResult() {
        if (bytesConsumed == 0 && bytesProduced == 0) {
            return EMPTY_RESULTS[emptyResultIndex(status, handshakeStatus)];
        }
        return new SSLEngineResult(status, handshakeStatus, bytesConsumed, bytesProduced);
    }

    @Override
    public String toString() {
        return "MutableSslEngineResult[status=" + status + ", handshakeStatus=" + handshakeStatus +
                ", bytesConsumed=" + bytesConsumed + ", bytesProduced=" + bytesProduced + ']';
    }
}

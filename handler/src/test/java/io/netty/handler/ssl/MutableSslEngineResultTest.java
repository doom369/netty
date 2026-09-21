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

import org.junit.jupiter.api.Test;

import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLEngineResult.HandshakeStatus;
import javax.net.ssl.SSLEngineResult.Status;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertSame;

public class MutableSslEngineResultTest {

    @Test
    public void testSetAndGet() {
        MutableSslEngineResult result = new MutableSslEngineResult();
        assertSame(result, result.set(Status.BUFFER_OVERFLOW, HandshakeStatus.NEED_WRAP, 1, 2));
        assertEquals(Status.BUFFER_OVERFLOW, result.status());
        assertEquals(HandshakeStatus.NEED_WRAP, result.handshakeStatus());
        assertEquals(1, result.bytesConsumed());
        assertEquals(2, result.bytesProduced());
    }

    @Test
    public void testSetFromSSLEngineResult() {
        MutableSslEngineResult result = new MutableSslEngineResult();
        assertSame(result, result.set(new SSLEngineResult(Status.CLOSED, HandshakeStatus.NEED_UNWRAP, 3, 4)));
        assertEquals(Status.CLOSED, result.status());
        assertEquals(HandshakeStatus.NEED_UNWRAP, result.handshakeStatus());
        assertEquals(3, result.bytesConsumed());
        assertEquals(4, result.bytesProduced());
    }

    @Test
    public void testSetFromMutableSslEngineResult() {
        MutableSslEngineResult source = new MutableSslEngineResult()
                .set(Status.BUFFER_UNDERFLOW, HandshakeStatus.NEED_TASK, 5, 6);
        MutableSslEngineResult result = new MutableSslEngineResult();
        assertSame(result, result.set(source));
        assertEquals(Status.BUFFER_UNDERFLOW, result.status());
        assertEquals(HandshakeStatus.NEED_TASK, result.handshakeStatus());
        assertEquals(5, result.bytesConsumed());
        assertEquals(6, result.bytesProduced());

        // Must be a copy and not share state.
        source.set(Status.OK, HandshakeStatus.FINISHED, 0, 0);
        assertEquals(Status.BUFFER_UNDERFLOW, result.status());
        assertEquals(HandshakeStatus.NEED_TASK, result.handshakeStatus());
    }

    @Test
    public void testToSSLEngineResult() {
        MutableSslEngineResult result = new MutableSslEngineResult();
        for (Status status : Status.values()) {
            for (HandshakeStatus handshakeStatus : HandshakeStatus.values()) {
                SSLEngineResult converted = result.set(status, handshakeStatus, 7, 8).toSSLEngineResult();
                assertEquals(status, converted.getStatus());
                assertEquals(handshakeStatus, converted.getHandshakeStatus());
                assertEquals(7, converted.bytesConsumed());
                assertEquals(8, converted.bytesProduced());
                assertNotSame(converted, result.set(status, handshakeStatus, 7, 8).toSSLEngineResult());

                // Results that did not consume or produce anything are cached.
                SSLEngineResult empty = result.set(status, handshakeStatus, 0, 0).toSSLEngineResult();
                assertEquals(status, empty.getStatus());
                assertEquals(handshakeStatus, empty.getHandshakeStatus());
                assertEquals(0, empty.bytesConsumed());
                assertEquals(0, empty.bytesProduced());
                assertSame(empty, result.set(status, handshakeStatus, 0, 0).toSSLEngineResult());
            }
        }
    }
}

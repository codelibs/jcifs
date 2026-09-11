/*
 * © 2026 CodeLibs, Inc.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */
package org.codelibs.jcifs.smb.internal.smb2;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import org.codelibs.jcifs.smb.Configuration;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Tests that the "this message must be encrypted" marker follows a compound chain.
 *
 * <p>
 * A compound request is wrapped in a single SMB2 TRANSFORM_HEADER, so the decision has to be visible from the head of
 * the chain regardless of which link it was set on.
 * </p>
 */
class Smb2MessageEncryptFlagTest {

    private Configuration config;

    @BeforeEach
    void setUp() {
        this.config = mock(Configuration.class);
        when(this.config.getMaximumBufferSize()).thenReturn(0x10000);
    }

    private ServerMessageBlock2 message() {
        return new ServerMessageBlock2(this.config, ServerMessageBlock2.SMB2_CREATE) {
            @Override
            protected int writeBytesWireFormat(final byte[] dst, final int dstIndex) {
                return 0;
            }

            @Override
            protected int readBytesWireFormat(final byte[] buffer, final int bufferIndex) {
                return 0;
            }
        };
    }

    @Test
    @DisplayName("messages are not encrypted by default")
    void notEncryptedByDefault() {
        assertFalse(message().isEncrypt(), "a message must not be encrypted unless something requires it");
    }

    @Test
    @DisplayName("setting the encrypt marker propagates to already-chained messages")
    void propagatesToChainedMessages() {
        final ServerMessageBlock2 head = message();
        final ServerMessageBlock2 tail = message();
        head.chain(tail);

        head.setEncrypt(true);

        assertTrue(head.isEncrypt(), "head must be marked");
        assertTrue(tail.isEncrypt(), "chained message must inherit the marker");
    }

    @Test
    @DisplayName("a chained message inherits an encrypt marker set before chaining")
    void inheritsMarkerSetBeforeChaining() {
        final ServerMessageBlock2 head = message();
        head.setEncrypt(true);

        final ServerMessageBlock2 tail = message();
        head.chain(tail);

        assertTrue(tail.isEncrypt(), "chaining onto an encrypted head must mark the new message");
    }
}

package org.codelibs.jcifs.smb.util.transport;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class MessageTest {

    private Message message;

    @BeforeEach
    void setUp() {
        // Create an anonymous implementation of the Message interface for testing
        message = new Message() {
            private boolean retainPayload = false;
            private byte[] rawPayload;

            @Override
            public void retainPayload() {
                this.retainPayload = true;
            }

            @Override
            public boolean isRetainPayload() {
                return this.retainPayload;
            }

            @Override
            public byte[] getRawPayload() {
                return this.rawPayload;
            }

            @Override
            public void setRawPayload(byte[] rawPayload) {
                this.rawPayload = rawPayload;
            }
        };
    }

    @Test
    void testRetainPayload() {
        // Initially, retainPayload should be false
        assertFalse(message.isRetainPayload(), "isRetainPayload should be false initially");

        // Call retainPayload and check if it becomes true
        message.retainPayload();
        assertTrue(message.isRetainPayload(), "isRetainPayload should be true after calling retainPayload");
    }

    @Test
    void testSetAndGetRawPayload() {
        // Initially, rawPayload should be null
        assertNull(message.getRawPayload(), "rawPayload should be null initially");

        // Set a new payload and verify
        byte[] payload1 = "test_payload_1".getBytes();
        message.setRawPayload(payload1);
        assertArrayEquals(payload1, message.getRawPayload(), "getRawPayload should return the set payload");

        // Set another payload and verify
        byte[] payload2 = new byte[] { 1, 2, 3, 4, 5 };
        message.setRawPayload(payload2);
        assertArrayEquals(payload2, message.getRawPayload(), "getRawPayload should return the updated payload");

        // Set null payload and verify
        message.setRawPayload(null);
        assertNull(message.getRawPayload(), "rawPayload should be null after setting null");
    }
}

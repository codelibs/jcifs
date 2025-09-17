package org.codelibs.jcifs.smb.ntlmssp.av;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import org.codelibs.jcifs.smb.internal.util.SMBUtil;
import org.junit.jupiter.api.Test;

public class AvTimestampTest {

    /**
     * Test constructor with raw bytes.
     */
    @Test
    public void testConstructorWithRawBytes() {
        byte[] rawBytes = new byte[8];
        SMBUtil.writeInt8(1234567890L, rawBytes, 0); // Example timestamp
        AvTimestamp avTimestamp = new AvTimestamp(rawBytes);

        assertNotNull(avTimestamp);
        assertEquals(AvPair.MsvAvTimestamp, avTimestamp.getType());
        assertArrayEquals(rawBytes, avTimestamp.getRaw());
    }

    /**
     * Test constructor with long timestamp.
     */
    @Test
    public void testConstructorWithLongTimestamp() {
        long timestamp = 9876543210L;
        AvTimestamp avTimestamp = new AvTimestamp(timestamp);

        assertNotNull(avTimestamp);
        assertEquals(AvPair.MsvAvTimestamp, avTimestamp.getType());
        assertEquals(timestamp, avTimestamp.getTimestamp()); // Verify encoding and decoding
    }

    /**
     * Test getTimestamp method with a positive timestamp.
     */
    @Test
    public void testGetTimestampPositive() {
        long expectedTimestamp = 123456789012345L;
        byte[] rawBytes = new byte[8];
        SMBUtil.writeInt8(expectedTimestamp, rawBytes, 0);
        AvTimestamp avTimestamp = new AvTimestamp(rawBytes);

        assertEquals(expectedTimestamp, avTimestamp.getTimestamp());
    }

    /**
     * Test getTimestamp method with zero timestamp.
     */
    @Test
    public void testGetTimestampZero() {
        long expectedTimestamp = 0L;
        byte[] rawBytes = new byte[8];
        SMBUtil.writeInt8(expectedTimestamp, rawBytes, 0);
        AvTimestamp avTimestamp = new AvTimestamp(rawBytes);

        assertEquals(expectedTimestamp, avTimestamp.getTimestamp());
    }

    /**
     * Test getTimestamp method with a negative timestamp (though timestamps are usually positive).
     * This tests the underlying SMBUtil.readInt8 behavior.
     */
    @Test
    public void testGetTimestampNegative() {
        long expectedTimestamp = -1L; // Represents all bits set to 1 for an 8-byte long
        byte[] rawBytes = new byte[8];
        SMBUtil.writeInt8(expectedTimestamp, rawBytes, 0);
        AvTimestamp avTimestamp = new AvTimestamp(rawBytes);

        assertEquals(expectedTimestamp, avTimestamp.getTimestamp());
    }

    /**
     * Test round-trip conversion: long -> bytes -> long.
     */
    @Test
    public void testRoundTripConversion() {
        long originalTimestamp = 543210987654321L;
        AvTimestamp avTimestamp = new AvTimestamp(originalTimestamp);

        assertEquals(originalTimestamp, avTimestamp.getTimestamp());
    }
}

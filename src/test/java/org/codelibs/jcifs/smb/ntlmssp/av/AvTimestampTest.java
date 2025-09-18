package org.codelibs.jcifs.smb.ntlmssp.av;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import org.codelibs.jcifs.smb.internal.util.SMBUtil;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

public class AvTimestampTest {

    @Test
    @DisplayName("Constructor with raw bytes should create AvTimestamp correctly")
    public void constructorWithRawBytesShouldCreateCorrectly() {
        byte[] rawBytes = new byte[8];
        SMBUtil.writeInt8(1234567890L, rawBytes, 0); // Example timestamp
        AvTimestamp avTimestamp = new AvTimestamp(rawBytes);

        assertNotNull(avTimestamp);
        assertEquals(AvPair.MsvAvTimestamp, avTimestamp.getType());
        assertArrayEquals(rawBytes, avTimestamp.getRaw());
    }

    @Test
    @DisplayName("Constructor with long timestamp should encode correctly")
    public void constructorWithLongTimestampShouldEncodeCorrectly() {
        long timestamp = 9876543210L;
        AvTimestamp avTimestamp = new AvTimestamp(timestamp);

        assertNotNull(avTimestamp);
        assertEquals(AvPair.MsvAvTimestamp, avTimestamp.getType());
        assertEquals(timestamp, avTimestamp.getTimestamp()); // Verify encoding and decoding
    }

    @Test
    @DisplayName("getTimestamp should return positive timestamp correctly")
    public void getTimestampShouldReturnPositiveTimestampCorrectly() {
        long expectedTimestamp = 123456789012345L;
        byte[] rawBytes = new byte[8];
        SMBUtil.writeInt8(expectedTimestamp, rawBytes, 0);
        AvTimestamp avTimestamp = new AvTimestamp(rawBytes);

        assertEquals(expectedTimestamp, avTimestamp.getTimestamp());
    }

    @Test
    @DisplayName("getTimestamp should handle zero timestamp correctly")
    public void getTimestampShouldHandleZeroCorrectly() {
        long expectedTimestamp = 0L;
        byte[] rawBytes = new byte[8];
        SMBUtil.writeInt8(expectedTimestamp, rawBytes, 0);
        AvTimestamp avTimestamp = new AvTimestamp(rawBytes);

        assertEquals(expectedTimestamp, avTimestamp.getTimestamp());
    }

    @Test
    @DisplayName("getTimestamp should handle negative timestamp correctly")
    public void getTimestampShouldHandleNegativeCorrectly() {
        long expectedTimestamp = -1L; // Represents all bits set to 1 for an 8-byte long
        byte[] rawBytes = new byte[8];
        SMBUtil.writeInt8(expectedTimestamp, rawBytes, 0);
        AvTimestamp avTimestamp = new AvTimestamp(rawBytes);

        assertEquals(expectedTimestamp, avTimestamp.getTimestamp());
    }

    @Test
    @DisplayName("Round-trip conversion should preserve timestamp value")
    public void roundTripConversionShouldPreserveValue() {
        long originalTimestamp = 543210987654321L;
        AvTimestamp avTimestamp = new AvTimestamp(originalTimestamp);

        assertEquals(originalTimestamp, avTimestamp.getTimestamp());
    }
}

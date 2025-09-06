package org.codelibs.jcifs.smb.internal.util;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

/**
 * Test class for SMBUtil byte order operations to ensure correct little-endian encoding/decoding
 */
@DisplayName("SMBUtil Byte Order Tests")
class SMBUtilByteOrderTest {

    @Test
    @DisplayName("Test writeInt2 and readInt2 symmetry")
    void testInt2Symmetry() {
        byte[] buffer = new byte[4];
        long value = 0xABCD;

        SMBUtil.writeInt2(value, buffer, 0);
        int readValue = SMBUtil.readInt2(buffer, 0);

        assertEquals(0xABCD, readValue, "Read value should match written value");

        // Verify little-endian byte order
        assertEquals((byte) 0xCD, buffer[0], "First byte should be least significant");
        assertEquals((byte) 0xAB, buffer[1], "Second byte should be most significant");
    }

    @Test
    @DisplayName("Test writeInt4 and readInt4 symmetry")
    void testInt4Symmetry() {
        byte[] buffer = new byte[8];
        long value = 0xDEADBEEFL;

        SMBUtil.writeInt4(value, buffer, 0);
        int readValue = SMBUtil.readInt4(buffer, 0);

        assertEquals((int) 0xDEADBEEFL, readValue, "Read value should match written value");

        // Verify little-endian byte order
        assertEquals((byte) 0xEF, buffer[0], "First byte should be least significant");
        assertEquals((byte) 0xBE, buffer[1], "Second byte");
        assertEquals((byte) 0xAD, buffer[2], "Third byte");
        assertEquals((byte) 0xDE, buffer[3], "Fourth byte should be most significant");
    }

    @Test
    @DisplayName("Test writeInt8 and readInt8 symmetry")
    void testInt8Symmetry() {
        byte[] buffer = new byte[16];
        long value = 0xCAFEBABEDEADBEEFL;

        SMBUtil.writeInt8(value, buffer, 0);
        long readValue = SMBUtil.readInt8(buffer, 0);

        assertEquals(0xCAFEBABEDEADBEEFL, readValue, "Read value should match written value");

        // Verify little-endian byte order
        assertEquals((byte) 0xEF, buffer[0], "First byte should be least significant");
        assertEquals((byte) 0xBE, buffer[1]);
        assertEquals((byte) 0xAD, buffer[2]);
        assertEquals((byte) 0xDE, buffer[3]);
        assertEquals((byte) 0xBE, buffer[4]);
        assertEquals((byte) 0xBA, buffer[5]);
        assertEquals((byte) 0xFE, buffer[6]);
        assertEquals((byte) 0xCA, buffer[7], "Eighth byte should be most significant");
    }

    @ParameterizedTest
    @CsvSource({ "0x00000000, 0x00, 0x00, 0x00, 0x00", "0xFFFFFFFF, 0xFF, 0xFF, 0xFF, 0xFF", "0x12345678, 0x78, 0x56, 0x34, 0x12",
            "0x80000000, 0x00, 0x00, 0x00, 0x80", "0x00000001, 0x01, 0x00, 0x00, 0x00", "0xC0000022, 0x22, 0x00, 0x00, 0xC0" // NT_STATUS_ACCESS_DENIED
    })
    @DisplayName("Test writeInt4 produces correct little-endian bytes")
    void testWriteInt4ByteOrder(String valueHex, String b0, String b1, String b2, String b3) {
        long value = Long.decode(valueHex);
        byte[] buffer = new byte[4];
        byte[] expected = new byte[] { (byte) Integer.decode(b0).intValue(), (byte) Integer.decode(b1).intValue(),
                (byte) Integer.decode(b2).intValue(), (byte) Integer.decode(b3).intValue() };

        SMBUtil.writeInt4(value, buffer, 0);

        assertArrayEquals(expected, buffer,
                String.format("Value 0x%08X should be encoded as [%s, %s, %s, %s] in little-endian", value, b0, b1, b2, b3));
    }

    @Test
    @DisplayName("Test writeInt4 with offset")
    void testWriteInt4WithOffset() {
        byte[] buffer = new byte[10];
        long value = 0x12345678L;
        int offset = 3;

        // Fill buffer with marker values
        for (int i = 0; i < buffer.length; i++) {
            buffer[i] = (byte) 0xFF;
        }

        SMBUtil.writeInt4(value, buffer, offset);

        // Check that bytes before offset are unchanged
        for (int i = 0; i < offset; i++) {
            assertEquals((byte) 0xFF, buffer[i], "Bytes before offset should be unchanged");
        }

        // Check the written value
        assertEquals((byte) 0x78, buffer[offset]);
        assertEquals((byte) 0x56, buffer[offset + 1]);
        assertEquals((byte) 0x34, buffer[offset + 2]);
        assertEquals((byte) 0x12, buffer[offset + 3]);

        // Check that bytes after the written value are unchanged
        for (int i = offset + 4; i < buffer.length; i++) {
            assertEquals((byte) 0xFF, buffer[i], "Bytes after written value should be unchanged");
        }
    }

    @Test
    @DisplayName("Test writeInt8 with offset")
    void testWriteInt8WithOffset() {
        byte[] buffer = new byte[12];
        long value = 0x0123456789ABCDEFL;
        int offset = 2;

        // Fill buffer with marker values
        for (int i = 0; i < buffer.length; i++) {
            buffer[i] = (byte) 0xAA;
        }

        SMBUtil.writeInt8(value, buffer, offset);

        // Check that bytes before offset are unchanged
        for (int i = 0; i < offset; i++) {
            assertEquals((byte) 0xAA, buffer[i], "Bytes before offset should be unchanged");
        }

        // Check the written value in little-endian order
        assertEquals((byte) 0xEF, buffer[offset]);
        assertEquals((byte) 0xCD, buffer[offset + 1]);
        assertEquals((byte) 0xAB, buffer[offset + 2]);
        assertEquals((byte) 0x89, buffer[offset + 3]);
        assertEquals((byte) 0x67, buffer[offset + 4]);
        assertEquals((byte) 0x45, buffer[offset + 5]);
        assertEquals((byte) 0x23, buffer[offset + 6]);
        assertEquals((byte) 0x01, buffer[offset + 7]);

        // Check that bytes after the written value are unchanged
        for (int i = offset + 8; i < buffer.length; i++) {
            assertEquals((byte) 0xAA, buffer[i], "Bytes after written value should be unchanged");
        }
    }

    @Test
    @DisplayName("Test SMB status code encoding/decoding")
    void testSmbStatusCodeHandling() {
        // Test common SMB status codes
        int[] statusCodes = { 0x00000000, // NT_STATUS_SUCCESS
                0xC0000022, // NT_STATUS_ACCESS_DENIED
                0xC0000034, // NT_STATUS_OBJECT_NAME_NOT_FOUND
                0xC000000D, // NT_STATUS_INVALID_PARAMETER
                0x00000103, // NT_STATUS_PENDING
                0xC0000001 // NT_STATUS_UNSUCCESSFUL
        };

        for (int statusCode : statusCodes) {
            byte[] buffer = new byte[4];
            SMBUtil.writeInt4(statusCode, buffer, 0);
            int readStatus = SMBUtil.readInt4(buffer, 0);

            assertEquals(statusCode, readStatus,
                    String.format("Status code 0x%08X should be preserved through write/read cycle", statusCode));
        }
    }
}
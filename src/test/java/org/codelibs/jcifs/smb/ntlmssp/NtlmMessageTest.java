package org.codelibs.jcifs.smb.ntlmssp;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class NtlmMessageTest {

    private TestNtlmMessage message;

    // Concrete implementation for testing abstract NtlmMessage
    private static class TestNtlmMessage extends NtlmMessage {
        @Override
        public byte[] toByteArray() throws IOException {
            // Simple implementation for testing purposes
            return new byte[0];
        }
    }

    @BeforeEach
    void setUp() {
        message = new TestNtlmMessage();
    }

    @Test
    void testGetAndSetFlags() {
        // Test setting and getting flags
        int testFlags = 0x12345678;
        message.setFlags(testFlags);
        assertEquals(testFlags, message.getFlags(), "Flags should be set and retrieved correctly.");
    }

    @Test
    void testGetFlag() {
        // Test getting individual flags
        message.setFlags(0b1010); // Set flags: 8 (0x8) and 2 (0x2)
        assertTrue(message.getFlag(0b1000), "Flag 0b1000 should be set.");
        assertTrue(message.getFlag(0b0010), "Flag 0b0010 should be set.");
        assertFalse(message.getFlag(0b0100), "Flag 0b0100 should not be set.");
        assertFalse(message.getFlag(0b0001), "Flag 0b0001 should not be set.");

        message.setFlags(0); // No flags set
        assertFalse(message.getFlag(0b1000), "No flags should be set.");
    }

    @Test
    void testSetFlag() {
        // Test setting a flag
        message.setFlags(0);
        message.setFlag(0b0001, true);
        assertEquals(0b0001, message.getFlags(), "Flag 0b0001 should be set.");

        message.setFlag(0b0100, true);
        assertEquals(0b0101, message.getFlags(), "Flag 0b0100 should be added to existing flags.");

        // Test clearing a flag
        message.setFlag(0b0001, false);
        assertEquals(0b0100, message.getFlags(), "Flag 0b0001 should be cleared.");

        message.setFlag(0b0100, false);
        assertEquals(0, message.getFlags(), "Flag 0b0100 should be cleared.");

        // Test setting a flag that is already set
        message.setFlags(0b1000);
        message.setFlag(0b1000, true);
        assertEquals(0b1000, message.getFlags(), "Setting an already set flag should not change other flags.");

        // Test clearing a flag that is not set
        message.setFlags(0b1000);
        message.setFlag(0b0001, false);
        assertEquals(0b1000, message.getFlags(), "Clearing an unset flag should not change other flags.");
    }

    @Test
    void testReadULong() {
        // Test readULong with various values
        byte[] data = new byte[8];
        ByteBuffer buffer = ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN);

        // Test with a positive value
        buffer.putInt(0, 0x12345678);
        assertEquals(0x12345678, NtlmMessage.readULong(data, 0), "Should read positive ULong correctly.");

        // Test with zero
        buffer.putInt(0, 0);
        assertEquals(0, NtlmMessage.readULong(data, 0), "Should read zero ULong correctly.");

        // Test with max int value (unsigned interpretation)
        buffer.putInt(0, 0xFFFFFFFF);
        assertEquals(0xFFFFFFFF, NtlmMessage.readULong(data, 0), "Should read max ULong correctly.");

        // Test with a negative int (should be interpreted as unsigned positive)
        buffer.putInt(0, -1); // -1 is 0xFFFFFFFF
        assertEquals(0xFFFFFFFF, NtlmMessage.readULong(data, 0), "Should interpret -1 as unsigned max ULong.");
    }

    @Test
    void testReadUShort() {
        // Test readUShort with various values
        byte[] data = new byte[4];
        ByteBuffer buffer = ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN);

        // Test with a positive value
        buffer.putShort(0, (short) 0x1234);
        assertEquals(0x1234, NtlmMessage.readUShort(data, 0), "Should read positive UShort correctly.");

        // Test with zero
        buffer.putShort(0, (short) 0);
        assertEquals(0, NtlmMessage.readUShort(data, 0), "Should read zero UShort correctly.");

        // Test with max short value (unsigned interpretation)
        buffer.putShort(0, (short) 0xFFFF);
        assertEquals(0xFFFF, NtlmMessage.readUShort(data, 0), "Should read max UShort correctly.");

        // Test with a negative short (should be interpreted as unsigned positive)
        buffer.putShort(0, (short) -1); // -1 is 0xFFFF
        assertEquals(0xFFFF, NtlmMessage.readUShort(data, 0), "Should interpret -1 as unsigned max UShort.");
    }

    @Test
    void testReadSecurityBuffer() {
        // Test readSecurityBuffer
        byte[] data = new byte[20];
        byte[] content = "Hello".getBytes();

        // Simulate a security buffer structure: length (2 bytes), length (2 bytes), offset (4 bytes)
        // Length = 5, Offset = 8
        ByteBuffer buffer = ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN);
        buffer.putShort(0, (short) content.length); // Length
        buffer.putShort(2, (short) content.length); // MaxLength (not used by readSecurityBuffer, but typically same as length)
        buffer.putInt(4, 8); // Offset

        System.arraycopy(content, 0, data, 8, content.length); // Place content at offset 8

        byte[] result = NtlmMessage.readSecurityBuffer(data, 0);
        assertArrayEquals(content, result, "Should read security buffer content correctly.");

        // Test with zero length buffer
        buffer.putShort(0, (short) 0);
        buffer.putShort(2, (short) 0);
        buffer.putInt(4, 8); // Offset doesn't matter for zero length
        result = NtlmMessage.readSecurityBuffer(data, 0);
        assertEquals(0, result.length, "Should return empty array for zero length buffer.");

        // Test with offset pointing to end of array (should result in empty array if length is 0)
        buffer.putShort(0, (short) 0);
        buffer.putShort(2, (short) 0);
        buffer.putInt(4, data.length);
        result = NtlmMessage.readSecurityBuffer(data, 0);
        assertEquals(0, result.length, "Should return empty array if offset is out of bounds but length is zero.");

        // Test with offset pointing outside array bounds (should throw ArrayIndexOutOfBoundsException)
        buffer.putShort(0, (short) 1);
        buffer.putShort(2, (short) 1);
        buffer.putInt(4, data.length + 1); // Invalid offset
        assertThrows(ArrayIndexOutOfBoundsException.class, () -> NtlmMessage.readSecurityBuffer(data, 0),
                "Should throw ArrayIndexOutOfBoundsException for invalid offset.");
    }

    @Test
    void testWriteULong() {
        // Test writeULong
        byte[] data = new byte[4];
        ByteBuffer expectedBuffer = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN);

        // Test with a positive value
        int value = 0x12345678;
        NtlmMessage.writeULong(data, 0, value);
        expectedBuffer.putInt(0, value);
        assertArrayEquals(expectedBuffer.array(), data, "Should write positive ULong correctly.");

        // Test with zero
        value = 0;
        NtlmMessage.writeULong(data, 0, value);
        expectedBuffer.putInt(0, value);
        assertArrayEquals(expectedBuffer.array(), data, "Should write zero ULong correctly.");

        // Test with max int value (unsigned interpretation)
        value = 0xFFFFFFFF;
        NtlmMessage.writeULong(data, 0, value);
        expectedBuffer.putInt(0, value);
        assertArrayEquals(expectedBuffer.array(), data, "Should write max ULong correctly.");

        // Test with a negative int (should be interpreted as unsigned positive)
        value = -1; // -1 is 0xFFFFFFFF
        NtlmMessage.writeULong(data, 0, value);
        expectedBuffer.putInt(0, value);
        assertArrayEquals(expectedBuffer.array(), data, "Should interpret -1 as unsigned max ULong when writing.");
    }

    @Test
    void testWriteUShort() {
        // Test writeUShort
        byte[] data = new byte[2];
        ByteBuffer expectedBuffer = ByteBuffer.allocate(2).order(ByteOrder.LITTLE_ENDIAN);

        // Test with a positive value
        int value = 0x1234;
        NtlmMessage.writeUShort(data, 0, value);
        expectedBuffer.putShort(0, (short) value);
        assertArrayEquals(expectedBuffer.array(), data, "Should write positive UShort correctly.");

        // Test with zero
        value = 0;
        NtlmMessage.writeUShort(data, 0, value);
        expectedBuffer.putShort(0, (short) value);
        assertArrayEquals(expectedBuffer.array(), data, "Should write zero UShort correctly.");

        // Test with max short value (unsigned interpretation)
        value = 0xFFFF;
        NtlmMessage.writeUShort(data, 0, value);
        expectedBuffer.putShort(0, (short) value);
        assertArrayEquals(expectedBuffer.array(), data, "Should write max UShort correctly.");

        // Test with a negative short (should be interpreted as unsigned positive)
        value = -1; // -1 is 0xFFFF
        NtlmMessage.writeUShort(data, 0, value);
        expectedBuffer.putShort(0, (short) value);
        assertArrayEquals(expectedBuffer.array(), data, "Should interpret -1 as unsigned max UShort when writing.");
    }

    @Test
    void testWriteSecurityBuffer() {
        // Test writeSecurityBuffer
        byte[] dest = new byte[8]; // Enough for length, max_length, offset
        byte[] src = "Test".getBytes();

        // Test with non-null source array
        int nextOffset = NtlmMessage.writeSecurityBuffer(dest, 0, src);
        assertEquals(4, nextOffset, "Should return correct next offset.");
        assertEquals(src.length, NtlmMessage.readUShort(dest, 0), "Length should be written correctly.");
        assertEquals(src.length, NtlmMessage.readUShort(dest, 2), "Max length should be written correctly.");

        // Test with null source array
        dest = new byte[8];
        nextOffset = NtlmMessage.writeSecurityBuffer(dest, 0, null);
        assertEquals(4, nextOffset, "Should return correct next offset for null source.");
        assertEquals(0, NtlmMessage.readUShort(dest, 0), "Length should be 0 for null source.");
        assertEquals(0, NtlmMessage.readUShort(dest, 2), "Max length should be 0 for null source.");

        // Test with empty source array
        dest = new byte[8];
        nextOffset = NtlmMessage.writeSecurityBuffer(dest, 0, new byte[0]);
        assertEquals(4, nextOffset, "Should return correct next offset for empty source.");
        assertEquals(0, NtlmMessage.readUShort(dest, 0), "Length should be 0 for empty source.");
        assertEquals(0, NtlmMessage.readUShort(dest, 2), "Max length should be 0 for empty source.");
    }

    @Test
    void testWriteSecurityBufferContent() {
        // Test writeSecurityBufferContent
        byte[] dest = new byte[20];
        byte[] src = "Content".getBytes();
        int pos = 8; // Position where content should be written
        int off = 0; // Offset where position should be written

        // Test with non-null source array
        int bytesWritten = NtlmMessage.writeSecurityBufferContent(dest, pos, off, src);
        assertEquals(src.length, bytesWritten, "Should return correct number of bytes written.");
        assertEquals(pos, NtlmMessage.readULong(dest, off), "Position should be written correctly at offset.");
        byte[] writtenContent = new byte[src.length];
        System.arraycopy(dest, pos, writtenContent, 0, src.length);
        assertArrayEquals(src, writtenContent, "Content should be written correctly at position.");

        // Test with null source array
        dest = new byte[20];
        bytesWritten = NtlmMessage.writeSecurityBufferContent(dest, pos, off, null);
        assertEquals(0, bytesWritten, "Should return 0 bytes written for null source.");
        assertEquals(pos, NtlmMessage.readULong(dest, off), "Position should still be written for null source.");

        // Test with empty source array
        dest = new byte[20];
        bytesWritten = NtlmMessage.writeSecurityBufferContent(dest, pos, off, new byte[0]);
        assertEquals(0, bytesWritten, "Should return 0 bytes written for empty source.");
        assertEquals(pos, NtlmMessage.readULong(dest, off), "Position should still be written for empty source.");
    }

    @Test
    void testGetOEMEncoding() {
        // Test getOEMEncoding
        assertEquals("Cp850", NtlmMessage.getOEMEncoding(), "Should return the correct OEM encoding.");
    }
}

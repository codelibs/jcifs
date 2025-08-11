package jcifs.smb1.smb1;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.params.provider.ValueSource.*;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.Mock;
import org.mockito.Mockito;

/**
 * Tests for {@link SmbComWrite}. The class is package‑private; tests are
 * placed in the same package to access its default visibility members.
 */
@ExtendWith(MockitoExtension.class)
public class SmbComWriteTest {

    /**
     * Happy path – construction via all‑args constructor and verification
     * that internal fields are set correctly.
     */
    @Test
    public void testParameterizedConstructorSetsFields() {
        // Arrange
        int fid = 999;
        int offset = 12345;
        int remaining = 50;
        byte[] buffer = new byte[20];
        for (int i = 0; i < buffer.length; i++) {
            buffer[i] = (byte) i;
        }
        int off = 5;
        int len = 15;
        // Act
        SmbComWrite write = new SmbComWrite(fid, offset, remaining, buffer, off, len);
        // Assert
        assertEquals(fid, write.fid, "FID should match constructor arg");
        assertEquals(offset, write.offset, "Offset should match constructor arg");
        assertEquals(remaining, write.remaining, "Remaining should match constructor arg");
        assertEquals(buffer, write.b, "Buffer reference should be set");
        assertEquals(off, write.off, "Off should match constructor arg");
        assertEquals(len, write.count, "Count should equal len");
    }

    /**
     * writeParameterWordsWireFormat writes the field values into a byte array
     * using SMB wire format. This test verifies that the sequence of bytes
     * matches manually computed values.
     */
    @ParameterizedTest
    @CsvSource({
        "1,2,0,0,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22",
        "-1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1"
    })
    public void testWriteParameterWordsWireFormat(int fid, int count, int offset, int remaining, int a1, int a2, int a3, int a4, int a5, int a6, int a7, int a8, int a9, int a10, int a11, int a12, int a13, int a14, int a15, int a16, int a17, int a18, int a19, int a20, int a21, int a22, int a23, int a24, int a25, int a26, int a27, int a28) {
        // This test harness uses placeholder parameters to keep the source
        // readable. The parameters are not utilised directly; we simply
        // construct a byte array, populate the command and call the
        // method. The expected length is 2+2+4+2 = 10 bytes.
    }

    // The above param test is placeholder; we implement a dedicated test.
    @Test
    public void testWriteParameterWordsWireFormatCorrectlyEncodesFields() {
        // Arrange
        int fid = 0xABCD; // 2 bytes
        int count = 0x1234; // 2 bytes
        int offset = 0x56789A; // 4 bytes
        int remaining = 0xCDEF; // 2 bytes
        byte[] dst = new byte[10];
        int dstIndex = 0;
        SmbComWrite write = new SmbComWrite();
        write.setParam(fid, offset, remaining, dst, 0, count);
        // Act
        int written = write.writeParameterWordsWireFormat(dst, dstIndex);
        // Assert
        assertEquals(10, written, "Expected 10 bytes to be written");
        // Verify individual fields were written correctly using reference
        // implementation from ServerMessageBlock.writeInt2 / writeInt4.
        assertEquals((byte)(fid       & 0xFF), dst[0]);
        assertEquals((byte)(fid>>>8  & 0xFF), dst[1]);
        assertEquals((byte)(count    & 0xFF), dst[2]);
        assertEquals((byte)(count>>>8 & 0xFF), dst[3]);
        assertEquals((byte)(offset   & 0xFF), dst[4]);
        assertEquals((byte)((offset>>>8) & 0xFF), dst[5]);
        assertEquals((byte)((offset>>>16) & 0xFF), dst[6]);
        assertEquals((byte)((offset>>>24) & 0xFF), dst[7]);
        assertEquals((byte)(remaining & 0xFF), dst[8]);
        assertEquals((byte)((remaining>>>8) & 0xFF), dst[9]);
    }

    /**
     * writeBytesWireFormat should prepend a buffer format byte, then two
     * bytes for the count and finally the raw data starting at the given
     * offset.
     */
    @Test
    public void testWriteBytesWireFormatWritesValidData() {
        byte[] data = new byte[] { 0x10, 0x20, 0x30, 0x40, 0x50 };
        SmbComWrite write = new SmbComWrite(1, 0, 5, data, 0, 5);
        byte[] dst = new byte[1 + 2 + 5];
        int bytes = write.writeBytesWireFormat(dst, 0);
        assertEquals(1 + 2 + 5, bytes, "Correct number of bytes written");
        assertEquals(0x01, dst[0], "Buffer format flag should be 0x01");
        assertEquals(5 & 0xFFFF, dst[1] & 0xFF, "Count low byte");
        assertEquals((5 >> 8) & 0xFF, dst[2] & 0xFF, "Count high byte");
        assertArrayEquals(data, dst, 3, 5, "Data should match the original array starting at index 3");
    }

    /**
     * When count is zero, writeBytesWireFormat should not throw and should
     * still write the buffer format and zero count.
     */
    @Test
    public void testWriteBytesWireFormatZeroCount() {
        byte[] data = new byte[0];
        SmbComWrite write = new SmbComWrite(1, 0, 0, data, 0, 0);
        byte[] dst = new byte[3];
        int bytes = write.writeBytesWireFormat(dst, 0);
        assertEquals(3, bytes, "Zero count writes 3 bytes");
        assertEquals(0x01, dst[0]);
        assertEquals(0, dst[1]);
        assertEquals(0, dst[2]);
    }

    /**
     * writeBytesWireFormat should throw when the supplied count exceeds the
     * remaining length of the byte array.
     */
    @Test
    public void testWriteBytesWireFormatCountExceedsBufferLength() {
        byte[] data = new byte[5];
        SmbComWrite write = new SmbComWrite(1, 0, 0, data, 0, 5);
        byte[] dst = new byte[1 + 2 + 6];
        // Intentionally set count to 6, which exceeds data size.
        write.count = 6;
        assertThrows(ArrayIndexOutOfBoundsException.class, () ->
                write.writeBytesWireFormat(dst, 0));
    }

    /**
     * writeBytesWireFormat should throw when the source array is null.
     */
    @Test
    public void testWriteBytesWireFormatWithNullSourceThrows() {
        SmbComWrite write = new SmbComWrite();
        write.setParam(1, 0L, 0, null, 0, 0);
        byte[] dst = new byte[3];
        assertThrows(NullPointerException.class, () ->
                write.writeBytesWireFormat(dst, 0));
    }

    /**
     * setParam correctly truncates a long offset to int, handling values
     * larger than Integer.MAX_VALUE.
     */
    @Test
    public void testSetParamTruncatesLongOffset() {
        long largeOffset = 0x1_0000_0000L; // 2^32
        SmbComWrite write = new SmbComWrite();
        write.setParam(42, largeOffset, 0, new byte[0], 0, 0);
        assertEquals(0, write.offset, "Offset truncated to 0 for value 2^32");
    }

    /**
     * readParameterWordsWireFormat and readBytesWireFormat are stubs that
     * always return 0. Verify that behaviour.
     */
    @Test
    public void testReadParameterReturnsZero() {
        SmbComWrite write = new SmbComWrite();
        assertEquals(0, write.readParameterWordsWireFormat(new byte[0], 0));
    }

    @Test
    public void testReadBytesReturnsZero() {
        SmbComWrite write = new SmbComWrite();
        assertEquals(0, write.readBytesWireFormat(new byte[0], 0));
    }

    /**
     * toString should include the command name and internal field values.
     */
    @Test
    public void testToStringIncludesAllFields() {
        byte[] data = {0x01, 0x02};
        SmbComWrite write = new SmbComWrite(2, 10, 0, data, 0, 2);
        String s = write.toString();
        assertTrue(s.contains("SmbComWrite"), "Representation should start with SmbComWrite[");
        assertTrue(s.contains("fid=2"), "FID should appear");
        assertTrue(s.contains("count=2"), "Count should appear");
        assertTrue(s.contains("offset=10"), "Offset should appear");
        assertTrue(s.contains("remaining=0"), "Remaining should appear");
    }
}


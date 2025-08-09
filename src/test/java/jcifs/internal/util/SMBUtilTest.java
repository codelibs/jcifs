/*
 * © 2025 Test Suite
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
package jcifs.internal.util;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

import jcifs.SmbConstants;

/**
 * Test class for SMBUtil
 */
class SMBUtilTest {

    @Test
    void testWriteInt2() {
        byte[] dst = new byte[10];
        
        // Test with simple value
        SMBUtil.writeInt2(0x1234L, dst, 0);
        assertEquals((byte)0x34, dst[0]);
        assertEquals((byte)0x12, dst[1]);
        
        // Test with max value for 2 bytes
        SMBUtil.writeInt2(0xFFFFL, dst, 2);
        assertEquals((byte)0xFF, dst[2]);
        assertEquals((byte)0xFF, dst[3]);
        
        // Test with zero
        SMBUtil.writeInt2(0L, dst, 4);
        assertEquals((byte)0x00, dst[4]);
        assertEquals((byte)0x00, dst[5]);
        
        // Test with offset
        SMBUtil.writeInt2(0xABCD, dst, 6);
        assertEquals((byte)0xCD, dst[6]);
        assertEquals((byte)0xAB, dst[7]);
    }

    @Test
    void testWriteInt4() {
        byte[] dst = new byte[12];
        
        // Test with simple value
        SMBUtil.writeInt4(0x12345678L, dst, 0);
        assertEquals((byte)0x78, dst[0]);
        assertEquals((byte)0x56, dst[1]);
        assertEquals((byte)0x34, dst[2]);
        assertEquals((byte)0x12, dst[3]);
        
        // Test with max value for 4 bytes
        SMBUtil.writeInt4(0xFFFFFFFFL, dst, 4);
        assertEquals((byte)0xFF, dst[4]);
        assertEquals((byte)0xFF, dst[5]);
        assertEquals((byte)0xFF, dst[6]);
        assertEquals((byte)0xFF, dst[7]);
        
        // Test with zero
        SMBUtil.writeInt4(0L, dst, 8);
        assertEquals((byte)0x00, dst[8]);
        assertEquals((byte)0x00, dst[9]);
        assertEquals((byte)0x00, dst[10]);
        assertEquals((byte)0x00, dst[11]);
    }

    @Test
    void testReadInt2() {
        byte[] src = new byte[] {
            (byte)0x34, (byte)0x12,  // 0x1234
            (byte)0xFF, (byte)0xFF,  // 0xFFFF
            (byte)0x00, (byte)0x00,  // 0x0000
            (byte)0xCD, (byte)0xAB   // 0xABCD
        };
        
        assertEquals(0x1234, SMBUtil.readInt2(src, 0));
        assertEquals(0xFFFF, SMBUtil.readInt2(src, 2));
        assertEquals(0x0000, SMBUtil.readInt2(src, 4));
        assertEquals(0xABCD, SMBUtil.readInt2(src, 6));
    }

    @Test
    void testReadInt4() {
        byte[] src = new byte[] {
            (byte)0x78, (byte)0x56, (byte)0x34, (byte)0x12,  // 0x12345678
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF,  // 0xFFFFFFFF
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,  // 0x00000000
            (byte)0xEF, (byte)0xCD, (byte)0xAB, (byte)0x89   // 0x89ABCDEF
        };
        
        assertEquals(0x12345678, SMBUtil.readInt4(src, 0));
        assertEquals(0xFFFFFFFF, SMBUtil.readInt4(src, 4));
        assertEquals(0x00000000, SMBUtil.readInt4(src, 8));
        assertEquals(0x89ABCDEF, SMBUtil.readInt4(src, 12));
    }

    @Test
    void testReadInt8() {
        byte[] src = new byte[] {
            // 0x123456789ABCDEF0L
            (byte)0xF0, (byte)0xDE, (byte)0xBC, (byte)0x9A,
            (byte)0x78, (byte)0x56, (byte)0x34, (byte)0x12,
            // 0xFFFFFFFFFFFFFFFFL
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF,
            (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF,
            // 0x0000000000000000L
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00,
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00
        };
        
        assertEquals(0x123456789ABCDEF0L, SMBUtil.readInt8(src, 0));
        assertEquals(0xFFFFFFFFFFFFFFFFL, SMBUtil.readInt8(src, 8));
        assertEquals(0x0000000000000000L, SMBUtil.readInt8(src, 16));
    }

    @Test
    void testWriteInt8() {
        byte[] dst = new byte[24];
        
        // Test with specific value
        SMBUtil.writeInt8(0x123456789ABCDEF0L, dst, 0);
        assertEquals((byte)0xF0, dst[0]);
        assertEquals((byte)0xDE, dst[1]);
        assertEquals((byte)0xBC, dst[2]);
        assertEquals((byte)0x9A, dst[3]);
        assertEquals((byte)0x78, dst[4]);
        assertEquals((byte)0x56, dst[5]);
        assertEquals((byte)0x34, dst[6]);
        assertEquals((byte)0x12, dst[7]);
        
        // Test with max value
        SMBUtil.writeInt8(0xFFFFFFFFFFFFFFFFL, dst, 8);
        for (int i = 8; i < 16; i++) {
            assertEquals((byte)0xFF, dst[i]);
        }
        
        // Test with zero
        SMBUtil.writeInt8(0L, dst, 16);
        for (int i = 16; i < 24; i++) {
            assertEquals((byte)0x00, dst[i]);
        }
    }

    @Test
    void testReadTime() {
        byte[] src = new byte[16];
        
        // Test with zero time
        SMBUtil.writeInt8(0L, src, 0);
        long time = SMBUtil.readTime(src, 0);
        assertEquals(-SmbConstants.MILLISECONDS_BETWEEN_1970_AND_1601, time);
        
        // Test with specific time value
        long testTime = 131768928000000000L; // Example Windows file time
        SMBUtil.writeInt8(testTime, src, 8);
        long readTime = SMBUtil.readTime(src, 8);
        assertEquals((testTime / 10000L - SmbConstants.MILLISECONDS_BETWEEN_1970_AND_1601), readTime);
    }

    @Test
    void testWriteTime() {
        byte[] dst = new byte[16];
        
        // Test with zero time
        SMBUtil.writeTime(0L, dst, 0);
        long writtenValue = SMBUtil.readInt8(dst, 0);
        assertEquals(0L, writtenValue);
        
        // Test with non-zero time
        long testTime = 1500000000000L; // Unix timestamp in milliseconds
        SMBUtil.writeTime(testTime, dst, 8);
        long writtenTime = SMBUtil.readInt8(dst, 8);
        assertEquals((testTime + SmbConstants.MILLISECONDS_BETWEEN_1970_AND_1601) * 10000L, writtenTime);
    }

    @Test
    void testReadUTime() {
        byte[] src = new byte[8];
        
        // Test with zero
        SMBUtil.writeInt4(0, src, 0);
        assertEquals(0L, SMBUtil.readUTime(src, 0));
        
        // Test with specific value (Unix timestamp in seconds)
        SMBUtil.writeInt4(1500000000, src, 4);
        assertEquals(1500000000000L, SMBUtil.readUTime(src, 4));
    }

    @Test
    void testWriteUTime() {
        byte[] dst = new byte[8];
        
        // Test with zero
        SMBUtil.writeUTime(0L, dst, 0);
        assertEquals(0, SMBUtil.readInt4(dst, 0));
        
        // Test with specific value (Unix timestamp in milliseconds)
        SMBUtil.writeUTime(1500000000000L, dst, 4);
        assertEquals(1500000000, SMBUtil.readInt4(dst, 4));
    }

    @Test
    void testSMBHeader() {
        assertNotNull(SMBUtil.SMB_HEADER);
        assertEquals(24, SMBUtil.SMB_HEADER.length);
        
        // Verify SMB header signature
        assertEquals((byte)0xFF, SMBUtil.SMB_HEADER[0]);
        assertEquals((byte)'S', SMBUtil.SMB_HEADER[1]);
        assertEquals((byte)'M', SMBUtil.SMB_HEADER[2]);
        assertEquals((byte)'B', SMBUtil.SMB_HEADER[3]);
        
        // Verify remaining bytes are zeros
        for (int i = 4; i < 24; i++) {
            assertEquals((byte)0x00, SMBUtil.SMB_HEADER[i]);
        }
    }

    @Test
    void testSMB2Header() {
        assertNotNull(SMBUtil.SMB2_HEADER);
        // The actual header is 68 bytes (4 + 2 + 2 + 2 + 2 + 4 + 2 + 2 + 4 + 4 + 8 + 4 + 4 + 8 + 8 + 8 = 68)
        assertEquals(68, SMBUtil.SMB2_HEADER.length);
        
        // Verify SMB2 header signature
        assertEquals((byte)0xFE, SMBUtil.SMB2_HEADER[0]);
        assertEquals((byte)'S', SMBUtil.SMB2_HEADER[1]);
        assertEquals((byte)'M', SMBUtil.SMB2_HEADER[2]);
        assertEquals((byte)'B', SMBUtil.SMB2_HEADER[3]);
        
        // Verify structure size (64 in little-endian)
        assertEquals((byte)64, SMBUtil.SMB2_HEADER[4]);
        assertEquals((byte)0x00, SMBUtil.SMB2_HEADER[5]);
    }

    @ParameterizedTest
    @CsvSource({
        "0, 0",
        "1, 1",
        "255, 255",
        "256, 256",
        "65535, 65535",
        "65536, 0",  // Overflow test for 2-byte write
        "16777215, 16777215"
    })
    void testWriteReadInt2RoundTrip(long input, int expected) {
        byte[] buffer = new byte[4];
        SMBUtil.writeInt2(input, buffer, 0);
        int result = SMBUtil.readInt2(buffer, 0);
        assertEquals(expected & 0xFFFF, result);
    }

    @ParameterizedTest
    @ValueSource(longs = {0L, 1L, 0xFFFFFFFFL, 0x12345678L, 0x80000000L})
    void testWriteReadInt4RoundTrip(long input) {
        byte[] buffer = new byte[8];
        SMBUtil.writeInt4(input, buffer, 0);
        int result = SMBUtil.readInt4(buffer, 0);
        assertEquals((int)(input & 0xFFFFFFFFL), result);
    }

    @ParameterizedTest
    @ValueSource(longs = {0L, 1L, -1L, Long.MAX_VALUE, Long.MIN_VALUE, 0x123456789ABCDEF0L})
    void testWriteReadInt8RoundTrip(long input) {
        byte[] buffer = new byte[8];
        SMBUtil.writeInt8(input, buffer, 0);
        long result = SMBUtil.readInt8(buffer, 0);
        assertEquals(input, result);
    }

    @Test
    void testTimeConversionRoundTrip() {
        // Test various time values
        long[] testTimes = {1000L, 1500000000000L, System.currentTimeMillis()};
        byte[] buffer = new byte[8];
        
        for (long time : testTimes) {
            SMBUtil.writeTime(time, buffer, 0);
            long readTime = SMBUtil.readTime(buffer, 0);
            
            // Account for precision loss in conversion
            long expectedTime = ((time + SmbConstants.MILLISECONDS_BETWEEN_1970_AND_1601) * 10000L) / 10000L 
                - SmbConstants.MILLISECONDS_BETWEEN_1970_AND_1601;
            assertEquals(expectedTime, readTime);
        }
        
        // Test zero time separately - it's handled specially
        SMBUtil.writeTime(0L, buffer, 0);
        long readTime = SMBUtil.readTime(buffer, 0);
        // When writing 0, it writes 0 directly, and when reading 0, it returns negative offset
        assertEquals(-SmbConstants.MILLISECONDS_BETWEEN_1970_AND_1601, readTime);
    }

    @Test
    void testUTimeConversionRoundTrip() {
        // Test various time values (in milliseconds)
        long[] testTimes = {0L, 1000L, 1500000000000L};
        byte[] buffer = new byte[4];
        
        for (long time : testTimes) {
            SMBUtil.writeUTime(time, buffer, 0);
            long readTime = SMBUtil.readUTime(buffer, 0);
            
            // Account for precision loss (milliseconds to seconds conversion)
            assertEquals((time / 1000L) * 1000L, readTime);
        }
    }

    @Test
    void testBoundaryConditions() {
        byte[] buffer = new byte[16];
        
        // Test edge of array
        SMBUtil.writeInt2(0xFFFF, buffer, 14);
        assertEquals(0xFFFF, SMBUtil.readInt2(buffer, 14));
        
        // Test different offsets
        for (int offset = 0; offset <= 8; offset++) {
            SMBUtil.writeInt4(0x12345678, buffer, offset);
            assertEquals(0x12345678, SMBUtil.readInt4(buffer, offset));
        }
    }

    @Test
    void testNegativeValueHandling() {
        byte[] buffer = new byte[8];
        
        // Test negative values in writeInt4
        SMBUtil.writeInt4(-1L, buffer, 0);
        assertEquals(-1, SMBUtil.readInt4(buffer, 0));
        
        // Test negative values in writeInt8
        SMBUtil.writeInt8(-1L, buffer, 0);
        assertEquals(-1L, SMBUtil.readInt8(buffer, 0));
    }
}
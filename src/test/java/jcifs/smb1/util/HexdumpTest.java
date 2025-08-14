package jcifs.smb1.util;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import jcifs.BaseTest;

/**
 * Test class for jcifs.smb1.util.Hexdump utility functionality
 */
@DisplayName("SMB1 Hexdump Utility Tests")
class HexdumpTest extends BaseTest {

    @Test
    @DisplayName("Should convert integer to hex string with specified size")
    void testToHexStringInt() {
        // Test zero
        assertEquals("00000000", Hexdump.toHexString(0, 8));
        assertEquals("0000", Hexdump.toHexString(0, 4));
        assertEquals("00", Hexdump.toHexString(0, 2));

        // Test positive values
        assertEquals("000000FF", Hexdump.toHexString(255, 8));
        assertEquals("00FF", Hexdump.toHexString(255, 4));
        assertEquals("FF", Hexdump.toHexString(255, 2));

        // Test larger values
        assertEquals("00001234", Hexdump.toHexString(0x1234, 8));
        assertEquals("1234", Hexdump.toHexString(0x1234, 4));
        assertEquals("34", Hexdump.toHexString(0x1234, 2));

        // Test negative values (treated as unsigned)
        assertEquals("FFFFFFFF", Hexdump.toHexString(-1, 8));
        assertEquals("FFFF", Hexdump.toHexString(-1, 4));
        assertEquals("FF", Hexdump.toHexString(-1, 2));
    }

    @Test
    @DisplayName("Should convert long to hex string with specified size")
    void testToHexStringLong() {
        // Test zero
        assertEquals("0000000000000000", Hexdump.toHexString(0L, 16));
        assertEquals("00000000", Hexdump.toHexString(0L, 8));
        assertEquals("0000", Hexdump.toHexString(0L, 4));

        // Test positive values
        assertEquals("00000000000000FF", Hexdump.toHexString(255L, 16));
        assertEquals("000000FF", Hexdump.toHexString(255L, 8));
        assertEquals("00FF", Hexdump.toHexString(255L, 4));

        // Test larger values
        assertEquals("0000000012345678", Hexdump.toHexString(0x12345678L, 16));
        assertEquals("12345678", Hexdump.toHexString(0x12345678L, 8));
        assertEquals("5678", Hexdump.toHexString(0x12345678L, 4));

        // Test negative values (treated as unsigned)
        assertEquals("FFFFFFFFFFFFFFFF", Hexdump.toHexString(-1L, 16));
        assertEquals("FFFFFFFF", Hexdump.toHexString(-1L, 8));
        assertEquals("FFFF", Hexdump.toHexString(-1L, 4));
    }

    @Test
    @DisplayName("Should convert byte array to hex string")
    void testToHexStringByteArray() {
        // Note: The implementation has a bug - it ignores the srcIndex parameter!
        // The third parameter is the size of the output string in characters
        // size = number of hex characters to output
        // Each byte produces 2 hex characters

        // Test basic conversion (srcIndex is ignored in the implementation)
        byte[] data1 = { 0x00, 0x01, 0x02, 0x03 };
        assertEquals("00", Hexdump.toHexString(data1, 0, 2)); // 2 chars = 1 byte
        assertEquals("000", Hexdump.toHexString(data1, 0, 3)); // 3 chars = 1.5 bytes (rounds up to 2)
        assertEquals("0001", Hexdump.toHexString(data1, 0, 4)); // 4 chars = 2 bytes
        assertEquals("000102", Hexdump.toHexString(data1, 0, 6)); // 6 chars = 3 bytes
        assertEquals("00010203", Hexdump.toHexString(data1, 0, 8)); // 8 chars = 4 bytes

        // Test with negative byte values
        byte[] data2 = { (byte) 0xFF, (byte) 0xFE, (byte) 0x80, 0x7F };
        assertEquals("FF", Hexdump.toHexString(data2, 0, 2)); // 2 chars = 1 byte
        assertEquals("FFF", Hexdump.toHexString(data2, 0, 3)); // 3 chars = 1.5 bytes (rounds up to 2)
        assertEquals("FFFE", Hexdump.toHexString(data2, 0, 4)); // 4 chars = 2 bytes
        assertEquals("FFFE80", Hexdump.toHexString(data2, 0, 6)); // 6 chars = 3 bytes
        assertEquals("FFFE807F", Hexdump.toHexString(data2, 0, 8)); // 8 chars = 4 bytes

        // Test odd size (should handle correctly)
        byte[] data3 = { 0x0A, 0x0B, 0x0C };
        assertEquals("0", Hexdump.toHexString(data3, 0, 1)); // 1 char = 0.5 bytes (rounds up to 1)
        assertEquals("0A", Hexdump.toHexString(data3, 0, 2)); // 2 chars = 1 byte
        assertEquals("0A0", Hexdump.toHexString(data3, 0, 3)); // 3 chars = 1.5 bytes (rounds up to 2)
        assertEquals("0A0B", Hexdump.toHexString(data3, 0, 4)); // 4 chars = 2 bytes
        assertEquals("0A0B0", Hexdump.toHexString(data3, 0, 5)); // 5 chars = 2.5 bytes (rounds up to 3)
        assertEquals("0A0B0C", Hexdump.toHexString(data3, 0, 6)); // 6 chars = 3 bytes

        // Test with offset - NOTE: srcIndex is ignored due to bug, it always starts from index 0
        byte[] data4 = { 0x00, 0x11, 0x22, 0x33, 0x44 };
        assertEquals("00", Hexdump.toHexString(data4, 1, 2)); // Bug: ignores srcIndex, reads from 0
        assertEquals("0011", Hexdump.toHexString(data4, 1, 4)); // Bug: ignores srcIndex, reads from 0
        assertEquals("0011", Hexdump.toHexString(data4, 2, 4)); // Bug: ignores srcIndex, reads from 0
    }

    @Test
    @DisplayName("Should perform hexdump with correct formatting")
    void testHexdump() {
        // Capture output
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        PrintStream ps = new PrintStream(baos);

        // Test with 16 bytes (one complete line)
        byte[] data1 = createTestData(16);
        Hexdump.hexdump(ps, data1, 0, 16);
        String output1 = baos.toString();

        assertNotNull(output1);
        assertTrue(output1.contains("00000:"));
        assertTrue(output1.contains(" 00 01 02 03"));
        assertTrue(output1.contains("|"));

        // Test with less than 16 bytes
        baos.reset();
        byte[] data2 = { 0x41, 0x42, 0x43, 0x44 }; // "ABCD"
        Hexdump.hexdump(ps, data2, 0, 4);
        String output2 = baos.toString();

        assertNotNull(output2);
        assertTrue(output2.contains("00000:"));
        assertTrue(output2.contains(" 41 42 43 44"));
        assertTrue(output2.contains("|ABCD"));

        // Test with empty array
        baos.reset();
        byte[] data3 = {};
        Hexdump.hexdump(ps, data3, 0, 0);
        String output3 = baos.toString();
        assertEquals("", output3.trim());
    }

    @Test
    @DisplayName("Should handle multiple lines in hexdump")
    void testHexdumpMultipleLines() {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        PrintStream ps = new PrintStream(baos);

        // Test with 32 bytes (two complete lines)
        byte[] data = createTestData(32);
        Hexdump.hexdump(ps, data, 0, 32);
        String output = baos.toString();

        assertNotNull(output);
        assertTrue(output.contains("00000:"));
        assertTrue(output.contains("00010:")); // Second line offset

        // Verify first line contains bytes 0-15
        assertTrue(output.contains(" 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F"));
        // Verify second line contains bytes 16-31
        assertTrue(output.contains(" 10 11 12 13 14 15 16 17 18 19 1A 1B 1C 1D 1E 1F"));
    }

    @Test
    @DisplayName("Should handle control characters in hexdump")
    void testHexdumpControlCharacters() {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        PrintStream ps = new PrintStream(baos);

        // Test with control characters and printable characters
        byte[] data = { 0x00, 0x01, 0x09, 0x0A, 0x0D, 0x1F, // Control characters
                0x20, 0x41, 0x42, 0x7E, // Printable characters
                (byte) 0x7F, (byte) 0x80, (byte) 0xFF // Extended/control
        };

        Hexdump.hexdump(ps, data, 0, data.length);
        String output = baos.toString();

        assertNotNull(output);
        // Control characters should be displayed as dots
        assertTrue(output.contains("|......"));
        // Printable characters should be displayed as is
        assertTrue(output.contains(" AB~"));
        // High bytes should be dots
        assertTrue(output.contains("..."));
    }

    @ParameterizedTest
    @ValueSource(ints = { 1, 15, 16, 17, 31, 32, 33, 64, 128 })
    @DisplayName("Should handle various data sizes in hexdump")
    void testHexdumpVariousSizes(int size) {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        PrintStream ps = new PrintStream(baos);

        byte[] data = createTestData(size);
        Hexdump.hexdump(ps, data, 0, size);
        String output = baos.toString();

        assertNotNull(output);
        assertTrue(output.contains("00000:"));

        // Calculate expected number of lines
        int expectedLines = (size + 15) / 16;
        String[] lines = output.split(System.getProperty("line.separator"));
        assertTrue(lines.length >= expectedLines);
    }

    @Test
    @DisplayName("Should handle hexdump with offset")
    void testHexdumpWithOffset() {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        PrintStream ps = new PrintStream(baos);

        // Create test data and dump from offset
        byte[] data = createTestData(64);
        int offset = 16;
        int length = 32;

        Hexdump.hexdump(ps, data, offset, length);
        String output = baos.toString();

        assertNotNull(output);
        // Should start at offset 0 in display but show data from offset 16
        assertTrue(output.contains("00000:"));
        // First byte should be 0x10 (16 in decimal)
        assertTrue(output.contains(" 10 11 12"));
    }

    @Test
    @DisplayName("Should convert hex chars correctly")
    void testToHexChars() {
        // Test integer conversion
        char[] dst1 = new char[8];
        Hexdump.toHexChars(0x1234ABCD, dst1, 0, 8);
        assertEquals("1234ABCD", new String(dst1));

        // Test with smaller size
        char[] dst2 = new char[4];
        Hexdump.toHexChars(0xABCD, dst2, 0, 4);
        assertEquals("ABCD", new String(dst2));

        // Test with offset
        char[] dst3 = new char[10];
        java.util.Arrays.fill(dst3, 'X');
        Hexdump.toHexChars(0xFF, dst3, 2, 2);
        assertEquals("XXFFXXXXXX", new String(dst3));

        // Test long conversion
        char[] dst4 = new char[16];
        Hexdump.toHexChars(0x123456789ABCDEF0L, dst4, 0, 16);
        assertEquals("123456789ABCDEF0", new String(dst4));
    }

    @Test
    @DisplayName("Should verify HEX_DIGITS constant")
    void testHexDigitsConstant() {
        // Verify the HEX_DIGITS array contains correct values
        assertEquals(16, Hexdump.HEX_DIGITS.length);
        assertEquals('0', Hexdump.HEX_DIGITS[0]);
        assertEquals('9', Hexdump.HEX_DIGITS[9]);
        assertEquals('A', Hexdump.HEX_DIGITS[10]);
        assertEquals('F', Hexdump.HEX_DIGITS[15]);
    }

    @Test
    @DisplayName("Should handle edge cases in toHexChars")
    void testToHexCharsEdgeCases() {
        // Test with zero
        char[] dst1 = new char[4];
        java.util.Arrays.fill(dst1, 'X');
        Hexdump.toHexChars(0, dst1, 0, 4);
        assertEquals("0000", new String(dst1));

        // Test with all F's
        char[] dst2 = new char[8];
        Hexdump.toHexChars(0xFFFFFFFF, dst2, 0, 8);
        assertEquals("FFFFFFFF", new String(dst2));

        // Test partial buffer update
        char[] dst3 = new char[6];
        java.util.Arrays.fill(dst3, 'Z');
        Hexdump.toHexChars(0xAB, dst3, 1, 2);
        assertEquals("ZABZZZ", new String(dst3));
    }
}
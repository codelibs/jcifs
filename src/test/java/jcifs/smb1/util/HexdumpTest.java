/*
 * Test suite for the {@link jcifs.smb1.util.Hexdump} utility class.
 *
 * The test class exercises all public static members of Hexdump,
 * focusing on observable behavior rather than implementation details.
 *
 * Mockito is employed simply to assert that the method under test invokes
 * {@link java.io.PrintStream#println(char[])} with a correctly sized
 * character array representing the hexdump output.
 */

package jcifs.smb1.util;

import static org.junit.jupiter.api.Assertions.*;

import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.util.stream.IntStream;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Tests for {@link Hexdump}. Since the class contains only static
 * helper methods, Mockito is used to verify interaction with a mocked
 * {@link PrintStream}.
 */
@ExtendWith(MockitoExtension.class)
class HexdumpTest {

    /**
     * Helper to compute the expected destination array size used in the hexdump
     * method for a given source byte length.  This mirrors the private logic
     * in {@link Hexdump#hexdump}.
     */
    private static int expectedHexdumpArraySize(int len) {
        int s = len % 16;
        int r = (s == 0) ? len / 16 : len / 16 + 1;
        int nlLength = System.lineSeparator().length();
        return r * (74 + nlLength);
    }

    /* =========================================================== */
    /* 1) Tests for the :hexdump(PrintStream, byte[], int, int) method */
    /* =========================================================== */

    @Test
    @DisplayName("hexdump() should write nothing when length is zero")
    void hexdumpZeroLength() throws Exception {
        byte[] data = {0x01, 0x02, 0x03};
        // Capture output to byte array rather than using an actual stream.
        java.io.ByteArrayOutputStream bao = new java.io.ByteArrayOutputStream();
        java.io.PrintStream ps = new java.io.PrintStream(bao);
        Hexdump.hexdump(ps, data, 0, 0);
        assertEquals(0, bao.size(), "The stream should remain empty");
    }

    @ParameterizedTest(name = "hexdump() should call println with array size {0}")
    @CsvSource({
        "16,74",  // 16 bytes -> r=1, array size = 74 + NL_LENGTH
        "24,148"  // 24 bytes -> r=2, double the size
    })
    void hexdumpCallsPrintlnWithCorrectArrayLength(int byteLen, int expectedArraySize) throws Exception {
        byte[] data = new byte[byteLen]; // arbitrary bytes
        MockedPrintStream mockPs = new MockedPrintStream();
        MockedPrintStream ps = mockPs.getMock();
        Hexdump.hexdump(ps, data, 0, data.length);
        ArgumentCaptor<char[]> captor = ArgumentCaptor.forClass(char[].class);
        verify(ps).println(captor.capture());
        char[] actual = captor.getValue();
        assertEquals(expectedArraySize, actual.length, "println receives array of correct size");
    }

    @Test
    @DisplayName("hexdump() should throw ArrayIndexOutOfBounds when source index exceeds array bounds")
    void hexdumpOutOfBounds() {
        byte[] data = {1,2,3,4,5};
        assertThrows(ArrayIndexOutOfBoundsException.class,
            () -> Hexdump.hexdump(System.out, data, 4, 4));
    }

    @Test
    @DisplayName("hexdump() should throw NegativeArraySizeException for negative length")
    void hexdumpNegativeLength() {
        byte[] data = {1,2,3};
        assertThrows(NegativeArraySizeException.class,
            () -> Hexdump.hexdump(System.out, data, 0, -1));
    }

    /* =========================================================== */
    /* 2) Tests for the helper {@code toHexString} methods */
    /* =========================================================== */

    @ParameterizedTest(name = "toHexString(int, size={1}) -> {2}")
    @CsvSource({
        "0xABCD,4,ABCD",
        "0x0,2,00"
    })
    void toHexStringIntWorks(int val, int size, String expected) {
        assertEquals(expected, Hexdump.toHexString(val, size));
    }

    @ParameterizedTest(name = "toHexString(long, size={1}) -> {2}")
    @CsvSource({
        "0x1ABCDE,5,1ABCDE",
        "0xFF,2,FF"
    })
    void toHexStringLongWorks(long val, int size, String expected) {
        assertEquals(expected, Hexdump.toHexString(val, size));
    }

    @Test
    @DisplayName("toHexString(byte[]) produces a hex string of the correct even length based on requested size")
    void toHexStringByteArrayOddSize() {
        byte[] src = {(byte)0x12, (byte)0xAF, (byte)0x34}; // 3 bytes
        String hex = Hexdump.toHexString(src, 0, 3); // requested size 3 -> size becomes 2
        assertEquals("12AF", hex, "Only two bytes generate 4 hex characters");
    }

    /* =========================================================== */
    /* 3) Tests for the helper {@code toHexChars} methods */
    /* =========================================================== */

    @Test
    @DisplayName("toHexChars(int) writes the expected hex digits into the char array")
    void toHexCharsIntWorks() {
        char[] dst = new char[4];
        Hexdump.toHexChars(0xABCD, dst, 0, 4);
        assertEquals("ABCD", new String(dst));
    }

    @Test
    @DisplayName("toHexChars(long) writes the expected hex digits for long values")
    void toHexCharsLongWorks() {
        char[] dst = new char[8];
        Hexdump.toHexChars(0x12345678L, dst, 0, 8);
        assertEquals("12345678", new String(dst));
    }
}


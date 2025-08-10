package jcifs;

import static org.junit.jupiter.api.Assertions.*;

import java.util.Arrays;
import java.util.stream.Stream;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import jcifs.util.ByteEncodable;

@DisplayName("Encodable contract tests using ByteEncodable")
class EncodableTest {

    // Generates a few representative slices and destination indices.
    static Stream<Arguments> byteEncodableArgs() {
        return Stream.of(
            // srcLen, off, len, dstIndex
            Arguments.of(makeSeq(8), 0, 8, 0),   // full copy at index 0
            Arguments.of(makeSeq(10), 2, 5, 3),  // middle slice, non-zero dst index
            Arguments.of(makeSeq(4), 4, 0, 0),   // zero-length slice at end
            Arguments.of(makeSeq(16), 7, 3, 0),  // small slice from middle
            Arguments.of(makeSeq(16), 0, 0, 5)   // zero-length with non-zero dst index
        );
    }

    // Creates a deterministic byte sequence [0,1,2,...,n-1]
    private static byte[] makeSeq(int n) {
        byte[] a = new byte[n];
        for (int i = 0; i < n; i++) {
            a[i] = (byte) i;
        }
        return a;
    }

    @ParameterizedTest
    @MethodSource("byteEncodableArgs")
    @DisplayName("encode() copies bytes correctly and returns size")
    void encodeCopiesAndReportsSize(byte[] src, int off, int len, int dstIndex) {
        Encodable enc = new ByteEncodable(src, off, len);

        // Destination has guard space to verify non-overwritten regions.
        byte[] dst = new byte[dstIndex + len + 5];
        Arrays.fill(dst, (byte) 0x55);

        // Act
        int written = enc.encode(dst, dstIndex);

        // Assert: reported written bytes matches size() and requested len.
        assertEquals(len, enc.size(), "size() must equal provided length");
        assertEquals(len, written, "encode() must return number of bytes written");

        // Assert: copied region equals the source slice.
        for (int i = 0; i < len; i++) {
            assertEquals(src[off + i], dst[dstIndex + i], "Byte mismatch at " + i);
        }

        // Assert: bytes before and after region remain unchanged.
        for (int i = 0; i < dstIndex; i++) {
            assertEquals((byte) 0x55, dst[i], "Unexpected change before copy region at " + i);
        }
        for (int i = dstIndex + len; i < dst.length; i++) {
            assertEquals((byte) 0x55, dst[i], "Unexpected change after copy region at " + i);
        }
    }

    @Test
    @DisplayName("encode() with zero length does not modify destination")
    void encodeZeroLengthDoesNotModifyDestination() {
        byte[] src = makeSeq(10);
        Encodable enc = new ByteEncodable(src, 5, 0); // zero length
        byte[] dst = new byte[8];
        Arrays.fill(dst, (byte) 0x7A);

        int written = enc.encode(dst, 3);

        assertEquals(0, enc.size(), "size() must be zero");
        assertEquals(0, written, "encode() must return zero for zero length");
        for (byte b : dst) {
            assertEquals((byte) 0x7A, b, "Destination should remain unchanged");
        }
    }

    @Test
    @DisplayName("encode() throws when destination too small")
    void encodeThrowsWhenDestinationTooSmall() {
        byte[] src = makeSeq(5);
        Encodable enc = new ByteEncodable(src, 0, 5);
        byte[] dst = new byte[4]; // too small

        assertThrows(ArrayIndexOutOfBoundsException.class, () -> enc.encode(dst, 0),
            "System.arraycopy should throw for insufficient destination space");
    }

    @Test
    @DisplayName("encode() throws when dstIndex causes overflow")
    void encodeThrowsWhenDstIndexCausesOverflow() {
        byte[] src = makeSeq(5);
        Encodable enc = new ByteEncodable(src, 0, 5);
        byte[] dst = new byte[6]; // size is 6, but index 2 + len 5 -> overflow

        assertThrows(ArrayIndexOutOfBoundsException.class, () -> enc.encode(dst, 2),
            "System.arraycopy should throw when dstIndex + len exceeds dst length");
    }

    @Test
    @DisplayName("encode() throws when dstIndex is negative")
    void encodeThrowsWhenDstIndexNegative() {
        byte[] src = makeSeq(3);
        Encodable enc = new ByteEncodable(src, 0, 3);
        byte[] dst = new byte[3];

        assertThrows(ArrayIndexOutOfBoundsException.class, () -> enc.encode(dst, -1),
            "System.arraycopy should throw for negative dstIndex");
    }
}


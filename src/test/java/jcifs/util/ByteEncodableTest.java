package jcifs.util;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

class ByteEncodableTest {

    @Test
    void testConstructorAndSize() {
        // Test with a basic byte array
        byte[] data = { 0x01, 0x02, 0x03, 0x04, 0x05 };
        ByteEncodable encodable = new ByteEncodable(data, 1, 3);

        // Verify size
        assertEquals(3, encodable.size(), "Size should be equal to the specified length");
    }

    @Test
    void testEncodeBasic() {
        // Test basic encoding
        byte[] data = { 0x01, 0x02, 0x03, 0x04, 0x05 };
        ByteEncodable encodable = new ByteEncodable(data, 1, 3);
        byte[] dest = new byte[5];

        int encodedLen = encodable.encode(dest, 0);

        // Verify encoded length
        assertEquals(3, encodedLen, "Encoded length should be equal to the specified length");

        // Verify content
        assertArrayEquals(new byte[] { 0x02, 0x03, 0x04, 0x00, 0x00 }, dest, "Encoded bytes should match the expected subset");
    }

    @Test
    void testEncodeWithOffset() {
        // Test encoding with a destination offset
        byte[] data = { 0x01, 0x02, 0x03, 0x04, 0x05 };
        ByteEncodable encodable = new ByteEncodable(data, 0, 3);
        byte[] dest = new byte[5]; // {0,0,0,0,0}
        dest[0] = (byte) 0xFF; // Add some initial data to dest

        int encodedLen = encodable.encode(dest, 1);

        // Verify encoded length
        assertEquals(3, encodedLen, "Encoded length should be equal to the specified length");

        // Verify content
        assertArrayEquals(new byte[] { (byte) 0xFF, 0x01, 0x02, 0x03, 0x00 }, dest, "Encoded bytes should be placed at the correct offset");
    }

    @Test
    void testEncodeZeroLength() {
        // Test encoding with zero length
        byte[] data = { 0x01, 0x02, 0x03 };
        ByteEncodable encodable = new ByteEncodable(data, 0, 0);
        byte[] dest = new byte[3];

        int encodedLen = encodable.encode(dest, 0);

        // Verify encoded length
        assertEquals(0, encodedLen, "Encoded length should be zero for zero length encodable");
        assertArrayEquals(new byte[] { 0x00, 0x00, 0x00 }, dest, "Destination array should remain unchanged for zero length encoding");
    }

    @Test
    void testEncodeEmptySourceArray() {
        // Test with an empty source array
        byte[] data = {};
        ByteEncodable encodable = new ByteEncodable(data, 0, 0);
        byte[] dest = new byte[1];

        int encodedLen = encodable.encode(dest, 0);

        assertEquals(0, encodedLen, "Encoded length should be zero for empty source array");
        assertArrayEquals(new byte[] { 0x00 }, dest, "Destination array should remain unchanged for empty source array");
    }

    @Test
    void testEncodeSourceOffsetBeyondLength() {
        // Test with source offset + length exceeding source array bounds
        byte[] data = { 0x01, 0x02 };
        // This constructor call itself should not throw an error, as it's just storing the values.
        // The error should occur when System.arraycopy is called.
        ByteEncodable encodable = new ByteEncodable(data, 1, 2); // off=1, len=2, data.length=2. 1+2 > 2

        byte[] dest = new byte[5];

        // Expect IndexOutOfBoundsException from System.arraycopy
        assertThrows(IndexOutOfBoundsException.class, () -> {
            encodable.encode(dest, 0);
        }, "Should throw IndexOutOfBoundsException if source offset + length exceeds source array bounds");
    }

    @Test
    void testEncodeDestinationTooSmall() {
        // Test when destination array is too small
        byte[] data = { 0x01, 0x02, 0x03 };
        ByteEncodable encodable = new ByteEncodable(data, 0, 3);
        byte[] dest = new byte[2]; // Destination is too small

        // Expect IndexOutOfBoundsException from System.arraycopy
        assertThrows(IndexOutOfBoundsException.class, () -> {
            encodable.encode(dest, 0);
        }, "Should throw IndexOutOfBoundsException if destination array is too small");
    }

    @Test
    void testEncodeDestinationOffsetOutOfBounds() {
        // Test when destination offset is out of bounds
        byte[] data = { 0x01, 0x02, 0x03 };
        ByteEncodable encodable = new ByteEncodable(data, 0, 3);
        byte[] dest = new byte[5];

        // Expect IndexOutOfBoundsException from System.arraycopy
        assertThrows(IndexOutOfBoundsException.class, () -> {
            encodable.encode(dest, 3); // destIndex=3, len=3, dest.length=5. 3+3 > 5
        }, "Should throw IndexOutOfBoundsException if destination offset + length exceeds destination array bounds");
    }

    @Test
    void testEncodeNullSourceArray() {
        // Test with a null source array
        ByteEncodable encodable = new ByteEncodable(null, 0, 0);
        byte[] dest = new byte[1];

        // Expect NullPointerException from System.arraycopy
        assertThrows(NullPointerException.class, () -> {
            encodable.encode(dest, 0);
        }, "Should throw NullPointerException if source array is null");
    }

    @Test
    void testEncodeNullDestinationArray() {
        // Test with a null destination array
        byte[] data = { 0x01 };
        ByteEncodable encodable = new ByteEncodable(data, 0, 1);

        // Expect NullPointerException from System.arraycopy
        assertThrows(NullPointerException.class, () -> {
            encodable.encode(null, 0);
        }, "Should throw NullPointerException if destination array is null");
    }
}

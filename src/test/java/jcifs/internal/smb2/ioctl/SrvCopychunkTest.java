package jcifs.internal.smb2.ioctl;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

import jcifs.internal.util.SMBUtil;

class SrvCopychunkTest {

    private static final int EXPECTED_SIZE = 24;
    private static final int RESERVED_BYTES = 4;

    @Nested
    @DisplayName("Constructor Tests")
    class ConstructorTests {

        @Test
        @DisplayName("Should create instance with valid parameters")
        void testConstructorWithValidParameters() {
            // Given
            long sourceOffset = 1024L;
            long targetOffset = 2048L;
            int length = 4096;

            // When
            SrvCopychunk chunk = new SrvCopychunk(sourceOffset, targetOffset, length);

            // Then
            assertNotNull(chunk);
        }

        @ParameterizedTest
        @DisplayName("Should create instance with various offset values")
        @CsvSource({ "0, 0, 1024", "1024, 2048, 4096", "9223372036854775807, 9223372036854775807, 2147483647", // Max long values
                "-1, -1, -1", // Negative values (should still create instance)
                "0, 9223372036854775807, 0" // Edge cases
        })
        void testConstructorWithVariousValues(long sourceOffset, long targetOffset, int length) {
            // When
            SrvCopychunk chunk = new SrvCopychunk(sourceOffset, targetOffset, length);

            // Then
            assertNotNull(chunk);
        }
    }

    @Nested
    @DisplayName("Size Method Tests")
    class SizeTests {

        @Test
        @DisplayName("Should return correct size of 24 bytes")
        void testSize() {
            // Given
            SrvCopychunk chunk = new SrvCopychunk(0, 0, 0);

            // When
            int size = chunk.size();

            // Then
            assertEquals(EXPECTED_SIZE, size);
        }

        @ParameterizedTest
        @DisplayName("Should return same size regardless of values")
        @CsvSource({ "0, 0, 0", "1024, 2048, 4096", "9223372036854775807, 9223372036854775807, 2147483647", "-1, -1, -1" })
        void testSizeIsConstant(long sourceOffset, long targetOffset, int length) {
            // Given
            SrvCopychunk chunk = new SrvCopychunk(sourceOffset, targetOffset, length);

            // When
            int size = chunk.size();

            // Then
            assertEquals(EXPECTED_SIZE, size);
        }
    }

    @Nested
    @DisplayName("Encode Method Tests")
    class EncodeTests {

        private byte[] buffer;
        private int startIndex;

        @BeforeEach
        void setUp() {
            buffer = new byte[100];
            startIndex = 10;
        }

        @Test
        @DisplayName("Should encode basic values correctly")
        void testEncodeBasicValues() {
            // Given
            long sourceOffset = 1024L;
            long targetOffset = 2048L;
            int length = 4096;
            SrvCopychunk chunk = new SrvCopychunk(sourceOffset, targetOffset, length);

            // When
            int bytesWritten = chunk.encode(buffer, startIndex);

            // Then
            assertEquals(EXPECTED_SIZE, bytesWritten);

            // Verify source offset
            assertEquals(sourceOffset, SMBUtil.readInt8(buffer, startIndex));

            // Verify target offset
            assertEquals(targetOffset, SMBUtil.readInt8(buffer, startIndex + 8));

            // Verify length
            assertEquals(length, SMBUtil.readInt4(buffer, startIndex + 16));

            // Verify reserved bytes are zeros
            for (int i = 0; i < RESERVED_BYTES; i++) {
                assertEquals(0, buffer[startIndex + 20 + i]);
            }
        }

        @Test
        @DisplayName("Should encode zero values correctly")
        void testEncodeZeroValues() {
            // Given
            SrvCopychunk chunk = new SrvCopychunk(0, 0, 0);

            // When
            int bytesWritten = chunk.encode(buffer, startIndex);

            // Then
            assertEquals(EXPECTED_SIZE, bytesWritten);
            assertEquals(0L, SMBUtil.readInt8(buffer, startIndex));
            assertEquals(0L, SMBUtil.readInt8(buffer, startIndex + 8));
            assertEquals(0, SMBUtil.readInt4(buffer, startIndex + 16));
        }

        @Test
        @DisplayName("Should encode maximum values correctly")
        void testEncodeMaxValues() {
            // Given
            long maxLong = Long.MAX_VALUE;
            int maxInt = Integer.MAX_VALUE;
            SrvCopychunk chunk = new SrvCopychunk(maxLong, maxLong, maxInt);

            // When
            int bytesWritten = chunk.encode(buffer, startIndex);

            // Then
            assertEquals(EXPECTED_SIZE, bytesWritten);
            assertEquals(maxLong, SMBUtil.readInt8(buffer, startIndex));
            assertEquals(maxLong, SMBUtil.readInt8(buffer, startIndex + 8));
            assertEquals(maxInt, SMBUtil.readInt4(buffer, startIndex + 16));
        }

        @Test
        @DisplayName("Should encode negative values as unsigned")
        void testEncodeNegativeValues() {
            // Given
            long negativeOffset = -1L;
            int negativeLength = -1;
            SrvCopychunk chunk = new SrvCopychunk(negativeOffset, negativeOffset, negativeLength);

            // When
            int bytesWritten = chunk.encode(buffer, startIndex);

            // Then
            assertEquals(EXPECTED_SIZE, bytesWritten);
            // Negative values should be encoded as their unsigned representation
            assertEquals(negativeOffset, SMBUtil.readInt8(buffer, startIndex));
            assertEquals(negativeOffset, SMBUtil.readInt8(buffer, startIndex + 8));
            assertEquals(negativeLength, SMBUtil.readInt4(buffer, startIndex + 16));
        }

        @ParameterizedTest
        @DisplayName("Should encode at various buffer positions")
        @ValueSource(ints = { 0, 1, 10, 50, 70 })
        void testEncodeAtDifferentPositions(int position) {
            // Given
            byte[] largeBuffer = new byte[200];
            long sourceOffset = 12345L;
            long targetOffset = 67890L;
            int length = 99999;
            SrvCopychunk chunk = new SrvCopychunk(sourceOffset, targetOffset, length);

            // When
            int bytesWritten = chunk.encode(largeBuffer, position);

            // Then
            assertEquals(EXPECTED_SIZE, bytesWritten);
            assertEquals(sourceOffset, SMBUtil.readInt8(largeBuffer, position));
            assertEquals(targetOffset, SMBUtil.readInt8(largeBuffer, position + 8));
            assertEquals(length, SMBUtil.readInt4(largeBuffer, position + 16));
        }

        @Test
        @DisplayName("Should not modify buffer beyond encoded area")
        void testEncodeDoesNotModifyBeyondArea() {
            // Given
            byte testByte = (byte) 0xFF;
            java.util.Arrays.fill(buffer, testByte);
            SrvCopychunk chunk = new SrvCopychunk(1024, 2048, 4096);

            // When
            chunk.encode(buffer, startIndex);

            // Then
            // Check bytes before encoded area
            for (int i = 0; i < startIndex; i++) {
                assertEquals(testByte, buffer[i], "Byte at position " + i + " was modified");
            }

            // Check bytes after encoded area
            for (int i = startIndex + EXPECTED_SIZE; i < buffer.length; i++) {
                assertEquals(testByte, buffer[i], "Byte at position " + i + " was modified");
            }
        }

        @Test
        @DisplayName("Should handle encoding at buffer boundary")
        void testEncodeAtBufferBoundary() {
            // Given
            byte[] exactBuffer = new byte[EXPECTED_SIZE];
            SrvCopychunk chunk = new SrvCopychunk(999L, 888L, 777);

            // When
            int bytesWritten = chunk.encode(exactBuffer, 0);

            // Then
            assertEquals(EXPECTED_SIZE, bytesWritten);
            assertEquals(999L, SMBUtil.readInt8(exactBuffer, 0));
            assertEquals(888L, SMBUtil.readInt8(exactBuffer, 8));
            assertEquals(777, SMBUtil.readInt4(exactBuffer, 16));
        }
    }

    @Nested
    @DisplayName("Integration Tests")
    class IntegrationTests {

        @Test
        @DisplayName("Should encode and verify complete structure")
        void testCompleteEncodingStructure() {
            // Given
            long sourceOffset = 0x1234567890ABCDEFL;
            long targetOffset = 0xFEDCBA0987654321L;
            int length = 0x12345678;
            SrvCopychunk chunk = new SrvCopychunk(sourceOffset, targetOffset, length);
            byte[] buffer = new byte[EXPECTED_SIZE];

            // When
            int bytesWritten = chunk.encode(buffer, 0);

            // Then
            assertEquals(EXPECTED_SIZE, bytesWritten);
            assertEquals(chunk.size(), bytesWritten);

            // Verify complete structure
            assertEquals(sourceOffset, SMBUtil.readInt8(buffer, 0));
            assertEquals(targetOffset, SMBUtil.readInt8(buffer, 8));
            assertEquals(length, SMBUtil.readInt4(buffer, 16));

            // Verify reserved section is zero
            assertEquals(0, SMBUtil.readInt4(buffer, 20));
        }

        @Test
        @DisplayName("Should handle multiple sequential encodings")
        void testMultipleSequentialEncodings() {
            // Given
            SrvCopychunk chunk1 = new SrvCopychunk(100, 200, 300);
            SrvCopychunk chunk2 = new SrvCopychunk(400, 500, 600);
            SrvCopychunk chunk3 = new SrvCopychunk(700, 800, 900);
            byte[] buffer = new byte[EXPECTED_SIZE * 3];

            // When
            int offset1 = chunk1.encode(buffer, 0);
            int offset2 = chunk2.encode(buffer, offset1);
            int offset3 = chunk3.encode(buffer, offset1 + offset2);

            // Then
            assertEquals(EXPECTED_SIZE, offset1);
            assertEquals(EXPECTED_SIZE, offset2);
            assertEquals(EXPECTED_SIZE, offset3);

            // Verify first chunk
            assertEquals(100L, SMBUtil.readInt8(buffer, 0));
            assertEquals(200L, SMBUtil.readInt8(buffer, 8));
            assertEquals(300, SMBUtil.readInt4(buffer, 16));

            // Verify second chunk
            assertEquals(400L, SMBUtil.readInt8(buffer, EXPECTED_SIZE));
            assertEquals(500L, SMBUtil.readInt8(buffer, EXPECTED_SIZE + 8));
            assertEquals(600, SMBUtil.readInt4(buffer, EXPECTED_SIZE + 16));

            // Verify third chunk
            assertEquals(700L, SMBUtil.readInt8(buffer, EXPECTED_SIZE * 2));
            assertEquals(800L, SMBUtil.readInt8(buffer, EXPECTED_SIZE * 2 + 8));
            assertEquals(900, SMBUtil.readInt4(buffer, EXPECTED_SIZE * 2 + 16));
        }
    }

    @Nested
    @DisplayName("Edge Case Tests")
    class EdgeCaseTests {

        @Test
        @DisplayName("Should handle encoding with minimum buffer size")
        void testMinimumBufferSize() {
            // Given
            byte[] minBuffer = new byte[EXPECTED_SIZE];
            SrvCopychunk chunk = new SrvCopychunk(1, 2, 3);

            // When
            int bytesWritten = chunk.encode(minBuffer, 0);

            // Then
            assertEquals(EXPECTED_SIZE, bytesWritten);
            assertEquals(1L, SMBUtil.readInt8(minBuffer, 0));
            assertEquals(2L, SMBUtil.readInt8(minBuffer, 8));
            assertEquals(3, SMBUtil.readInt4(minBuffer, 16));
        }

        @Test
        @DisplayName("Should handle special offset patterns")
        void testSpecialOffsetPatterns() {
            // Given - alternating bit pattern
            long pattern1 = 0xAAAAAAAAAAAAAAAAL;
            long pattern2 = 0x5555555555555555L;
            int pattern3 = 0xDEADBEEF;
            SrvCopychunk chunk = new SrvCopychunk(pattern1, pattern2, pattern3);
            byte[] buffer = new byte[EXPECTED_SIZE];

            // When
            int bytesWritten = chunk.encode(buffer, 0);

            // Then
            assertEquals(EXPECTED_SIZE, bytesWritten);
            assertEquals(pattern1, SMBUtil.readInt8(buffer, 0));
            assertEquals(pattern2, SMBUtil.readInt8(buffer, 8));
            assertEquals(pattern3, SMBUtil.readInt4(buffer, 16));
        }
    }
}

/*
 * © 2025 Test Class for SrvCopychunkCopy
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
package jcifs.internal.smb2.ioctl;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import jcifs.internal.util.SMBUtil;
import java.util.Arrays;

class SrvCopychunkCopyTest {

    private static final int SOURCE_KEY_SIZE = 24;
    private static final int HEADER_SIZE = 32; // 24 bytes source key + 4 bytes chunk count + 4 bytes reserved
    private static final int CHUNK_SIZE = 24;

    @Mock
    private SrvCopychunk mockChunk;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    @Nested
    @DisplayName("Constructor Tests")
    class ConstructorTests {

        @Test
        @DisplayName("Should create instance with source key and single chunk")
        void testConstructorWithSingleChunk() {
            // Given
            byte[] sourceKey = new byte[SOURCE_KEY_SIZE];
            Arrays.fill(sourceKey, (byte) 0xAB);
            SrvCopychunk chunk = new SrvCopychunk(100, 200, 300);

            // When
            SrvCopychunkCopy copy = new SrvCopychunkCopy(sourceKey, chunk);

            // Then
            assertNotNull(copy);
        }

        @Test
        @DisplayName("Should create instance with source key and multiple chunks")
        void testConstructorWithMultipleChunks() {
            // Given
            byte[] sourceKey = new byte[SOURCE_KEY_SIZE];
            SrvCopychunk chunk1 = new SrvCopychunk(100, 200, 300);
            SrvCopychunk chunk2 = new SrvCopychunk(400, 500, 600);
            SrvCopychunk chunk3 = new SrvCopychunk(700, 800, 900);

            // When
            SrvCopychunkCopy copy = new SrvCopychunkCopy(sourceKey, chunk1, chunk2, chunk3);

            // Then
            assertNotNull(copy);
        }

        @Test
        @DisplayName("Should create instance with empty chunks array")
        void testConstructorWithEmptyChunks() {
            // Given
            byte[] sourceKey = new byte[SOURCE_KEY_SIZE];

            // When
            SrvCopychunkCopy copy = new SrvCopychunkCopy(sourceKey);

            // Then
            assertNotNull(copy);
        }

        @Test
        @DisplayName("Should accept various source key patterns")
        void testConstructorWithVariousSourceKeys() {
            // Given
            byte[] zeroKey = new byte[SOURCE_KEY_SIZE];
            byte[] maxKey = new byte[SOURCE_KEY_SIZE];
            Arrays.fill(maxKey, (byte) 0xFF);
            byte[] patternKey = new byte[SOURCE_KEY_SIZE];
            for (int i = 0; i < SOURCE_KEY_SIZE; i++) {
                patternKey[i] = (byte) i;
            }

            // When & Then
            assertNotNull(new SrvCopychunkCopy(zeroKey));
            assertNotNull(new SrvCopychunkCopy(maxKey));
            assertNotNull(new SrvCopychunkCopy(patternKey));
        }
    }

    @Nested
    @DisplayName("Size Method Tests")
    class SizeTests {

        @Test
        @DisplayName("Should return correct size with no chunks")
        void testSizeWithNoChunks() {
            // Given
            byte[] sourceKey = new byte[SOURCE_KEY_SIZE];
            SrvCopychunkCopy copy = new SrvCopychunkCopy(sourceKey);

            // When
            int size = copy.size();

            // Then
            assertEquals(HEADER_SIZE, size);
        }

        @Test
        @DisplayName("Should return correct size with single chunk")
        void testSizeWithSingleChunk() {
            // Given
            byte[] sourceKey = new byte[SOURCE_KEY_SIZE];
            SrvCopychunk chunk = new SrvCopychunk(0, 0, 0);
            SrvCopychunkCopy copy = new SrvCopychunkCopy(sourceKey, chunk);

            // When
            int size = copy.size();

            // Then
            assertEquals(HEADER_SIZE + CHUNK_SIZE, size);
        }

        @ParameterizedTest
        @DisplayName("Should return correct size with multiple chunks")
        @ValueSource(ints = {1, 2, 3, 5, 10, 100})
        void testSizeWithMultipleChunks(int chunkCount) {
            // Given
            byte[] sourceKey = new byte[SOURCE_KEY_SIZE];
            SrvCopychunk[] chunks = new SrvCopychunk[chunkCount];
            for (int i = 0; i < chunkCount; i++) {
                chunks[i] = new SrvCopychunk(i * 100, i * 200, i * 300);
            }
            SrvCopychunkCopy copy = new SrvCopychunkCopy(sourceKey, chunks);

            // When
            int size = copy.size();

            // Then
            assertEquals(HEADER_SIZE + (chunkCount * CHUNK_SIZE), size);
        }
    }

    @Nested
    @DisplayName("Encode Method Tests")
    class EncodeTests {

        private byte[] buffer;
        private int startIndex;
        private byte[] sourceKey;

        @BeforeEach
        void setUp() {
            buffer = new byte[500];
            startIndex = 10;
            sourceKey = new byte[SOURCE_KEY_SIZE];
            for (int i = 0; i < SOURCE_KEY_SIZE; i++) {
                sourceKey[i] = (byte) (i + 1);
            }
        }

        @Test
        @DisplayName("Should encode source key correctly")
        void testEncodeSourceKey() {
            // Given
            SrvCopychunkCopy copy = new SrvCopychunkCopy(sourceKey);

            // When
            int bytesWritten = copy.encode(buffer, startIndex);

            // Then
            assertEquals(HEADER_SIZE, bytesWritten);
            
            // Verify source key is copied correctly
            for (int i = 0; i < SOURCE_KEY_SIZE; i++) {
                assertEquals(sourceKey[i], buffer[startIndex + i], 
                    "Source key byte at position " + i + " doesn't match");
            }
        }

        @Test
        @DisplayName("Should encode chunk count correctly")
        void testEncodeChunkCount() {
            // Given
            SrvCopychunk chunk1 = new SrvCopychunk(100, 200, 300);
            SrvCopychunk chunk2 = new SrvCopychunk(400, 500, 600);
            SrvCopychunkCopy copy = new SrvCopychunkCopy(sourceKey, chunk1, chunk2);

            // When
            int bytesWritten = copy.encode(buffer, startIndex);

            // Then
            int chunkCount = SMBUtil.readInt4(buffer, startIndex + SOURCE_KEY_SIZE);
            assertEquals(2, chunkCount);
        }

        @Test
        @DisplayName("Should encode reserved bytes as zeros")
        void testEncodeReservedBytes() {
            // Given
            Arrays.fill(buffer, (byte) 0xFF); // Fill with non-zero to verify zeros are written
            SrvCopychunkCopy copy = new SrvCopychunkCopy(sourceKey);

            // When
            copy.encode(buffer, startIndex);

            // Then
            // Check reserved 4 bytes after chunk count
            for (int i = 0; i < 4; i++) {
                assertEquals(0, buffer[startIndex + SOURCE_KEY_SIZE + 4 + i],
                    "Reserved byte at position " + i + " should be zero");
            }
        }

        @Test
        @DisplayName("Should encode single chunk data correctly")
        void testEncodeSingleChunk() {
            // Given
            SrvCopychunk chunk = new SrvCopychunk(1024, 2048, 4096);
            SrvCopychunkCopy copy = new SrvCopychunkCopy(sourceKey, chunk);

            // When
            int bytesWritten = copy.encode(buffer, startIndex);

            // Then
            assertEquals(HEADER_SIZE + CHUNK_SIZE, bytesWritten);
            
            // Verify chunk data
            int chunkStart = startIndex + HEADER_SIZE;
            assertEquals(1024L, SMBUtil.readInt8(buffer, chunkStart));
            assertEquals(2048L, SMBUtil.readInt8(buffer, chunkStart + 8));
            assertEquals(4096, SMBUtil.readInt4(buffer, chunkStart + 16));
        }

        @Test
        @DisplayName("Should encode multiple chunks correctly")
        void testEncodeMultipleChunks() {
            // Given
            SrvCopychunk chunk1 = new SrvCopychunk(100, 200, 300);
            SrvCopychunk chunk2 = new SrvCopychunk(400, 500, 600);
            SrvCopychunk chunk3 = new SrvCopychunk(700, 800, 900);
            SrvCopychunkCopy copy = new SrvCopychunkCopy(sourceKey, chunk1, chunk2, chunk3);

            // When
            int bytesWritten = copy.encode(buffer, startIndex);

            // Then
            assertEquals(HEADER_SIZE + (3 * CHUNK_SIZE), bytesWritten);
            
            // Verify chunk count
            assertEquals(3, SMBUtil.readInt4(buffer, startIndex + SOURCE_KEY_SIZE));
            
            // Verify first chunk
            int chunkStart = startIndex + HEADER_SIZE;
            assertEquals(100L, SMBUtil.readInt8(buffer, chunkStart));
            assertEquals(200L, SMBUtil.readInt8(buffer, chunkStart + 8));
            assertEquals(300, SMBUtil.readInt4(buffer, chunkStart + 16));
            
            // Verify second chunk
            chunkStart += CHUNK_SIZE;
            assertEquals(400L, SMBUtil.readInt8(buffer, chunkStart));
            assertEquals(500L, SMBUtil.readInt8(buffer, chunkStart + 8));
            assertEquals(600, SMBUtil.readInt4(buffer, chunkStart + 16));
            
            // Verify third chunk
            chunkStart += CHUNK_SIZE;
            assertEquals(700L, SMBUtil.readInt8(buffer, chunkStart));
            assertEquals(800L, SMBUtil.readInt8(buffer, chunkStart + 8));
            assertEquals(900, SMBUtil.readInt4(buffer, chunkStart + 16));
        }

        @Test
        @DisplayName("Should not modify buffer beyond encoded area")
        void testEncodeDoesNotModifyBeyondArea() {
            // Given
            byte testByte = (byte) 0xEE;
            Arrays.fill(buffer, testByte);
            SrvCopychunk chunk = new SrvCopychunk(1, 2, 3);
            SrvCopychunkCopy copy = new SrvCopychunkCopy(sourceKey, chunk);
            int expectedSize = HEADER_SIZE + CHUNK_SIZE;

            // When
            copy.encode(buffer, startIndex);

            // Then
            // Check bytes before encoded area
            for (int i = 0; i < startIndex; i++) {
                assertEquals(testByte, buffer[i], "Byte at position " + i + " was modified");
            }
            
            // Check bytes after encoded area
            for (int i = startIndex + expectedSize; i < buffer.length; i++) {
                assertEquals(testByte, buffer[i], "Byte at position " + i + " was modified");
            }
        }

        @Test
        @DisplayName("Should encode at buffer boundary")
        void testEncodeAtBufferBoundary() {
            // Given
            SrvCopychunk chunk = new SrvCopychunk(111, 222, 333);
            SrvCopychunkCopy copy = new SrvCopychunkCopy(sourceKey, chunk);
            byte[] exactBuffer = new byte[HEADER_SIZE + CHUNK_SIZE];

            // When
            int bytesWritten = copy.encode(exactBuffer, 0);

            // Then
            assertEquals(HEADER_SIZE + CHUNK_SIZE, bytesWritten);
            
            // Verify source key
            for (int i = 0; i < SOURCE_KEY_SIZE; i++) {
                assertEquals(sourceKey[i], exactBuffer[i]);
            }
            
            // Verify chunk count
            assertEquals(1, SMBUtil.readInt4(exactBuffer, SOURCE_KEY_SIZE));
        }

        @ParameterizedTest
        @DisplayName("Should encode at various buffer positions")
        @ValueSource(ints = {0, 1, 10, 50, 100, 200})
        void testEncodeAtDifferentPositions(int position) {
            // Given
            byte[] largeBuffer = new byte[500];
            SrvCopychunk chunk = new SrvCopychunk(12345, 67890, 99999);
            SrvCopychunkCopy copy = new SrvCopychunkCopy(sourceKey, chunk);

            // When
            int bytesWritten = copy.encode(largeBuffer, position);

            // Then
            assertEquals(HEADER_SIZE + CHUNK_SIZE, bytesWritten);
            
            // Verify source key at correct position
            for (int i = 0; i < SOURCE_KEY_SIZE; i++) {
                assertEquals(sourceKey[i], largeBuffer[position + i]);
            }
            
            // Verify chunk count at correct position
            assertEquals(1, SMBUtil.readInt4(largeBuffer, position + SOURCE_KEY_SIZE));
        }

        @Test
        @DisplayName("Should encode with zero chunks correctly")
        void testEncodeWithZeroChunks() {
            // Given
            SrvCopychunkCopy copy = new SrvCopychunkCopy(sourceKey);

            // When
            int bytesWritten = copy.encode(buffer, startIndex);

            // Then
            assertEquals(HEADER_SIZE, bytesWritten);
            
            // Verify chunk count is zero
            assertEquals(0, SMBUtil.readInt4(buffer, startIndex + SOURCE_KEY_SIZE));
        }
    }

    @Nested
    @DisplayName("Integration Tests")
    class IntegrationTests {

        @Test
        @DisplayName("Should handle complete copy operation with multiple chunks")
        void testCompleteCopyOperation() {
            // Given
            byte[] sourceKey = new byte[SOURCE_KEY_SIZE];
            for (int i = 0; i < SOURCE_KEY_SIZE; i++) {
                sourceKey[i] = (byte) (0xA0 + i);
            }
            
            SrvCopychunk[] chunks = {
                new SrvCopychunk(0, 1024, 4096),
                new SrvCopychunk(4096, 5120, 8192),
                new SrvCopychunk(12288, 13312, 16384)
            };
            
            SrvCopychunkCopy copy = new SrvCopychunkCopy(sourceKey, chunks);
            byte[] buffer = new byte[200];

            // When
            int bytesWritten = copy.encode(buffer, 0);

            // Then
            assertEquals(copy.size(), bytesWritten);
            assertEquals(HEADER_SIZE + (3 * CHUNK_SIZE), bytesWritten);
            
            // Verify complete structure
            for (int i = 0; i < SOURCE_KEY_SIZE; i++) {
                assertEquals(sourceKey[i], buffer[i]);
            }
            assertEquals(3, SMBUtil.readInt4(buffer, SOURCE_KEY_SIZE));
            
            // Verify all chunks
            int offset = HEADER_SIZE;
            assertEquals(0L, SMBUtil.readInt8(buffer, offset));
            assertEquals(1024L, SMBUtil.readInt8(buffer, offset + 8));
            assertEquals(4096, SMBUtil.readInt4(buffer, offset + 16));
            
            offset += CHUNK_SIZE;
            assertEquals(4096L, SMBUtil.readInt8(buffer, offset));
            assertEquals(5120L, SMBUtil.readInt8(buffer, offset + 8));
            assertEquals(8192, SMBUtil.readInt4(buffer, offset + 16));
            
            offset += CHUNK_SIZE;
            assertEquals(12288L, SMBUtil.readInt8(buffer, offset));
            assertEquals(13312L, SMBUtil.readInt8(buffer, offset + 8));
            assertEquals(16384, SMBUtil.readInt4(buffer, offset + 16));
        }

        @Test
        @DisplayName("Should encode consistently with size method")
        void testEncodeSizeConsistency() {
            // Given
            byte[] sourceKey = new byte[SOURCE_KEY_SIZE];
            Arrays.fill(sourceKey, (byte) 0x55);
            
            SrvCopychunk[] testCases = {
                new SrvCopychunk(1, 2, 3),
                new SrvCopychunk(4, 5, 6),
                new SrvCopychunk(7, 8, 9),
                new SrvCopychunk(10, 11, 12),
                new SrvCopychunk(13, 14, 15)
            };
            
            for (int numChunks = 0; numChunks <= testCases.length; numChunks++) {
                // Create copy with varying number of chunks
                SrvCopychunk[] chunks = Arrays.copyOf(testCases, numChunks);
                SrvCopychunkCopy copy = new SrvCopychunkCopy(sourceKey, chunks);
                byte[] buffer = new byte[500];
                
                // When
                int expectedSize = copy.size();
                int actualEncoded = copy.encode(buffer, 0);
                
                // Then
                assertEquals(expectedSize, actualEncoded, 
                    "Size and encode methods return different values for " + numChunks + " chunks");
            }
        }

        @Test
        @DisplayName("Should handle large number of chunks")
        void testLargeNumberOfChunks() {
            // Given
            byte[] sourceKey = new byte[SOURCE_KEY_SIZE];
            int chunkCount = 50;
            SrvCopychunk[] chunks = new SrvCopychunk[chunkCount];
            
            for (int i = 0; i < chunkCount; i++) {
                chunks[i] = new SrvCopychunk(i * 1000L, i * 2000L, i * 100);
            }
            
            SrvCopychunkCopy copy = new SrvCopychunkCopy(sourceKey, chunks);
            byte[] buffer = new byte[HEADER_SIZE + (chunkCount * CHUNK_SIZE)];

            // When
            int bytesWritten = copy.encode(buffer, 0);

            // Then
            assertEquals(HEADER_SIZE + (chunkCount * CHUNK_SIZE), bytesWritten);
            assertEquals(chunkCount, SMBUtil.readInt4(buffer, SOURCE_KEY_SIZE));
            
            // Verify some chunks
            int offset = HEADER_SIZE;
            assertEquals(0L, SMBUtil.readInt8(buffer, offset));
            assertEquals(0L, SMBUtil.readInt8(buffer, offset + 8));
            assertEquals(0, SMBUtil.readInt4(buffer, offset + 16));
            
            offset = HEADER_SIZE + ((chunkCount - 1) * CHUNK_SIZE);
            assertEquals((chunkCount - 1) * 1000L, SMBUtil.readInt8(buffer, offset));
            assertEquals((chunkCount - 1) * 2000L, SMBUtil.readInt8(buffer, offset + 8));
            assertEquals((chunkCount - 1) * 100, SMBUtil.readInt4(buffer, offset + 16));
        }
    }

    @Nested
    @DisplayName("Edge Case Tests")
    class EdgeCaseTests {

        @Test
        @DisplayName("Should handle source key with all zeros")
        void testSourceKeyAllZeros() {
            // Given
            byte[] zeroKey = new byte[SOURCE_KEY_SIZE]; // All zeros by default
            SrvCopychunk chunk = new SrvCopychunk(1, 2, 3);
            SrvCopychunkCopy copy = new SrvCopychunkCopy(zeroKey, chunk);
            byte[] buffer = new byte[100];

            // When
            int bytesWritten = copy.encode(buffer, 0);

            // Then
            assertEquals(HEADER_SIZE + CHUNK_SIZE, bytesWritten);
            for (int i = 0; i < SOURCE_KEY_SIZE; i++) {
                assertEquals(0, buffer[i]);
            }
        }

        @Test
        @DisplayName("Should handle source key with all max values")
        void testSourceKeyAllMax() {
            // Given
            byte[] maxKey = new byte[SOURCE_KEY_SIZE];
            Arrays.fill(maxKey, (byte) 0xFF);
            SrvCopychunk chunk = new SrvCopychunk(Long.MAX_VALUE, Long.MAX_VALUE, Integer.MAX_VALUE);
            SrvCopychunkCopy copy = new SrvCopychunkCopy(maxKey, chunk);
            byte[] buffer = new byte[100];

            // When
            int bytesWritten = copy.encode(buffer, 0);

            // Then
            assertEquals(HEADER_SIZE + CHUNK_SIZE, bytesWritten);
            for (int i = 0; i < SOURCE_KEY_SIZE; i++) {
                assertEquals((byte) 0xFF, buffer[i]);
            }
            
            // Verify chunk with max values
            int chunkStart = HEADER_SIZE;
            assertEquals(Long.MAX_VALUE, SMBUtil.readInt8(buffer, chunkStart));
            assertEquals(Long.MAX_VALUE, SMBUtil.readInt8(buffer, chunkStart + 8));
            assertEquals(Integer.MAX_VALUE, SMBUtil.readInt4(buffer, chunkStart + 16));
        }

        @Test
        @DisplayName("Should handle alternating bit pattern in source key")
        void testSourceKeyAlternatingPattern() {
            // Given
            byte[] patternKey = new byte[SOURCE_KEY_SIZE];
            for (int i = 0; i < SOURCE_KEY_SIZE; i++) {
                patternKey[i] = (byte) ((i % 2 == 0) ? 0xAA : 0x55);
            }
            SrvCopychunkCopy copy = new SrvCopychunkCopy(patternKey);
            byte[] buffer = new byte[100];

            // When
            copy.encode(buffer, 0);

            // Then
            for (int i = 0; i < SOURCE_KEY_SIZE; i++) {
                byte expected = (byte) ((i % 2 == 0) ? 0xAA : 0x55);
                assertEquals(expected, buffer[i], "Pattern mismatch at position " + i);
            }
        }

        @Test
        @DisplayName("Should handle chunks with negative values")
        void testChunksWithNegativeValues() {
            // Given
            byte[] sourceKey = new byte[SOURCE_KEY_SIZE];
            SrvCopychunk chunk = new SrvCopychunk(-1L, -100L, -1);
            SrvCopychunkCopy copy = new SrvCopychunkCopy(sourceKey, chunk);
            byte[] buffer = new byte[100];

            // When
            int bytesWritten = copy.encode(buffer, 0);

            // Then
            assertEquals(HEADER_SIZE + CHUNK_SIZE, bytesWritten);
            
            // Negative values should be encoded as their unsigned representation
            int chunkStart = HEADER_SIZE;
            assertEquals(-1L, SMBUtil.readInt8(buffer, chunkStart));
            assertEquals(-100L, SMBUtil.readInt8(buffer, chunkStart + 8));
            assertEquals(-1, SMBUtil.readInt4(buffer, chunkStart + 16));
        }
    }

    @Nested
    @DisplayName("Mock Tests")
    class MockTests {

        @Test
        @DisplayName("Should call encode on each chunk")
        void testCallsEncodeOnEachChunk() {
            // Given
            byte[] sourceKey = new byte[SOURCE_KEY_SIZE];
            SrvCopychunk mockChunk1 = mock(SrvCopychunk.class);
            SrvCopychunk mockChunk2 = mock(SrvCopychunk.class);
            when(mockChunk1.encode(any(byte[].class), anyInt())).thenReturn(CHUNK_SIZE);
            when(mockChunk2.encode(any(byte[].class), anyInt())).thenReturn(CHUNK_SIZE);
            
            SrvCopychunkCopy copy = new SrvCopychunkCopy(sourceKey, mockChunk1, mockChunk2);
            byte[] buffer = new byte[200];

            // When
            copy.encode(buffer, 0);

            // Then
            verify(mockChunk1, times(1)).encode(eq(buffer), eq(HEADER_SIZE));
            verify(mockChunk2, times(1)).encode(eq(buffer), eq(HEADER_SIZE + CHUNK_SIZE));
        }

        @Test
        @DisplayName("Should accumulate encoded bytes from chunks")
        void testAccumulatesEncodedBytes() {
            // Given
            byte[] sourceKey = new byte[SOURCE_KEY_SIZE];
            SrvCopychunk mockChunk1 = mock(SrvCopychunk.class);
            SrvCopychunk mockChunk2 = mock(SrvCopychunk.class);
            SrvCopychunk mockChunk3 = mock(SrvCopychunk.class);
            
            // Simulate different encode return values
            when(mockChunk1.encode(any(byte[].class), anyInt())).thenReturn(20);
            when(mockChunk2.encode(any(byte[].class), anyInt())).thenReturn(24);
            when(mockChunk3.encode(any(byte[].class), anyInt())).thenReturn(22);
            
            SrvCopychunkCopy copy = new SrvCopychunkCopy(sourceKey, mockChunk1, mockChunk2, mockChunk3);
            byte[] buffer = new byte[200];

            // When
            int totalBytes = copy.encode(buffer, 0);

            // Then
            assertEquals(HEADER_SIZE + 20 + 24 + 22, totalBytes);
            verify(mockChunk1).encode(buffer, HEADER_SIZE);
            verify(mockChunk2).encode(buffer, HEADER_SIZE + 20);
            verify(mockChunk3).encode(buffer, HEADER_SIZE + 20 + 24);
        }
    }
}
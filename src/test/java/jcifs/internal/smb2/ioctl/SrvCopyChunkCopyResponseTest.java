/*
 * © 2025 Test Class for SrvCopyChunkCopyResponse
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
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import jcifs.internal.SMBProtocolDecodingException;
import jcifs.internal.util.SMBUtil;

@ExtendWith(MockitoExtension.class)
class SrvCopyChunkCopyResponseTest {

    private SrvCopyChunkCopyResponse response;

    @BeforeEach
    void setUp() {
        response = new SrvCopyChunkCopyResponse();
    }

    @Nested
    @DisplayName("Constructor Tests")
    class ConstructorTests {

        @Test
        @DisplayName("Should create response with default values")
        void testConstructor() {
            SrvCopyChunkCopyResponse copyResponse = new SrvCopyChunkCopyResponse();
            assertNotNull(copyResponse);
        }

        @Test
        @DisplayName("Should initialize chunksWritten to zero")
        void testInitialChunksWrittenValue() {
            assertEquals(0, response.getChunksWritten());
        }

        @Test
        @DisplayName("Should initialize chunkBytesWritten to zero")
        void testInitialChunkBytesWrittenValue() {
            assertEquals(0, response.getChunkBytesWritten());
        }

        @Test
        @DisplayName("Should initialize totalBytesWritten to zero")
        void testInitialTotalBytesWrittenValue() {
            assertEquals(0, response.getTotalBytesWritten());
        }
    }

    @Nested
    @DisplayName("Getter Tests")
    class GetterTests {

        @Test
        @DisplayName("Should get chunksWritten value")
        void testGetChunksWritten() {
            // Initial value should be 0
            assertEquals(0, response.getChunksWritten());
        }

        @Test
        @DisplayName("Should get chunkBytesWritten value")
        void testGetChunkBytesWritten() {
            // Initial value should be 0
            assertEquals(0, response.getChunkBytesWritten());
        }

        @Test
        @DisplayName("Should get totalBytesWritten value")
        void testGetTotalBytesWritten() {
            // Initial value should be 0
            assertEquals(0, response.getTotalBytesWritten());
        }
    }

    @Nested
    @DisplayName("Decode Tests")
    class DecodeTests {

        @Test
        @DisplayName("Should decode valid copy chunk response")
        void testDecodeValidResponse() throws SMBProtocolDecodingException {
            byte[] buffer = createValidCopyChunkResponse(5, 65536, 327680);
            
            int bytesDecoded = response.decode(buffer, 0, buffer.length);
            
            assertEquals(12, bytesDecoded); // 3 x 4 bytes = 12 bytes
            assertEquals(5, response.getChunksWritten());
            assertEquals(65536, response.getChunkBytesWritten());
            assertEquals(327680, response.getTotalBytesWritten());
        }

        @Test
        @DisplayName("Should decode at different buffer offset")
        void testDecodeWithOffset() throws SMBProtocolDecodingException {
            byte[] buffer = new byte[256];
            int offset = 100;
            byte[] responseData = createValidCopyChunkResponse(10, 131072, 1310720);
            System.arraycopy(responseData, 0, buffer, offset, responseData.length);
            
            int bytesDecoded = response.decode(buffer, offset, responseData.length);
            
            assertEquals(12, bytesDecoded);
            assertEquals(10, response.getChunksWritten());
            assertEquals(131072, response.getChunkBytesWritten());
            assertEquals(1310720, response.getTotalBytesWritten());
        }

        @ParameterizedTest
        @DisplayName("Should decode various chunksWritten values")
        @ValueSource(ints = {0, 1, 10, 100, 1000, Integer.MAX_VALUE})
        void testDecodeVariousChunksWritten(int chunks) throws SMBProtocolDecodingException {
            byte[] buffer = createValidCopyChunkResponse(chunks, 0, 0);
            
            int bytesDecoded = response.decode(buffer, 0, buffer.length);
            
            assertEquals(12, bytesDecoded);
            assertEquals(chunks, response.getChunksWritten());
        }

        @ParameterizedTest
        @DisplayName("Should decode various chunkBytesWritten values")
        @ValueSource(ints = {0, 1, 1024, 65536, 1048576, Integer.MAX_VALUE})
        void testDecodeVariousChunkBytesWritten(int chunkBytes) throws SMBProtocolDecodingException {
            byte[] buffer = createValidCopyChunkResponse(0, chunkBytes, 0);
            
            int bytesDecoded = response.decode(buffer, 0, buffer.length);
            
            assertEquals(12, bytesDecoded);
            assertEquals(chunkBytes, response.getChunkBytesWritten());
        }

        @ParameterizedTest
        @DisplayName("Should decode various totalBytesWritten values")
        @ValueSource(ints = {0, 1, 1024, 65536, 1048576, Integer.MAX_VALUE})
        void testDecodeVariousTotalBytesWritten(int totalBytes) throws SMBProtocolDecodingException {
            byte[] buffer = createValidCopyChunkResponse(0, 0, totalBytes);
            
            int bytesDecoded = response.decode(buffer, 0, buffer.length);
            
            assertEquals(12, bytesDecoded);
            assertEquals(totalBytes, response.getTotalBytesWritten());
        }

        @ParameterizedTest
        @DisplayName("Should decode combinations of values")
        @CsvSource({
            "0, 0, 0",
            "1, 65536, 65536",
            "2, 65536, 131072",
            "5, 131072, 655360",
            "10, 1048576, 10485760",
            "100, 65536, 6553600",
            "1000, 4096, 4096000"
        })
        void testDecodeCombinations(int chunks, int chunkBytes, int totalBytes) throws SMBProtocolDecodingException {
            byte[] buffer = createValidCopyChunkResponse(chunks, chunkBytes, totalBytes);
            
            int bytesDecoded = response.decode(buffer, 0, buffer.length);
            
            assertEquals(12, bytesDecoded);
            assertEquals(chunks, response.getChunksWritten());
            assertEquals(chunkBytes, response.getChunkBytesWritten());
            assertEquals(totalBytes, response.getTotalBytesWritten());
        }

        @Test
        @DisplayName("Should decode zero values")
        void testDecodeZeroValues() throws SMBProtocolDecodingException {
            byte[] buffer = createValidCopyChunkResponse(0, 0, 0);
            
            int bytesDecoded = response.decode(buffer, 0, buffer.length);
            
            assertEquals(12, bytesDecoded);
            assertEquals(0, response.getChunksWritten());
            assertEquals(0, response.getChunkBytesWritten());
            assertEquals(0, response.getTotalBytesWritten());
        }

        @Test
        @DisplayName("Should handle negative values as unsigned")
        void testDecodeNegativeValuesAsUnsigned() throws SMBProtocolDecodingException {
            byte[] buffer = new byte[12];
            SMBUtil.writeInt4(-1, buffer, 0); // chunksWritten
            SMBUtil.writeInt4(-2, buffer, 4); // chunkBytesWritten
            SMBUtil.writeInt4(-3, buffer, 8); // totalBytesWritten
            
            int bytesDecoded = response.decode(buffer, 0, buffer.length);
            
            assertEquals(12, bytesDecoded);
            assertEquals(-1, response.getChunksWritten());
            assertEquals(-2, response.getChunkBytesWritten());
            assertEquals(-3, response.getTotalBytesWritten());
        }

        @ParameterizedTest
        @DisplayName("Should decode at various offsets")
        @ValueSource(ints = {0, 10, 50, 100, 200})
        void testDecodeAtVariousOffsets(int offset) throws SMBProtocolDecodingException {
            byte[] buffer = new byte[512];
            byte[] responseData = createValidCopyChunkResponse(7, 8192, 57344);
            System.arraycopy(responseData, 0, buffer, offset, responseData.length);
            
            SrvCopyChunkCopyResponse localResponse = new SrvCopyChunkCopyResponse();
            int bytesDecoded = localResponse.decode(buffer, offset, responseData.length);
            
            assertEquals(12, bytesDecoded);
            assertEquals(7, localResponse.getChunksWritten());
            assertEquals(8192, localResponse.getChunkBytesWritten());
            assertEquals(57344, localResponse.getTotalBytesWritten());
        }

        @Test
        @DisplayName("Should decode minimum buffer size")
        void testDecodeMinimumBufferSize() throws SMBProtocolDecodingException {
            byte[] buffer = new byte[12]; // Exact size needed
            SMBUtil.writeInt4(3, buffer, 0);
            SMBUtil.writeInt4(4096, buffer, 4);
            SMBUtil.writeInt4(12288, buffer, 8);
            
            int bytesDecoded = response.decode(buffer, 0, buffer.length);
            
            assertEquals(12, bytesDecoded);
            assertEquals(3, response.getChunksWritten());
            assertEquals(4096, response.getChunkBytesWritten());
            assertEquals(12288, response.getTotalBytesWritten());
        }

        @Test
        @DisplayName("Should return correct bytes consumed")
        void testReturnBytesConsumed() throws SMBProtocolDecodingException {
            byte[] buffer = new byte[100];
            byte[] responseData = createValidCopyChunkResponse(8, 16384, 131072);
            System.arraycopy(responseData, 0, buffer, 20, responseData.length);
            
            int bytesDecoded = response.decode(buffer, 20, 80);
            
            // Should always return 12 bytes (3 x int4)
            assertEquals(12, bytesDecoded);
            assertEquals(8, response.getChunksWritten());
            assertEquals(16384, response.getChunkBytesWritten());
            assertEquals(131072, response.getTotalBytesWritten());
        }

        private byte[] createValidCopyChunkResponse(int chunks, int chunkBytes, int totalBytes) {
            byte[] buffer = new byte[12];
            SMBUtil.writeInt4(chunks, buffer, 0);
            SMBUtil.writeInt4(chunkBytes, buffer, 4);
            SMBUtil.writeInt4(totalBytes, buffer, 8);
            return buffer;
        }
    }

    @Nested
    @DisplayName("Integration Tests")
    class IntegrationTests {

        @Test
        @DisplayName("Should maintain state after multiple decodes")
        void testMultipleDecodes() throws SMBProtocolDecodingException {
            // First decode
            byte[] buffer1 = createValidCopyChunkResponse(1, 1024, 1024);
            response.decode(buffer1, 0, buffer1.length);
            assertEquals(1, response.getChunksWritten());
            assertEquals(1024, response.getChunkBytesWritten());
            assertEquals(1024, response.getTotalBytesWritten());
            
            // Second decode - should update values
            byte[] buffer2 = createValidCopyChunkResponse(5, 8192, 40960);
            response.decode(buffer2, 0, buffer2.length);
            assertEquals(5, response.getChunksWritten());
            assertEquals(8192, response.getChunkBytesWritten());
            assertEquals(40960, response.getTotalBytesWritten());
        }

        @Test
        @DisplayName("Should work with real-world values")
        void testRealWorldValues() throws SMBProtocolDecodingException {
            // Typical server response after copying chunks
            byte[] buffer = createValidCopyChunkResponse(
                16,      // 16 chunks written
                1048576, // 1MB per chunk
                16777216 // 16MB total
            );
            
            int bytesDecoded = response.decode(buffer, 0, buffer.length);
            
            assertEquals(12, bytesDecoded);
            assertEquals(16, response.getChunksWritten());
            assertEquals(1048576, response.getChunkBytesWritten());
            assertEquals(16777216, response.getTotalBytesWritten());
        }

        @Test
        @DisplayName("Should handle server-side copy response")
        void testServerSideCopyResponse() throws SMBProtocolDecodingException {
            // Simulate a server-side copy operation response
            byte[] buffer = createValidCopyChunkResponse(32, 262144, 8388608);
            
            int bytesDecoded = response.decode(buffer, 0, buffer.length);
            
            assertEquals(12, bytesDecoded);
            assertEquals(32, response.getChunksWritten());
            assertEquals(262144, response.getChunkBytesWritten()); // 256KB chunks
            assertEquals(8388608, response.getTotalBytesWritten()); // 8MB total
        }

        @Test
        @DisplayName("Should create multiple independent instances")
        void testMultipleInstances() throws SMBProtocolDecodingException {
            SrvCopyChunkCopyResponse response1 = new SrvCopyChunkCopyResponse();
            SrvCopyChunkCopyResponse response2 = new SrvCopyChunkCopyResponse();
            
            byte[] buffer1 = createValidCopyChunkResponse(10, 4096, 40960);
            byte[] buffer2 = createValidCopyChunkResponse(20, 8192, 163840);
            
            response1.decode(buffer1, 0, buffer1.length);
            response2.decode(buffer2, 0, buffer2.length);
            
            // Each instance should maintain its own state
            assertEquals(10, response1.getChunksWritten());
            assertEquals(4096, response1.getChunkBytesWritten());
            assertEquals(40960, response1.getTotalBytesWritten());
            
            assertEquals(20, response2.getChunksWritten());
            assertEquals(8192, response2.getChunkBytesWritten());
            assertEquals(163840, response2.getTotalBytesWritten());
        }

        private byte[] createValidCopyChunkResponse(int chunks, int chunkBytes, int totalBytes) {
            byte[] buffer = new byte[12];
            SMBUtil.writeInt4(chunks, buffer, 0);
            SMBUtil.writeInt4(chunkBytes, buffer, 4);
            SMBUtil.writeInt4(totalBytes, buffer, 8);
            return buffer;
        }
    }

    @Nested
    @DisplayName("Edge Case Tests")
    class EdgeCaseTests {

        @Test
        @DisplayName("Should handle maximum values")
        void testMaximumValues() throws SMBProtocolDecodingException {
            byte[] buffer = createValidCopyChunkResponse(
                Integer.MAX_VALUE,
                Integer.MAX_VALUE,
                Integer.MAX_VALUE
            );
            
            int bytesDecoded = response.decode(buffer, 0, buffer.length);
            
            assertEquals(12, bytesDecoded);
            assertEquals(Integer.MAX_VALUE, response.getChunksWritten());
            assertEquals(Integer.MAX_VALUE, response.getChunkBytesWritten());
            assertEquals(Integer.MAX_VALUE, response.getTotalBytesWritten());
        }

        @Test
        @DisplayName("Should handle partial copy operations")
        void testPartialCopyOperation() throws SMBProtocolDecodingException {
            // Simulate partial copy where not all requested bytes were copied
            byte[] buffer = createValidCopyChunkResponse(
                3,      // Only 3 chunks written (maybe less than requested)
                65536,  // 64KB per chunk
                196608  // 192KB total (3 * 64KB)
            );
            
            int bytesDecoded = response.decode(buffer, 0, buffer.length);
            
            assertEquals(12, bytesDecoded);
            assertEquals(3, response.getChunksWritten());
            assertEquals(65536, response.getChunkBytesWritten());
            assertEquals(196608, response.getTotalBytesWritten());
        }

        @Test
        @DisplayName("Should handle failed copy operation")
        void testFailedCopyOperation() throws SMBProtocolDecodingException {
            // Simulate failed copy where no chunks were written
            byte[] buffer = createValidCopyChunkResponse(0, 0, 0);
            
            int bytesDecoded = response.decode(buffer, 0, buffer.length);
            
            assertEquals(12, bytesDecoded);
            assertEquals(0, response.getChunksWritten());
            assertEquals(0, response.getChunkBytesWritten());
            assertEquals(0, response.getTotalBytesWritten());
        }

        @Test
        @DisplayName("Should decode with exact buffer length")
        void testExactBufferLength() throws SMBProtocolDecodingException {
            byte[] buffer = new byte[12];
            SMBUtil.writeInt4(50, buffer, 0);
            SMBUtil.writeInt4(32768, buffer, 4);
            SMBUtil.writeInt4(1638400, buffer, 8);
            
            int bytesDecoded = response.decode(buffer, 0, 12);
            
            assertEquals(12, bytesDecoded);
            assertEquals(50, response.getChunksWritten());
            assertEquals(32768, response.getChunkBytesWritten());
            assertEquals(1638400, response.getTotalBytesWritten());
        }

        @Test
        @DisplayName("Should handle buffer with extra data")
        void testBufferWithExtraData() throws SMBProtocolDecodingException {
            byte[] buffer = new byte[100];
            // Write valid response data
            SMBUtil.writeInt4(15, buffer, 0);
            SMBUtil.writeInt4(16384, buffer, 4);
            SMBUtil.writeInt4(245760, buffer, 8);
            // Fill rest with random data
            for (int i = 12; i < buffer.length; i++) {
                buffer[i] = (byte) (i % 256);
            }
            
            int bytesDecoded = response.decode(buffer, 0, buffer.length);
            
            // Should only consume 12 bytes
            assertEquals(12, bytesDecoded);
            assertEquals(15, response.getChunksWritten());
            assertEquals(16384, response.getChunkBytesWritten());
            assertEquals(245760, response.getTotalBytesWritten());
        }

        private byte[] createValidCopyChunkResponse(int chunks, int chunkBytes, int totalBytes) {
            byte[] buffer = new byte[12];
            SMBUtil.writeInt4(chunks, buffer, 0);
            SMBUtil.writeInt4(chunkBytes, buffer, 4);
            SMBUtil.writeInt4(totalBytes, buffer, 8);
            return buffer;
        }
    }

    @Nested
    @DisplayName("Boundary Tests")
    class BoundaryTests {

        @Test
        @DisplayName("Should handle single chunk copy")
        void testSingleChunkCopy() throws SMBProtocolDecodingException {
            byte[] buffer = createValidCopyChunkResponse(1, 4096, 4096);
            
            int bytesDecoded = response.decode(buffer, 0, buffer.length);
            
            assertEquals(12, bytesDecoded);
            assertEquals(1, response.getChunksWritten());
            assertEquals(4096, response.getChunkBytesWritten());
            assertEquals(4096, response.getTotalBytesWritten());
        }

        @Test
        @DisplayName("Should handle mismatched chunk and total bytes")
        void testMismatchedValues() throws SMBProtocolDecodingException {
            // This could happen if the last chunk is smaller
            byte[] buffer = createValidCopyChunkResponse(
                10,     // 10 chunks
                65536,  // Last chunk size (not average)
                589824  // Total less than 10 * 65536
            );
            
            int bytesDecoded = response.decode(buffer, 0, buffer.length);
            
            assertEquals(12, bytesDecoded);
            assertEquals(10, response.getChunksWritten());
            assertEquals(65536, response.getChunkBytesWritten());
            assertEquals(589824, response.getTotalBytesWritten());
        }

        @Test
        @DisplayName("Should handle power of 2 values")
        void testPowerOfTwoValues() throws SMBProtocolDecodingException {
            byte[] buffer = createValidCopyChunkResponse(
                64,       // 2^6 chunks
                1048576,  // 2^20 bytes (1MB)
                67108864  // 2^26 bytes (64MB)
            );
            
            int bytesDecoded = response.decode(buffer, 0, buffer.length);
            
            assertEquals(12, bytesDecoded);
            assertEquals(64, response.getChunksWritten());
            assertEquals(1048576, response.getChunkBytesWritten());
            assertEquals(67108864, response.getTotalBytesWritten());
        }

        private byte[] createValidCopyChunkResponse(int chunks, int chunkBytes, int totalBytes) {
            byte[] buffer = new byte[12];
            SMBUtil.writeInt4(chunks, buffer, 0);
            SMBUtil.writeInt4(chunkBytes, buffer, 4);
            SMBUtil.writeInt4(totalBytes, buffer, 8);
            return buffer;
        }
    }
}
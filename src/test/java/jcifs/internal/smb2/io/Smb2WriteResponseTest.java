package jcifs.internal.smb2.io;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import jcifs.Configuration;
import jcifs.internal.SMBProtocolDecodingException;
import jcifs.internal.smb2.ServerMessageBlock2;
import jcifs.internal.util.SMBUtil;

class Smb2WriteResponseTest {

    @Mock
    private Configuration mockConfig;

    private Smb2WriteResponse response;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        response = new Smb2WriteResponse(mockConfig);
    }

    @Nested
    @DisplayName("Constructor Tests")
    class ConstructorTests {

        @Test
        @DisplayName("Should create response with configuration")
        void testConstructor() {
            Smb2WriteResponse writeResponse = new Smb2WriteResponse(mockConfig);
            assertNotNull(writeResponse);
            // Note: getConfig() is protected, cannot test directly
        }

        @Test
        @DisplayName("Should initialize count to zero")
        void testInitialCountValue() {
            assertEquals(0, response.getCount());
        }

        @Test
        @DisplayName("Should initialize remaining to zero")
        void testInitialRemainingValue() {
            assertEquals(0, response.getRemaining());
        }
    }

    @Nested
    @DisplayName("Getter Tests")
    class GetterTests {

        @Test
        @DisplayName("Should get count value")
        void testGetCount() {
            // Initial value should be 0
            assertEquals(0, response.getCount());
        }

        @Test
        @DisplayName("Should get remaining value")
        void testGetRemaining() {
            // Initial value should be 0
            assertEquals(0, response.getRemaining());
        }
    }

    @Nested
    @DisplayName("WriteBytesWireFormat Tests")
    class WriteBytesWireFormatTests {

        @Test
        @DisplayName("Should always return 0 for writeBytesWireFormat")
        void testWriteBytesWireFormat() {
            byte[] buffer = new byte[1024];
            int result = response.writeBytesWireFormat(buffer, 0);
            assertEquals(0, result);
        }

        @Test
        @DisplayName("Should return 0 regardless of buffer position")
        void testWriteBytesWireFormatDifferentPosition() {
            byte[] buffer = new byte[1024];
            int result = response.writeBytesWireFormat(buffer, 100);
            assertEquals(0, result);
        }

        @Test
        @DisplayName("Should return 0 with empty buffer")
        void testWriteBytesWireFormatEmptyBuffer() {
            byte[] buffer = new byte[0];
            int result = response.writeBytesWireFormat(buffer, 0);
            assertEquals(0, result);
        }
    }

    @Nested
    @DisplayName("ReadBytesWireFormat Tests")
    class ReadBytesWireFormatTests {

        @Test
        @DisplayName("Should read valid write response")
        void testReadValidWriteResponse() throws SMBProtocolDecodingException {
            byte[] buffer = createValidWriteResponse(1024, 512);

            int bytesRead = response.readBytesWireFormat(buffer, 0);

            assertEquals(16, bytesRead); // Structure size + reserved (4) + count (4) + remaining (4) + channel info (4)
            assertEquals(1024, response.getCount());
            assertEquals(512, response.getRemaining());
        }

        @Test
        @DisplayName("Should throw exception for invalid structure size")
        void testInvalidStructureSize() {
            byte[] buffer = new byte[64];
            SMBUtil.writeInt2(16, buffer, 0); // Wrong structure size (should be 17)

            assertThrows(SMBProtocolDecodingException.class, () -> {
                response.readBytesWireFormat(buffer, 0);
            }, "Expected structureSize = 17");
        }

        @ParameterizedTest
        @DisplayName("Should read various count values")
        @ValueSource(ints = { 0, 1, 100, 1024, 65536, Integer.MAX_VALUE })
        void testReadVariousCountValues(int count) throws SMBProtocolDecodingException {
            byte[] buffer = createValidWriteResponse(count, 0);

            int bytesRead = response.readBytesWireFormat(buffer, 0);

            assertEquals(16, bytesRead);
            assertEquals(count, response.getCount());
        }

        @ParameterizedTest
        @DisplayName("Should read various remaining values")
        @ValueSource(ints = { 0, 1, 100, 1024, 65536, Integer.MAX_VALUE })
        void testReadVariousRemainingValues(int remaining) throws SMBProtocolDecodingException {
            byte[] buffer = createValidWriteResponse(0, remaining);

            int bytesRead = response.readBytesWireFormat(buffer, 0);

            assertEquals(16, bytesRead);
            assertEquals(remaining, response.getRemaining());
        }

        @ParameterizedTest
        @DisplayName("Should read response at various buffer offsets")
        @ValueSource(ints = { 0, 10, 100, 500 })
        void testReadAtDifferentOffsets(int offset) throws SMBProtocolDecodingException {
            byte[] buffer = new byte[1024];
            byte[] responseData = createValidWriteResponse(2048, 1024);
            System.arraycopy(responseData, 0, buffer, offset, responseData.length);

            int bytesRead = response.readBytesWireFormat(buffer, offset);

            assertEquals(16, bytesRead);
            assertEquals(2048, response.getCount());
            assertEquals(1024, response.getRemaining());
        }

        @Test
        @DisplayName("Should handle zero count and remaining")
        void testReadZeroValues() throws SMBProtocolDecodingException {
            byte[] buffer = createValidWriteResponse(0, 0);

            int bytesRead = response.readBytesWireFormat(buffer, 0);

            assertEquals(16, bytesRead);
            assertEquals(0, response.getCount());
            assertEquals(0, response.getRemaining());
        }

        @Test
        @DisplayName("Should ignore WriteChannelInfo fields")
        void testIgnoreWriteChannelInfo() throws SMBProtocolDecodingException {
            byte[] buffer = new byte[64];
            SMBUtil.writeInt2(17, buffer, 0); // Structure size
            SMBUtil.writeInt2(0, buffer, 2); // Reserved
            SMBUtil.writeInt4(4096, buffer, 4); // Count
            SMBUtil.writeInt4(2048, buffer, 8); // Remaining
            SMBUtil.writeInt2(100, buffer, 12); // WriteChannelInfoOffset (ignored)
            SMBUtil.writeInt2(200, buffer, 14); // WriteChannelInfoLength (ignored)

            int bytesRead = response.readBytesWireFormat(buffer, 0);

            assertEquals(16, bytesRead);
            assertEquals(4096, response.getCount());
            assertEquals(2048, response.getRemaining());
        }

        @ParameterizedTest
        @DisplayName("Should read count and remaining combinations")
        @CsvSource({ "0, 0", "512, 512", "1024, 0", "0, 1024", "4096, 8192", "65536, 131072", "1048576, 2097152" })
        void testReadCountAndRemainingCombinations(int count, int remaining) throws SMBProtocolDecodingException {
            byte[] buffer = createValidWriteResponse(count, remaining);

            int bytesRead = response.readBytesWireFormat(buffer, 0);

            assertEquals(16, bytesRead);
            assertEquals(count, response.getCount());
            assertEquals(remaining, response.getRemaining());
        }

        @Test
        @DisplayName("Should handle maximum integer values")
        void testMaximumValues() throws SMBProtocolDecodingException {
            byte[] buffer = createValidWriteResponse(Integer.MAX_VALUE, Integer.MAX_VALUE);

            int bytesRead = response.readBytesWireFormat(buffer, 0);

            assertEquals(16, bytesRead);
            assertEquals(Integer.MAX_VALUE, response.getCount());
            assertEquals(Integer.MAX_VALUE, response.getRemaining());
        }

        @Test
        @DisplayName("Should handle negative values as unsigned")
        void testNegativeValuesAsUnsigned() throws SMBProtocolDecodingException {
            byte[] buffer = new byte[64];
            SMBUtil.writeInt2(17, buffer, 0); // Structure size
            SMBUtil.writeInt2(0, buffer, 2); // Reserved
            SMBUtil.writeInt4(-1, buffer, 4); // Count (will be read as unsigned)
            SMBUtil.writeInt4(-2, buffer, 8); // Remaining (will be read as unsigned)
            SMBUtil.writeInt4(0, buffer, 12); // WriteChannelInfoOffset/Length

            int bytesRead = response.readBytesWireFormat(buffer, 0);

            assertEquals(16, bytesRead);
            assertEquals(-1, response.getCount()); // -1 as signed int represents max unsigned value
            assertEquals(-2, response.getRemaining());
        }

        private byte[] createValidWriteResponse(int count, int remaining) {
            byte[] buffer = new byte[64];
            SMBUtil.writeInt2(17, buffer, 0); // Structure size (must be 17)
            SMBUtil.writeInt2(0, buffer, 2); // Reserved
            SMBUtil.writeInt4(count, buffer, 4); // Count
            SMBUtil.writeInt4(remaining, buffer, 8); // Remaining
            SMBUtil.writeInt2(0, buffer, 12); // WriteChannelInfoOffset
            SMBUtil.writeInt2(0, buffer, 14); // WriteChannelInfoLength
            // Padding bytes (4 bytes) at offset 16-19
            return buffer;
        }
    }

    @Nested
    @DisplayName("Integration Tests")
    class IntegrationTests {

        @Test
        @DisplayName("Should maintain state after multiple reads")
        void testMultipleReads() throws SMBProtocolDecodingException {
            // First read
            byte[] buffer1 = createValidWriteResponse(1024, 512);
            response.readBytesWireFormat(buffer1, 0);
            assertEquals(1024, response.getCount());
            assertEquals(512, response.getRemaining());

            // Second read - should update values
            byte[] buffer2 = createValidWriteResponse(2048, 1024);
            response.readBytesWireFormat(buffer2, 0);
            assertEquals(2048, response.getCount());
            assertEquals(1024, response.getRemaining());
        }

        @Test
        @DisplayName("Should handle response as part of ServerMessageBlock2")
        void testAsServerMessageBlock2Response() {
            // Verify inheritance
            assertTrue(response instanceof ServerMessageBlock2);

            // Verify command can be retrieved from parent
            assertEquals(0, response.getCommand());
        }

        @Test
        @DisplayName("Should work with different buffer sizes")
        void testDifferentBufferSizes() throws SMBProtocolDecodingException {
            // Minimum size buffer
            byte[] minBuffer = new byte[20];
            SMBUtil.writeInt2(17, minBuffer, 0);
            SMBUtil.writeInt2(0, minBuffer, 2);
            SMBUtil.writeInt4(100, minBuffer, 4);
            SMBUtil.writeInt4(50, minBuffer, 8);
            SMBUtil.writeInt4(0, minBuffer, 12);
            SMBUtil.writeInt4(0, minBuffer, 16);

            int bytesRead = response.readBytesWireFormat(minBuffer, 0);
            assertEquals(16, bytesRead);
            assertEquals(100, response.getCount());
            assertEquals(50, response.getRemaining());

            // Large buffer
            byte[] largeBuffer = new byte[8192];
            System.arraycopy(createValidWriteResponse(5000, 2500), 0, largeBuffer, 1000, 20);

            Smb2WriteResponse response2 = new Smb2WriteResponse(mockConfig);
            bytesRead = response2.readBytesWireFormat(largeBuffer, 1000);
            assertEquals(16, bytesRead);
            assertEquals(5000, response2.getCount());
            assertEquals(2500, response2.getRemaining());
        }

        private byte[] createValidWriteResponse(int count, int remaining) {
            byte[] buffer = new byte[64];
            SMBUtil.writeInt2(17, buffer, 0); // Structure size (must be 17)
            SMBUtil.writeInt2(0, buffer, 2); // Reserved
            SMBUtil.writeInt4(count, buffer, 4); // Count
            SMBUtil.writeInt4(remaining, buffer, 8); // Remaining
            SMBUtil.writeInt2(0, buffer, 12); // WriteChannelInfoOffset
            SMBUtil.writeInt2(0, buffer, 14); // WriteChannelInfoLength
            return buffer;
        }
    }

    @Nested
    @DisplayName("Edge Case Tests")
    class EdgeCaseTests {

        @Test
        @DisplayName("Should handle structure size exactly 17")
        void testExactStructureSize() throws SMBProtocolDecodingException {
            byte[] buffer = new byte[64];
            SMBUtil.writeInt2(17, buffer, 0); // Exact required size
            SMBUtil.writeInt2(0, buffer, 2);
            SMBUtil.writeInt4(1000, buffer, 4);
            SMBUtil.writeInt4(500, buffer, 8);
            SMBUtil.writeInt4(0, buffer, 12);
            SMBUtil.writeInt4(0, buffer, 16);

            int bytesRead = response.readBytesWireFormat(buffer, 0);

            assertEquals(16, bytesRead);
            assertEquals(1000, response.getCount());
            assertEquals(500, response.getRemaining());
        }

        @ParameterizedTest
        @DisplayName("Should throw exception for invalid structure sizes")
        @ValueSource(ints = { 0, 1, 16, 18, 100, 255, 65535 })
        void testInvalidStructureSizes(int structureSize) {
            byte[] buffer = new byte[64];
            SMBUtil.writeInt2(structureSize, buffer, 0);

            SMBProtocolDecodingException exception =
                    assertThrows(SMBProtocolDecodingException.class, () -> response.readBytesWireFormat(buffer, 0));

            assertEquals("Expected structureSize = 17", exception.getMessage());
        }

        @Test
        @DisplayName("Should handle response at end of buffer")
        void testResponseAtEndOfBuffer() throws SMBProtocolDecodingException {
            byte[] buffer = new byte[20]; // Exact size needed
            SMBUtil.writeInt2(17, buffer, 0);
            SMBUtil.writeInt2(0, buffer, 2);
            SMBUtil.writeInt4(999, buffer, 4);
            SMBUtil.writeInt4(111, buffer, 8);
            SMBUtil.writeInt4(0, buffer, 12);
            SMBUtil.writeInt4(0, buffer, 16);

            int bytesRead = response.readBytesWireFormat(buffer, 0);

            assertEquals(16, bytesRead);
            assertEquals(999, response.getCount());
            assertEquals(111, response.getRemaining());
        }

        @Test
        @DisplayName("Should create new instance with same config")
        void testMultipleInstancesWithSameConfig() throws SMBProtocolDecodingException {
            Smb2WriteResponse response1 = new Smb2WriteResponse(mockConfig);
            Smb2WriteResponse response2 = new Smb2WriteResponse(mockConfig);

            byte[] buffer1 = createValidWriteResponse(100, 50);
            byte[] buffer2 = createValidWriteResponse(200, 100);

            response1.readBytesWireFormat(buffer1, 0);
            response2.readBytesWireFormat(buffer2, 0);

            // Each instance should maintain its own state
            assertEquals(100, response1.getCount());
            assertEquals(50, response1.getRemaining());
            assertEquals(200, response2.getCount());
            assertEquals(100, response2.getRemaining());
        }

        private byte[] createValidWriteResponse(int count, int remaining) {
            byte[] buffer = new byte[64];
            SMBUtil.writeInt2(17, buffer, 0);
            SMBUtil.writeInt2(0, buffer, 2);
            SMBUtil.writeInt4(count, buffer, 4);
            SMBUtil.writeInt4(remaining, buffer, 8);
            SMBUtil.writeInt4(0, buffer, 12);
            SMBUtil.writeInt4(0, buffer, 16);
            return buffer;
        }
    }
}

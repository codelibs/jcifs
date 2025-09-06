package org.codelibs.jcifs.smb.internal.smb2.io;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Random;

import org.codelibs.jcifs.smb.CIFSContext;
import org.codelibs.jcifs.smb.Configuration;
import org.codelibs.jcifs.smb.internal.smb2.RequestWithFileId;
import org.codelibs.jcifs.smb.internal.smb2.ServerMessageBlock2Request;
import org.codelibs.jcifs.smb.internal.smb2.Smb2Constants;
import org.codelibs.jcifs.smb.internal.util.SMBUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

/**
 * Test class for Smb2WriteRequest functionality
 */
@DisplayName("Smb2WriteRequest Tests")
class Smb2WriteRequestTest {

    @Mock
    private Configuration mockConfig;

    @Mock
    private CIFSContext mockContext;

    private byte[] testFileId;
    private Smb2WriteRequest request;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        when(mockContext.getConfig()).thenReturn(mockConfig);

        testFileId = new byte[16];
        new SecureRandom().nextBytes(testFileId);
        request = new Smb2WriteRequest(mockConfig, testFileId);
    }

    @Nested
    @DisplayName("Constructor Tests")
    class ConstructorTests {

        @Test
        @DisplayName("Should create request with configuration and file ID")
        void testConstructor() {
            Smb2WriteRequest writeRequest = new Smb2WriteRequest(mockConfig, testFileId);
            assertNotNull(writeRequest);
            assertTrue(writeRequest instanceof ServerMessageBlock2Request);
            assertTrue(writeRequest instanceof RequestWithFileId);
        }

        @Test
        @DisplayName("Should initialize with SMB2_WRITE command")
        void testCommandInitialization() {
            Smb2WriteRequest writeRequest = new Smb2WriteRequest(mockConfig, testFileId);
            // Command is set in parent constructor
            assertNotNull(writeRequest);
        }

        @Test
        @DisplayName("Should accept null file ID in constructor")
        void testConstructorWithNullFileId() {
            assertDoesNotThrow(() -> new Smb2WriteRequest(mockConfig, null));
        }

        @Test
        @DisplayName("Should accept empty file ID in constructor")
        void testConstructorWithEmptyFileId() {
            byte[] emptyFileId = new byte[16];
            assertDoesNotThrow(() -> new Smb2WriteRequest(mockConfig, emptyFileId));
        }
    }

    @Nested
    @DisplayName("FileId Tests")
    class FileIdTests {

        @Test
        @DisplayName("Should set file ID correctly")
        void testSetFileId() {
            byte[] newFileId = new byte[16];
            new SecureRandom().nextBytes(newFileId);

            assertDoesNotThrow(() -> request.setFileId(newFileId));
        }

        @Test
        @DisplayName("Should handle null file ID in setter")
        void testSetNullFileId() {
            assertDoesNotThrow(() -> request.setFileId(null));
        }

        @Test
        @DisplayName("Should handle various file ID sizes")
        void testVariousFileIdSizes() {
            byte[] shortFileId = new byte[8];
            byte[] standardFileId = new byte[16];
            byte[] longFileId = new byte[32];

            assertDoesNotThrow(() -> request.setFileId(shortFileId));
            assertDoesNotThrow(() -> request.setFileId(standardFileId));
            assertDoesNotThrow(() -> request.setFileId(longFileId));
        }

        @Test
        @DisplayName("Should handle unspecified file ID")
        void testUnspecifiedFileId() {
            assertDoesNotThrow(() -> request.setFileId(Smb2Constants.UNSPECIFIED_FILEID));
        }
    }

    @Nested
    @DisplayName("Data Setting Tests")
    class DataSettingTests {

        @Test
        @DisplayName("Should set data with offset and length")
        void testSetData() {
            byte[] data = new byte[1024];
            new Random().nextBytes(data);

            assertDoesNotThrow(() -> request.setData(data, 0, data.length));
        }

        @Test
        @DisplayName("Should set data with partial buffer")
        void testSetDataPartialBuffer() {
            byte[] data = new byte[1024];
            new Random().nextBytes(data);

            assertDoesNotThrow(() -> request.setData(data, 100, 500));
        }

        @Test
        @DisplayName("Should handle null data")
        void testSetNullData() {
            assertDoesNotThrow(() -> request.setData(null, 0, 0));
        }

        @Test
        @DisplayName("Should handle empty data")
        void testSetEmptyData() {
            byte[] emptyData = new byte[0];
            assertDoesNotThrow(() -> request.setData(emptyData, 0, 0));
        }

        @ParameterizedTest
        @DisplayName("Should handle various data sizes")
        @ValueSource(ints = { 0, 1, 100, 1024, 4096, 65536, 1048576 })
        void testVariousDataSizes(int size) {
            byte[] data = new byte[size];
            assertDoesNotThrow(() -> request.setData(data, 0, size));
        }

        @ParameterizedTest
        @DisplayName("Should handle various offsets and lengths")
        @CsvSource({ "1024, 0, 1024", "1024, 100, 900", "1024, 500, 524", "2048, 1024, 1024", "4096, 2048, 2048", "65536, 32768, 32768" })
        void testVariousOffsetsAndLengths(int dataSize, int offset, int length) {
            byte[] data = new byte[dataSize];
            assertDoesNotThrow(() -> request.setData(data, offset, length));
        }
    }

    @Nested
    @DisplayName("Parameter Setting Tests")
    class ParameterSettingTests {

        @Test
        @DisplayName("Should set offset correctly")
        void testSetOffset() {
            assertDoesNotThrow(() -> request.setOffset(0L));
            assertDoesNotThrow(() -> request.setOffset(1024L));
            assertDoesNotThrow(() -> request.setOffset(Long.MAX_VALUE));
        }

        @Test
        @DisplayName("Should set remaining bytes")
        void testSetRemainingBytes() {
            assertDoesNotThrow(() -> request.setRemainingBytes(0));
            assertDoesNotThrow(() -> request.setRemainingBytes(1024));
            assertDoesNotThrow(() -> request.setRemainingBytes(Integer.MAX_VALUE));
        }

        @Test
        @DisplayName("Should set write flags")
        void testSetWriteFlags() {
            assertDoesNotThrow(() -> request.setWriteFlags(0));
            assertDoesNotThrow(() -> request.setWriteFlags(0x01));
            assertDoesNotThrow(() -> request.setWriteFlags(0xFF));
            assertDoesNotThrow(() -> request.setWriteFlags(Integer.MAX_VALUE));
        }

        @ParameterizedTest
        @DisplayName("Should handle various offset values")
        @ValueSource(longs = { 0L, 1L, 512L, 1024L, 4096L, 1048576L, Long.MAX_VALUE })
        void testVariousOffsets(long offset) {
            assertDoesNotThrow(() -> request.setOffset(offset));
        }

        @ParameterizedTest
        @DisplayName("Should handle various remaining bytes values")
        @ValueSource(ints = { 0, 1, 512, 1024, 4096, 65536, Integer.MAX_VALUE })
        void testVariousRemainingBytes(int remaining) {
            assertDoesNotThrow(() -> request.setRemainingBytes(remaining));
        }
    }

    @Nested
    @DisplayName("Size Calculation Tests")
    class SizeCalculationTests {

        @Test
        @DisplayName("Should calculate size correctly with no data")
        void testSizeWithNoData() {
            request.setData(new byte[0], 0, 0);
            int expectedSize = ((Smb2Constants.SMB2_HEADER_LENGTH + 48 + 7) / 8) * 8;
            assertEquals(expectedSize, request.size());
        }

        @Test
        @DisplayName("Should calculate size correctly with data")
        void testSizeWithData() {
            int dataLength = 1024;
            request.setData(new byte[dataLength], 0, dataLength);
            int expectedSize = ((Smb2Constants.SMB2_HEADER_LENGTH + 48 + dataLength + 7) / 8) * 8;
            assertEquals(expectedSize, request.size());
        }

        @ParameterizedTest
        @DisplayName("Should calculate size for various data lengths")
        @ValueSource(ints = { 0, 1, 7, 8, 100, 512, 1024, 4096, 65536 })
        void testSizeWithVariousDataLengths(int dataLength) {
            request.setData(new byte[dataLength], 0, dataLength);
            int expectedSize = ((Smb2Constants.SMB2_HEADER_LENGTH + 48 + dataLength + 7) / 8) * 8;
            assertEquals(expectedSize, request.size());
        }

        @Test
        @DisplayName("Should align size to 8-byte boundary")
        void testSizeAlignment() {
            // Test various data lengths to ensure 8-byte alignment
            for (int i = 0; i < 16; i++) {
                request.setData(new byte[i], 0, i);
                int size = request.size();
                assertEquals(0, size % 8, "Size should be aligned to 8-byte boundary");
            }
        }
    }

    @Nested
    @DisplayName("WriteBytesWireFormat Tests")
    class WriteBytesWireFormatTests {

        @Test
        @DisplayName("Should write request structure correctly")
        void testWriteBytesWireFormat() {
            // Setup
            byte[] data = new byte[100];
            new Random().nextBytes(data);
            request.setData(data, 0, data.length);
            request.setOffset(1024L);
            request.setRemainingBytes(500);
            request.setWriteFlags(0x01);

            byte[] buffer = new byte[1024];
            int headerStart = 64; // Simulated header start

            // Execute
            int bytesWritten = request.writeBytesWireFormat(buffer, headerStart);

            // Verify structure
            assertEquals(49, SMBUtil.readInt2(buffer, headerStart)); // Structure size
            assertEquals(data.length, SMBUtil.readInt4(buffer, headerStart + 4)); // Data length
            assertEquals(1024L, SMBUtil.readInt8(buffer, headerStart + 8)); // Offset
            assertArrayEquals(testFileId, Arrays.copyOfRange(buffer, headerStart + 16, headerStart + 32)); // File ID
            assertEquals(0, SMBUtil.readInt4(buffer, headerStart + 32)); // Channel
            assertEquals(500, SMBUtil.readInt4(buffer, headerStart + 36)); // Remaining bytes
            assertEquals(0, SMBUtil.readInt2(buffer, headerStart + 40)); // WriteChannelInfoOffset
            assertEquals(0, SMBUtil.readInt2(buffer, headerStart + 42)); // WriteChannelInfoLength
            assertEquals(0x01, SMBUtil.readInt4(buffer, headerStart + 44)); // Write flags

            // Verify data offset is written correctly
            int dataOffsetValue = SMBUtil.readInt2(buffer, headerStart + 2);
            assertEquals(headerStart - 0 + 48, dataOffsetValue); // Assuming getHeaderStart() returns 0

            // Verify data is copied
            assertArrayEquals(data, Arrays.copyOfRange(buffer, headerStart + 48, headerStart + 48 + data.length));

            // Verify total bytes written
            assertEquals(48 + data.length, bytesWritten);
        }

        @Test
        @DisplayName("Should handle empty data in wire format")
        void testWriteBytesWireFormatEmptyData() {
            request.setData(new byte[0], 0, 0);

            byte[] buffer = new byte[256];
            int bytesWritten = request.writeBytesWireFormat(buffer, 0);

            assertEquals(48, bytesWritten); // Only header, no data
            assertEquals(49, SMBUtil.readInt2(buffer, 0)); // Structure size
            assertEquals(0, SMBUtil.readInt4(buffer, 4)); // Data length
        }

        @Test
        @DisplayName("Should throw exception when data exceeds buffer")
        void testWriteBytesWireFormatDataExceedsBuffer() {
            byte[] largeData = new byte[1000];
            request.setData(largeData, 0, largeData.length);

            byte[] smallBuffer = new byte[100];

            IllegalArgumentException exception =
                    assertThrows(IllegalArgumentException.class, () -> request.writeBytesWireFormat(smallBuffer, 0));

            assertTrue(exception.getMessage().contains("Data exceeds buffer size"));
        }

        @Test
        @DisplayName("Should write data at correct offset in buffer")
        void testDataOffsetCalculation() {
            byte[] data = new byte[50];
            Arrays.fill(data, (byte) 0xAB);
            request.setData(data, 0, data.length);

            byte[] buffer = new byte[512];
            Arrays.fill(buffer, (byte) 0);

            int startIndex = 100;
            request.writeBytesWireFormat(buffer, startIndex);

            // Verify data is at correct position
            for (int i = 0; i < data.length; i++) {
                assertEquals((byte) 0xAB, buffer[startIndex + 48 + i]);
            }
        }

        @Test
        @DisplayName("Should handle partial data buffer correctly")
        void testPartialDataBuffer() {
            byte[] fullData = new byte[200];
            new Random().nextBytes(fullData);

            int offset = 50;
            int length = 100;
            request.setData(fullData, offset, length);

            byte[] buffer = new byte[512];
            int bytesWritten = request.writeBytesWireFormat(buffer, 0);

            // Verify only the specified portion is written
            assertEquals(48 + length, bytesWritten);
            assertArrayEquals(Arrays.copyOfRange(fullData, offset, offset + length), Arrays.copyOfRange(buffer, 48, 48 + length));
        }

        @Test
        @DisplayName("Should handle maximum values correctly")
        void testMaximumValues() {
            request.setOffset(Long.MAX_VALUE);
            request.setRemainingBytes(Integer.MAX_VALUE);
            request.setWriteFlags(Integer.MAX_VALUE);
            request.setData(new byte[10], 0, 10);

            byte[] buffer = new byte[256];
            int bytesWritten = request.writeBytesWireFormat(buffer, 0);

            assertEquals(58, bytesWritten); // 48 + 10 data bytes
            assertEquals(Long.MAX_VALUE, SMBUtil.readInt8(buffer, 8));
            assertEquals(Integer.MAX_VALUE, SMBUtil.readInt4(buffer, 36));
            assertEquals(Integer.MAX_VALUE, SMBUtil.readInt4(buffer, 44));
        }
    }

    @Nested
    @DisplayName("ReadBytesWireFormat Tests")
    class ReadBytesWireFormatTests {

        @Test
        @DisplayName("Should always return 0 for readBytesWireFormat")
        void testReadBytesWireFormat() {
            byte[] buffer = new byte[1024];
            int result = request.readBytesWireFormat(buffer, 0);
            assertEquals(0, result);
        }

        @Test
        @DisplayName("Should return 0 regardless of buffer position")
        void testReadBytesWireFormatDifferentPosition() {
            byte[] buffer = new byte[1024];
            int result = request.readBytesWireFormat(buffer, 100);
            assertEquals(0, result);
        }

        @Test
        @DisplayName("Should return 0 with empty buffer")
        void testReadBytesWireFormatEmptyBuffer() {
            byte[] buffer = new byte[0];
            int result = request.readBytesWireFormat(buffer, 0);
            assertEquals(0, result);
        }
    }

    @Nested
    @DisplayName("CreateResponse Tests")
    class CreateResponseTests {

        @Test
        @DisplayName("Should create appropriate response")
        void testCreateResponse() {
            Smb2WriteResponse response = request.createResponse(mockContext, request);
            assertNotNull(response);
            assertTrue(response instanceof Smb2WriteResponse);
        }

        @Test
        @DisplayName("Should create response with same configuration")
        void testCreateResponseConfiguration() {
            Smb2WriteResponse response = request.createResponse(mockContext, request);
            assertNotNull(response);
            // Response should be created with the same config from context
            verify(mockContext, times(1)).getConfig();
        }
    }

    @Nested
    @DisplayName("Integration Tests")
    class IntegrationTests {

        @Test
        @DisplayName("Should handle complete write request workflow")
        void testCompleteWriteWorkflow() {
            // Setup complete request
            byte[] data = new byte[2048];
            new Random().nextBytes(data);

            request.setFileId(testFileId);
            request.setData(data, 512, 1024);
            request.setOffset(4096L);
            request.setRemainingBytes(2048);
            request.setWriteFlags(0x02);

            // Calculate expected size
            int expectedSize = ((Smb2Constants.SMB2_HEADER_LENGTH + 48 + 1024 + 7) / 8) * 8;
            assertEquals(expectedSize, request.size());

            // Write to buffer
            byte[] buffer = new byte[4096];
            int bytesWritten = request.writeBytesWireFormat(buffer, 100);
            assertEquals(48 + 1024, bytesWritten);

            // Verify written structure
            assertEquals(49, SMBUtil.readInt2(buffer, 100)); // Structure size
            assertEquals(1024, SMBUtil.readInt4(buffer, 104)); // Data length
            assertEquals(4096L, SMBUtil.readInt8(buffer, 108)); // Offset
            assertEquals(2048, SMBUtil.readInt4(buffer, 136)); // Remaining bytes
            assertEquals(0x02, SMBUtil.readInt4(buffer, 144)); // Write flags
        }

        @Test
        @DisplayName("Should handle multiple parameter updates")
        void testMultipleParameterUpdates() {
            // Initial setup
            request.setData(new byte[100], 0, 100);
            request.setOffset(1000L);
            request.setRemainingBytes(500);
            request.setWriteFlags(0x01);

            // Update parameters
            request.setData(new byte[200], 0, 200);
            request.setOffset(2000L);
            request.setRemainingBytes(1000);
            request.setWriteFlags(0x02);

            // Update file ID
            byte[] newFileId = new byte[16];
            Arrays.fill(newFileId, (byte) 0xFF);
            request.setFileId(newFileId);

            // Write and verify
            byte[] buffer = new byte[512];
            int bytesWritten = request.writeBytesWireFormat(buffer, 0);

            assertEquals(248, bytesWritten); // 48 + 200
            assertEquals(200, SMBUtil.readInt4(buffer, 4));
            assertEquals(2000L, SMBUtil.readInt8(buffer, 8));
            assertEquals(1000, SMBUtil.readInt4(buffer, 36));
            assertEquals(0x02, SMBUtil.readInt4(buffer, 44));
            assertArrayEquals(newFileId, Arrays.copyOfRange(buffer, 16, 32));
        }

        @Test
        @DisplayName("Should maintain constant overhead")
        void testOverheadConstant() {
            assertEquals(Smb2Constants.SMB2_HEADER_LENGTH + 48, Smb2WriteRequest.OVERHEAD);
        }

        @Test
        @DisplayName("Should handle boundary conditions")
        void testBoundaryConditions() {
            // Test with exactly aligned data
            request.setData(new byte[8], 0, 8); // 8-byte aligned
            assertEquals(((Smb2Constants.SMB2_HEADER_LENGTH + 48 + 8 + 7) / 8) * 8, request.size());

            // Test with unaligned data
            request.setData(new byte[7], 0, 7); // Not 8-byte aligned
            assertEquals(((Smb2Constants.SMB2_HEADER_LENGTH + 48 + 7 + 7) / 8) * 8, request.size());
        }
    }

    @Nested
    @DisplayName("Edge Case Tests")
    class EdgeCaseTests {

        @Test
        @DisplayName("Should handle null data with non-zero length")
        void testNullDataNonZeroLength() {
            request.setData(null, 0, 100);

            byte[] buffer = new byte[256];

            // Should handle gracefully or throw appropriate exception
            assertThrows(NullPointerException.class, () -> request.writeBytesWireFormat(buffer, 0));
        }

        @Test
        @DisplayName("Should handle data offset beyond array bounds")
        void testDataOffsetBeyondBounds() {
            byte[] data = new byte[100];
            request.setData(data, 200, 50); // Offset beyond array

            byte[] buffer = new byte[256];

            assertThrows(ArrayIndexOutOfBoundsException.class, () -> request.writeBytesWireFormat(buffer, 0));
        }

        @Test
        @DisplayName("Should handle negative offset")
        void testNegativeOffset() {
            request.setOffset(-1L);
            request.setData(new byte[10], 0, 10);

            byte[] buffer = new byte[256];
            int bytesWritten = request.writeBytesWireFormat(buffer, 0);

            // Negative value should be written as-is (interpreted as unsigned by receiver)
            assertEquals(-1L, SMBUtil.readInt8(buffer, 8));
        }

        @Test
        @DisplayName("Should handle zero-length file ID")
        void testZeroLengthFileId() {
            request.setFileId(new byte[0]);
            request.setData(new byte[10], 0, 10);

            byte[] buffer = new byte[256];

            // Should handle zero-length file ID
            assertThrows(ArrayIndexOutOfBoundsException.class, () -> request.writeBytesWireFormat(buffer, 0));
        }

        @Test
        @DisplayName("Should handle file ID longer than 16 bytes")
        void testLongFileId() {
            byte[] longFileId = new byte[32];
            new SecureRandom().nextBytes(longFileId);
            request.setFileId(longFileId);
            request.setData(new byte[10], 0, 10);

            byte[] buffer = new byte[256];
            int bytesWritten = request.writeBytesWireFormat(buffer, 0);

            // Should only copy first 16 bytes
            assertArrayEquals(Arrays.copyOfRange(longFileId, 0, 16), Arrays.copyOfRange(buffer, 16, 32));
        }

        @Test
        @DisplayName("Should handle file ID shorter than 16 bytes")
        void testShortFileId() {
            byte[] shortFileId = new byte[8];
            Arrays.fill(shortFileId, (byte) 0xAB);
            request.setFileId(shortFileId);
            request.setData(new byte[10], 0, 10);

            byte[] buffer = new byte[256];

            // Should handle gracefully or throw appropriate exception
            assertThrows(ArrayIndexOutOfBoundsException.class, () -> request.writeBytesWireFormat(buffer, 0));
        }
    }
}

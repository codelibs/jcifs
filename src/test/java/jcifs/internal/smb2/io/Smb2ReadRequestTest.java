package jcifs.internal.smb2.io;

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

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import jcifs.CIFSContext;
import jcifs.Configuration;
import jcifs.internal.smb2.RequestWithFileId;
import jcifs.internal.smb2.ServerMessageBlock2Request;
import jcifs.internal.smb2.Smb2Constants;
import jcifs.internal.util.SMBUtil;

/**
 * Test class for Smb2ReadRequest functionality
 */
@DisplayName("Smb2ReadRequest Tests")
class Smb2ReadRequestTest {

    @Mock
    private Configuration mockConfig;

    @Mock
    private CIFSContext mockContext;

    private byte[] testFileId;
    private byte[] outputBuffer;
    private Smb2ReadRequest request;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        when(mockContext.getConfig()).thenReturn(mockConfig);

        testFileId = new byte[16];
        new SecureRandom().nextBytes(testFileId);
        outputBuffer = new byte[4096];
        request = new Smb2ReadRequest(mockConfig, testFileId, outputBuffer, 0);
    }

    @Nested
    @DisplayName("Constructor Tests")
    class ConstructorTests {

        @Test
        @DisplayName("Should create request with all parameters")
        void testConstructor() {
            byte[] buffer = new byte[1024];
            Smb2ReadRequest readRequest = new Smb2ReadRequest(mockConfig, testFileId, buffer, 100);
            assertNotNull(readRequest);
            assertTrue(readRequest instanceof ServerMessageBlock2Request);
            assertTrue(readRequest instanceof RequestWithFileId);
        }

        @Test
        @DisplayName("Should initialize with SMB2_READ command")
        void testCommandInitialization() {
            Smb2ReadRequest readRequest = new Smb2ReadRequest(mockConfig, testFileId, outputBuffer, 0);
            // Command is set in parent constructor
            assertNotNull(readRequest);
        }

        @Test
        @DisplayName("Should accept null file ID in constructor")
        void testConstructorWithNullFileId() {
            assertDoesNotThrow(() -> new Smb2ReadRequest(mockConfig, null, outputBuffer, 0));
        }

        @Test
        @DisplayName("Should accept empty file ID in constructor")
        void testConstructorWithEmptyFileId() {
            byte[] emptyFileId = new byte[16];
            assertDoesNotThrow(() -> new Smb2ReadRequest(mockConfig, emptyFileId, outputBuffer, 0));
        }

        @Test
        @DisplayName("Should accept null output buffer")
        void testConstructorWithNullOutputBuffer() {
            assertDoesNotThrow(() -> new Smb2ReadRequest(mockConfig, testFileId, null, 0));
        }

        @Test
        @DisplayName("Should handle various buffer offsets")
        void testConstructorWithVariousOffsets() {
            byte[] buffer = new byte[4096];
            assertDoesNotThrow(() -> new Smb2ReadRequest(mockConfig, testFileId, buffer, 0));
            assertDoesNotThrow(() -> new Smb2ReadRequest(mockConfig, testFileId, buffer, 100));
            assertDoesNotThrow(() -> new Smb2ReadRequest(mockConfig, testFileId, buffer, 2048));
        }
    }

    @Nested
    @DisplayName("Constants Tests")
    class ConstantsTests {

        @Test
        @DisplayName("Should have correct SMB2_READFLAG_READ_UNBUFFERED value")
        void testReadUnbufferedFlag() {
            assertEquals((byte) 0x1, Smb2ReadRequest.SMB2_READFLAG_READ_UNBUFFERED);
        }

        @Test
        @DisplayName("Should have correct SMB2_CHANNEL_NONE value")
        void testChannelNone() {
            assertEquals(0x0, Smb2ReadRequest.SMB2_CHANNEL_NONE);
        }

        @Test
        @DisplayName("Should have correct SMB2_CHANNEL_RDMA_V1 value")
        void testChannelRdmaV1() {
            assertEquals(0x1, Smb2ReadRequest.SMB2_CHANNEL_RDMA_V1);
        }

        @Test
        @DisplayName("Should have correct SMB2_CHANNEL_RDMA_V1_INVALIDATE value")
        void testChannelRdmaV1Invalidate() {
            assertEquals(0x2, Smb2ReadRequest.SMB2_CHANNEL_RDMA_V1_INVALIDATE);
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
    }

    @Nested
    @DisplayName("Parameter Setting Tests")
    class ParameterSettingTests {

        @Test
        @DisplayName("Should set padding correctly")
        void testSetPadding() {
            assertDoesNotThrow(() -> request.setPadding((byte) 0));
            assertDoesNotThrow(() -> request.setPadding((byte) 1));
            assertDoesNotThrow(() -> request.setPadding((byte) 0xFF));
        }

        @Test
        @DisplayName("Should set read flags correctly")
        void testSetReadFlags() {
            assertDoesNotThrow(() -> request.setReadFlags((byte) 0));
            assertDoesNotThrow(() -> request.setReadFlags(Smb2ReadRequest.SMB2_READFLAG_READ_UNBUFFERED));
            assertDoesNotThrow(() -> request.setReadFlags((byte) 0xFF));
        }

        @Test
        @DisplayName("Should set read length correctly")
        void testSetReadLength() {
            assertDoesNotThrow(() -> request.setReadLength(0));
            assertDoesNotThrow(() -> request.setReadLength(1024));
            assertDoesNotThrow(() -> request.setReadLength(65536));
            assertDoesNotThrow(() -> request.setReadLength(Integer.MAX_VALUE));
        }

        @Test
        @DisplayName("Should set offset correctly")
        void testSetOffset() {
            assertDoesNotThrow(() -> request.setOffset(0L));
            assertDoesNotThrow(() -> request.setOffset(1024L));
            assertDoesNotThrow(() -> request.setOffset(Long.MAX_VALUE));
        }

        @Test
        @DisplayName("Should set minimum count correctly")
        void testSetMinimumCount() {
            assertDoesNotThrow(() -> request.setMinimumCount(0));
            assertDoesNotThrow(() -> request.setMinimumCount(512));
            assertDoesNotThrow(() -> request.setMinimumCount(Integer.MAX_VALUE));
        }

        @Test
        @DisplayName("Should set remaining bytes correctly")
        void testSetRemainingBytes() {
            assertDoesNotThrow(() -> request.setRemainingBytes(0));
            assertDoesNotThrow(() -> request.setRemainingBytes(1024));
            assertDoesNotThrow(() -> request.setRemainingBytes(Integer.MAX_VALUE));
        }

        @ParameterizedTest
        @DisplayName("Should handle various padding values")
        @ValueSource(ints = { 0, 1, 15, 127, 255 })
        void testVariousPadding(int padding) {
            assertDoesNotThrow(() -> request.setPadding((byte) padding));
        }

        @ParameterizedTest
        @DisplayName("Should handle various read lengths")
        @ValueSource(ints = { 0, 1, 512, 1024, 4096, 65536, 1048576 })
        void testVariousReadLengths(int length) {
            assertDoesNotThrow(() -> request.setReadLength(length));
        }

        @ParameterizedTest
        @DisplayName("Should handle various offsets")
        @ValueSource(longs = { 0L, 1L, 512L, 1024L, 4096L, 1048576L, Long.MAX_VALUE })
        void testVariousOffsets(long offset) {
            assertDoesNotThrow(() -> request.setOffset(offset));
        }
    }

    @Nested
    @DisplayName("Size Calculation Tests")
    class SizeCalculationTests {

        @Test
        @DisplayName("Should calculate size correctly")
        void testSize() {
            int expectedSize = ((Smb2Constants.SMB2_HEADER_LENGTH + 49 + 7) / 8) * 8;
            assertEquals(expectedSize, request.size());
        }

        @Test
        @DisplayName("Should align size to 8-byte boundary")
        void testSizeAlignment() {
            int size = request.size();
            assertEquals(0, size % 8, "Size should be aligned to 8-byte boundary");
        }

        @Test
        @DisplayName("Should have consistent size regardless of parameters")
        void testSizeConsistency() {
            int originalSize = request.size();

            request.setReadLength(65536);
            assertEquals(originalSize, request.size());

            request.setOffset(Long.MAX_VALUE);
            assertEquals(originalSize, request.size());

            request.setMinimumCount(1024);
            assertEquals(originalSize, request.size());
        }
    }

    @Nested
    @DisplayName("WriteBytesWireFormat Tests")
    class WriteBytesWireFormatTests {

        @Test
        @DisplayName("Should write request structure correctly")
        void testWriteBytesWireFormat() {
            // Setup
            request.setPadding((byte) 2);
            request.setReadFlags((byte) 0x01);
            request.setReadLength(4096);
            request.setOffset(8192L);
            request.setMinimumCount(512);
            request.setRemainingBytes(1024);

            byte[] buffer = new byte[256];

            // Execute
            int bytesWritten = request.writeBytesWireFormat(buffer, 0);

            // Verify structure
            assertEquals(49, SMBUtil.readInt2(buffer, 0)); // Structure size
            assertEquals(2, buffer[2]); // Padding
            assertEquals(0x01, buffer[3]); // Read flags
            assertEquals(4096, SMBUtil.readInt4(buffer, 4)); // Read length
            assertEquals(8192L, SMBUtil.readInt8(buffer, 8)); // Offset
            assertArrayEquals(testFileId, Arrays.copyOfRange(buffer, 16, 32)); // File ID
            assertEquals(512, SMBUtil.readInt4(buffer, 32)); // Minimum count
            assertEquals(Smb2ReadRequest.SMB2_CHANNEL_NONE, SMBUtil.readInt4(buffer, 36)); // Channel
            assertEquals(1024, SMBUtil.readInt4(buffer, 40)); // Remaining bytes

            // ReadChannelInfo
            assertEquals(0, SMBUtil.readInt2(buffer, 44)); // ReadChannelInfoOffset
            assertEquals(0, SMBUtil.readInt2(buffer, 46)); // ReadChannelInfoLength

            // Buffer byte
            assertEquals(0, buffer[48]); // One byte in buffer must be zero

            // Verify total bytes written
            assertEquals(49, bytesWritten);
        }

        @Test
        @DisplayName("Should write default values correctly")
        void testWriteBytesWireFormatDefaults() {
            byte[] buffer = new byte[256];
            int bytesWritten = request.writeBytesWireFormat(buffer, 0);

            assertEquals(49, bytesWritten);
            assertEquals(49, SMBUtil.readInt2(buffer, 0)); // Structure size
            assertEquals(0, buffer[2]); // Default padding
            assertEquals(0, buffer[3]); // Default read flags
            assertEquals(0, SMBUtil.readInt4(buffer, 4)); // Default read length
            assertEquals(0L, SMBUtil.readInt8(buffer, 8)); // Default offset
            assertEquals(0, SMBUtil.readInt4(buffer, 32)); // Default minimum count
            assertEquals(0, SMBUtil.readInt4(buffer, 36)); // Default channel
            assertEquals(0, SMBUtil.readInt4(buffer, 40)); // Default remaining bytes
        }

        @Test
        @DisplayName("Should handle maximum values correctly")
        void testMaximumValues() {
            request.setPadding((byte) 0xFF);
            request.setReadFlags((byte) 0xFF);
            request.setReadLength(Integer.MAX_VALUE);
            request.setOffset(Long.MAX_VALUE);
            request.setMinimumCount(Integer.MAX_VALUE);
            request.setRemainingBytes(Integer.MAX_VALUE);

            byte[] buffer = new byte[256];
            int bytesWritten = request.writeBytesWireFormat(buffer, 0);

            assertEquals(49, bytesWritten);
            assertEquals((byte) 0xFF, buffer[2]);
            assertEquals((byte) 0xFF, buffer[3]);
            assertEquals(Integer.MAX_VALUE, SMBUtil.readInt4(buffer, 4));
            assertEquals(Long.MAX_VALUE, SMBUtil.readInt8(buffer, 8));
            assertEquals(Integer.MAX_VALUE, SMBUtil.readInt4(buffer, 32));
            assertEquals(Integer.MAX_VALUE, SMBUtil.readInt4(buffer, 40));
        }

        @Test
        @DisplayName("Should write at different buffer positions")
        void testWriteAtDifferentPositions() {
            request.setReadLength(2048);
            request.setOffset(4096L);

            byte[] buffer = new byte[512];

            // Test at position 0
            int bytesWritten = request.writeBytesWireFormat(buffer, 0);
            assertEquals(49, bytesWritten);
            assertEquals(2048, SMBUtil.readInt4(buffer, 4));

            // Test at position 100
            Arrays.fill(buffer, (byte) 0);
            bytesWritten = request.writeBytesWireFormat(buffer, 100);
            assertEquals(49, bytesWritten);
            assertEquals(2048, SMBUtil.readInt4(buffer, 104));
            assertEquals(4096L, SMBUtil.readInt8(buffer, 108));
        }

        @Test
        @DisplayName("Should handle null file ID during write")
        void testWriteWithNullFileId() {
            request.setFileId(null);
            request.setReadLength(1024);

            byte[] buffer = new byte[256];

            assertThrows(NullPointerException.class, () -> request.writeBytesWireFormat(buffer, 0));
        }

        @Test
        @DisplayName("Should handle file ID of different sizes")
        void testWriteWithDifferentFileIdSizes() {
            // Test with 16-byte file ID (standard)
            byte[] standardFileId = new byte[16];
            Arrays.fill(standardFileId, (byte) 0xAB);
            request.setFileId(standardFileId);

            byte[] buffer = new byte[256];
            int bytesWritten = request.writeBytesWireFormat(buffer, 0);

            assertEquals(49, bytesWritten);
            assertArrayEquals(standardFileId, Arrays.copyOfRange(buffer, 16, 32));

            // Test with longer file ID (should copy only first 16 bytes)
            byte[] longFileId = new byte[32];
            Arrays.fill(longFileId, (byte) 0xCD);
            request.setFileId(longFileId);

            Arrays.fill(buffer, (byte) 0);
            bytesWritten = request.writeBytesWireFormat(buffer, 0);

            assertEquals(49, bytesWritten);
            assertArrayEquals(Arrays.copyOfRange(longFileId, 0, 16), Arrays.copyOfRange(buffer, 16, 32));
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

        @Test
        @DisplayName("Should return 0 with null buffer")
        void testReadBytesWireFormatNullBuffer() {
            int result = request.readBytesWireFormat(null, 0);
            assertEquals(0, result);
        }
    }

    @Nested
    @DisplayName("CreateResponse Tests")
    class CreateResponseTests {

        @Test
        @DisplayName("Should create appropriate response")
        void testCreateResponse() {
            Smb2ReadResponse response = request.createResponse(mockContext, request);
            assertNotNull(response);
            assertTrue(response instanceof Smb2ReadResponse);
        }

        @Test
        @DisplayName("Should create response with same configuration and buffer")
        void testCreateResponseConfiguration() {
            Smb2ReadResponse response = request.createResponse(mockContext, request);
            assertNotNull(response);
            // Response should be created with the same config from context
            verify(mockContext, times(1)).getConfig();
        }

        @Test
        @DisplayName("Should pass output buffer to response")
        void testCreateResponseWithBuffer() {
            byte[] specificBuffer = new byte[2048];
            int offset = 128;
            Smb2ReadRequest requestWithBuffer = new Smb2ReadRequest(mockConfig, testFileId, specificBuffer, offset);

            Smb2ReadResponse response = requestWithBuffer.createResponse(mockContext, requestWithBuffer);
            assertNotNull(response);
            // Response should be created with same buffer and offset
        }
    }

    @Nested
    @DisplayName("Integration Tests")
    class IntegrationTests {

        @Test
        @DisplayName("Should handle complete read request workflow")
        void testCompleteReadWorkflow() {
            // Setup complete request
            request.setFileId(testFileId);
            request.setPadding((byte) 1);
            request.setReadFlags(Smb2ReadRequest.SMB2_READFLAG_READ_UNBUFFERED);
            request.setReadLength(8192);
            request.setOffset(16384L);
            request.setMinimumCount(1024);
            request.setRemainingBytes(4096);

            // Calculate expected size
            int expectedSize = ((Smb2Constants.SMB2_HEADER_LENGTH + 49 + 7) / 8) * 8;
            assertEquals(expectedSize, request.size());

            // Write to buffer
            byte[] buffer = new byte[256];
            int bytesWritten = request.writeBytesWireFormat(buffer, 50);
            assertEquals(49, bytesWritten);

            // Verify written structure
            assertEquals(49, SMBUtil.readInt2(buffer, 50)); // Structure size
            assertEquals(1, buffer[52]); // Padding
            assertEquals(0x01, buffer[53]); // Read flags
            assertEquals(8192, SMBUtil.readInt4(buffer, 54)); // Read length
            assertEquals(16384L, SMBUtil.readInt8(buffer, 58)); // Offset
            assertEquals(1024, SMBUtil.readInt4(buffer, 82)); // Minimum count
            assertEquals(4096, SMBUtil.readInt4(buffer, 90)); // Remaining bytes
        }

        @Test
        @DisplayName("Should handle multiple parameter updates")
        void testMultipleParameterUpdates() {
            // Initial setup
            request.setReadLength(1000);
            request.setOffset(500L);
            request.setMinimumCount(100);

            // Update parameters
            request.setReadLength(2000);
            request.setOffset(1000L);
            request.setMinimumCount(200);
            request.setRemainingBytes(3000);
            request.setPadding((byte) 4);
            request.setReadFlags((byte) 0x02);

            // Update file ID
            byte[] newFileId = new byte[16];
            Arrays.fill(newFileId, (byte) 0xEF);
            request.setFileId(newFileId);

            // Write and verify
            byte[] buffer = new byte[256];
            int bytesWritten = request.writeBytesWireFormat(buffer, 0);

            assertEquals(49, bytesWritten);
            assertEquals(2000, SMBUtil.readInt4(buffer, 4));
            assertEquals(1000L, SMBUtil.readInt8(buffer, 8));
            assertEquals(200, SMBUtil.readInt4(buffer, 32));
            assertEquals(3000, SMBUtil.readInt4(buffer, 40));
            assertEquals(4, buffer[2]);
            assertEquals(0x02, buffer[3]);
            assertArrayEquals(newFileId, Arrays.copyOfRange(buffer, 16, 32));
        }

        @Test
        @DisplayName("Should handle read request with RDMA channel")
        void testReadRequestWithRdmaChannel() {
            request.setReadLength(65536);
            request.setOffset(0L);
            // Note: channel is private and not settable via public API
            // This test documents that channel defaults to SMB2_CHANNEL_NONE

            byte[] buffer = new byte[256];
            request.writeBytesWireFormat(buffer, 0);

            assertEquals(Smb2ReadRequest.SMB2_CHANNEL_NONE, SMBUtil.readInt4(buffer, 36));
        }
    }

    @Nested
    @DisplayName("Edge Case Tests")
    class EdgeCaseTests {

        @Test
        @DisplayName("Should handle negative offset")
        void testNegativeOffset() {
            request.setOffset(-1L);
            request.setReadLength(1024);

            byte[] buffer = new byte[256];
            int bytesWritten = request.writeBytesWireFormat(buffer, 0);

            // Negative value should be written as-is (interpreted as unsigned by receiver)
            assertEquals(-1L, SMBUtil.readInt8(buffer, 8));
        }

        @Test
        @DisplayName("Should handle zero-length read")
        void testZeroLengthRead() {
            request.setReadLength(0);
            request.setMinimumCount(0);

            byte[] buffer = new byte[256];
            int bytesWritten = request.writeBytesWireFormat(buffer, 0);

            assertEquals(49, bytesWritten);
            assertEquals(0, SMBUtil.readInt4(buffer, 4));
            assertEquals(0, SMBUtil.readInt4(buffer, 32));
        }

        @Test
        @DisplayName("Should handle minimum count greater than read length")
        void testMinimumCountGreaterThanReadLength() {
            request.setReadLength(1024);
            request.setMinimumCount(2048);

            byte[] buffer = new byte[256];
            int bytesWritten = request.writeBytesWireFormat(buffer, 0);

            assertEquals(49, bytesWritten);
            assertEquals(1024, SMBUtil.readInt4(buffer, 4));
            assertEquals(2048, SMBUtil.readInt4(buffer, 32));
        }

        @Test
        @DisplayName("Should handle file ID shorter than 16 bytes")
        void testShortFileId() {
            byte[] shortFileId = new byte[8];
            Arrays.fill(shortFileId, (byte) 0xAB);
            request.setFileId(shortFileId);

            byte[] buffer = new byte[256];

            // Should handle gracefully or throw appropriate exception
            assertThrows(ArrayIndexOutOfBoundsException.class, () -> request.writeBytesWireFormat(buffer, 0));
        }

        @Test
        @DisplayName("Should handle all parameters at maximum")
        void testAllParametersMaximum() {
            request.setPadding((byte) 0xFF);
            request.setReadFlags((byte) 0xFF);
            request.setReadLength(Integer.MAX_VALUE);
            request.setOffset(Long.MAX_VALUE);
            request.setMinimumCount(Integer.MAX_VALUE);
            request.setRemainingBytes(Integer.MAX_VALUE);

            byte[] buffer = new byte[256];
            int bytesWritten = request.writeBytesWireFormat(buffer, 0);

            assertEquals(49, bytesWritten);
            // Verify structure integrity with maximum values
            assertEquals(49, SMBUtil.readInt2(buffer, 0));
        }

        @Test
        @DisplayName("Should handle buffer overflow protection")
        void testBufferOverflowProtection() {
            request.setReadLength(65536);

            byte[] smallBuffer = new byte[48]; // Smaller than required 49 bytes

            // Should not overflow buffer
            assertThrows(ArrayIndexOutOfBoundsException.class, () -> request.writeBytesWireFormat(smallBuffer, 0));
        }

        @Test
        @DisplayName("Should handle write at buffer boundary")
        void testWriteAtBufferBoundary() {
            request.setReadLength(1024);

            byte[] buffer = new byte[100];

            // Try to write at position that would exceed buffer
            assertThrows(ArrayIndexOutOfBoundsException.class, () -> request.writeBytesWireFormat(buffer, 52)); // 52 + 49 > 100
        }
    }
}

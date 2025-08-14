package jcifs.internal.smb2.info;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import jcifs.Configuration;
import jcifs.internal.SMBProtocolDecodingException;
import jcifs.internal.smb2.ServerMessageBlock2;
import jcifs.internal.smb2.ServerMessageBlock2Response;
import jcifs.internal.util.SMBUtil;

/**
 * Test class for Smb2SetInfoResponse functionality
 */
@DisplayName("Smb2SetInfoResponse Tests")
@MockitoSettings(strictness = Strictness.LENIENT)
class Smb2SetInfoResponseTest {

    private Configuration mockConfig;
    private Smb2SetInfoResponse response;

    @BeforeEach
    void setUp() {
        mockConfig = mock(Configuration.class);
        response = new Smb2SetInfoResponse(mockConfig);
    }

    @Test
    @DisplayName("Test constructor initializes with config")
    void testConstructor() {
        assertNotNull(response);
        // Command is not set in constructor, only after decoding
        assertEquals((short) 0, response.getCommand());
    }

    @Test
    @DisplayName("Test writeBytesWireFormat returns 0")
    void testWriteBytesWireFormat() {
        byte[] dst = new byte[1024];
        int dstIndex = 0;

        int result = response.writeBytesWireFormat(dst, dstIndex);

        assertEquals(0, result);
    }

    @Test
    @DisplayName("Test readBytesWireFormat with valid structure size")
    void testReadBytesWireFormatValidStructureSize() throws SMBProtocolDecodingException {
        byte[] buffer = new byte[1024];
        int bufferIndex = 0;

        // Set structure size to 2 (valid)
        SMBUtil.writeInt2(2, buffer, bufferIndex);

        int result = response.readBytesWireFormat(buffer, bufferIndex);

        assertEquals(2, result);
    }

    @Test
    @DisplayName("Test readBytesWireFormat with invalid structure size throws exception")
    void testReadBytesWireFormatInvalidStructureSize() {
        byte[] buffer = new byte[1024];
        int bufferIndex = 0;

        // Set structure size to 4 (invalid, should be 2)
        SMBUtil.writeInt2(4, buffer, bufferIndex);

        SMBProtocolDecodingException exception =
                assertThrows(SMBProtocolDecodingException.class, () -> response.readBytesWireFormat(buffer, bufferIndex),
                        "Should throw SMBProtocolDecodingException for invalid structure size");

        assertEquals("Expected structureSize = 2", exception.getMessage());
    }

    @Test
    @DisplayName("Test readBytesWireFormat with zero structure size throws exception")
    void testReadBytesWireFormatZeroStructureSize() {
        byte[] buffer = new byte[1024];
        int bufferIndex = 0;

        // Set structure size to 0 (invalid)
        SMBUtil.writeInt2(0, buffer, bufferIndex);

        SMBProtocolDecodingException exception =
                assertThrows(SMBProtocolDecodingException.class, () -> response.readBytesWireFormat(buffer, bufferIndex),
                        "Should throw SMBProtocolDecodingException for zero structure size");

        assertEquals("Expected structureSize = 2", exception.getMessage());
    }

    @Test
    @DisplayName("Test readBytesWireFormat with negative structure size throws exception")
    void testReadBytesWireFormatNegativeStructureSize() {
        byte[] buffer = new byte[1024];
        int bufferIndex = 0;

        // Set structure size to -1 (0xFFFF when read as unsigned)
        SMBUtil.writeInt2(0xFFFF, buffer, bufferIndex);

        SMBProtocolDecodingException exception =
                assertThrows(SMBProtocolDecodingException.class, () -> response.readBytesWireFormat(buffer, bufferIndex),
                        "Should throw SMBProtocolDecodingException for negative structure size");

        assertEquals("Expected structureSize = 2", exception.getMessage());
    }

    @ParameterizedTest
    @ValueSource(ints = { 1, 3, 4, 5, 10, 100, 255, 256, 1000, 65535 })
    @DisplayName("Test readBytesWireFormat with various invalid structure sizes")
    void testReadBytesWireFormatVariousInvalidSizes(int invalidSize) {
        byte[] buffer = new byte[1024];
        int bufferIndex = 0;

        SMBUtil.writeInt2(invalidSize, buffer, bufferIndex);

        SMBProtocolDecodingException exception =
                assertThrows(SMBProtocolDecodingException.class, () -> response.readBytesWireFormat(buffer, bufferIndex),
                        "Should throw SMBProtocolDecodingException for structure size " + invalidSize);

        assertEquals("Expected structureSize = 2", exception.getMessage());
    }

    @Test
    @DisplayName("Test readBytesWireFormat with different buffer positions")
    void testReadBytesWireFormatDifferentBufferPositions() throws SMBProtocolDecodingException {
        byte[] buffer = new byte[1024];

        // Test at different positions in the buffer
        int[] positions = { 0, 10, 100, 500 };

        for (int position : positions) {
            // Set structure size to 2 at the given position
            SMBUtil.writeInt2(2, buffer, position);

            int result = response.readBytesWireFormat(buffer, position);

            assertEquals(2, result, "Should return 2 for buffer position " + position);
        }
    }

    @Test
    @DisplayName("Test readBytesWireFormat with minimum buffer size")
    void testReadBytesWireFormatMinimumBufferSize() throws SMBProtocolDecodingException {
        byte[] buffer = new byte[2]; // Minimum size needed for structure size
        int bufferIndex = 0;

        SMBUtil.writeInt2(2, buffer, bufferIndex);

        int result = response.readBytesWireFormat(buffer, bufferIndex);

        assertEquals(2, result);
    }

    @Test
    @DisplayName("Test inheritance from ServerMessageBlock2Response")
    void testInheritance() {
        assertTrue(response instanceof ServerMessageBlock2Response);
        assertTrue(response instanceof ServerMessageBlock2);
    }

    @Test
    @DisplayName("Test decode method integration")
    void testDecodeMethodIntegration() throws Exception {
        byte[] buffer = new byte[1024];
        int bufferIndex = 0;

        // Prepare SMB2 header (64 bytes)
        // Protocol ID
        System.arraycopy(new byte[] { (byte) 0xFE, 'S', 'M', 'B' }, 0, buffer, bufferIndex, 4);
        // Header length
        SMBUtil.writeInt2(64, buffer, bufferIndex + 4);
        // Credit charge
        SMBUtil.writeInt2(1, buffer, bufferIndex + 6);
        // Status
        SMBUtil.writeInt4(0, buffer, bufferIndex + 8);
        // Command - SMB2_SET_INFO (0x0011)
        SMBUtil.writeInt2(0x0011, buffer, bufferIndex + 12);
        // Credits
        SMBUtil.writeInt2(1, buffer, bufferIndex + 14);
        // Flags
        SMBUtil.writeInt4(1, buffer, bufferIndex + 16); // SMB2_FLAGS_SERVER_TO_REDIR
        // Next command
        SMBUtil.writeInt4(0, buffer, bufferIndex + 20);
        // Message ID
        SMBUtil.writeInt8(1, buffer, bufferIndex + 24);
        // Reserved/Async ID
        SMBUtil.writeInt8(0, buffer, bufferIndex + 32);
        // Session ID
        SMBUtil.writeInt8(0, buffer, bufferIndex + 40);
        // Signature
        System.arraycopy(new byte[16], 0, buffer, bufferIndex + 48, 16);

        // Body starts at bufferIndex + 64
        // Structure size = 2
        SMBUtil.writeInt2(2, buffer, bufferIndex + 64);

        // Decode the response
        int result = response.decode(buffer, bufferIndex);

        assertEquals(66, result);
        assertEquals(0, response.getStatus()); // Should be STATUS_SUCCESS
    }

    @Test
    @DisplayName("Test readBytesWireFormat preserves buffer content")
    void testReadBytesWireFormatPreservesBuffer() throws SMBProtocolDecodingException {
        byte[] buffer = new byte[1024];
        int bufferIndex = 0;

        // Fill buffer with test data
        for (int i = 0; i < buffer.length; i++) {
            buffer[i] = (byte) (i % 256);
        }

        // Set structure size to 2
        SMBUtil.writeInt2(2, buffer, bufferIndex);

        // Make a copy of the buffer
        byte[] bufferCopy = buffer.clone();

        // Call readBytesWireFormat
        response.readBytesWireFormat(buffer, bufferIndex);

        // Verify buffer wasn't modified
        assertArrayEquals(bufferCopy, buffer, "Buffer content should not be modified");
    }

    @Test
    @DisplayName("Test multiple calls to readBytesWireFormat")
    void testMultipleReadBytesWireFormatCalls() throws SMBProtocolDecodingException {
        byte[] buffer = new byte[1024];
        int bufferIndex = 0;

        // Set structure size to 2
        SMBUtil.writeInt2(2, buffer, bufferIndex);

        // Call readBytesWireFormat multiple times
        for (int i = 0; i < 5; i++) {
            int result = response.readBytesWireFormat(buffer, bufferIndex);
            assertEquals(2, result, "Should consistently return 2 on call " + (i + 1));
        }
    }

    @Test
    @DisplayName("Test edge case with maximum buffer index")
    void testReadBytesWireFormatMaxBufferIndex() throws SMBProtocolDecodingException {
        byte[] buffer = new byte[65536]; // Large buffer
        int bufferIndex = 65534; // Near the end

        // Set structure size to 2
        SMBUtil.writeInt2(2, buffer, bufferIndex);

        int result = response.readBytesWireFormat(buffer, bufferIndex);

        assertEquals(2, result);
    }

    @Test
    @DisplayName("Test writeBytesWireFormat with various buffer configurations")
    void testWriteBytesWireFormatVariousConfigurations() {
        // Test with different buffer sizes and indices
        int[][] configs = { { 100, 0 }, { 1024, 50 }, { 4096, 2000 }, { 65536, 32768 } };

        for (int[] config : configs) {
            byte[] dst = new byte[config[0]];
            int dstIndex = config[1];

            int result = response.writeBytesWireFormat(dst, dstIndex);

            assertEquals(0, result, String.format("Should return 0 for buffer size %d at index %d", config[0], config[1]));
        }
    }
}
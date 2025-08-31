package jcifs.internal.smb2.io;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;

import java.lang.reflect.Field;
import java.util.Arrays;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

import jcifs.BaseTest;
import jcifs.Configuration;
import jcifs.internal.SMBProtocolDecodingException;
import jcifs.internal.smb2.ServerMessageBlock2;
import jcifs.internal.smb2.ServerMessageBlock2Response;
import jcifs.internal.smb2.Smb2Constants;
import jcifs.internal.util.SMBUtil;
import jcifs.smb.NtStatus;

/**
 * Test class for Smb2ReadResponse functionality
 */
@DisplayName("Smb2ReadResponse Tests")
class Smb2ReadResponseTest extends BaseTest {

    private Configuration mockConfig;
    private byte[] outputBuffer;
    private int outputBufferOffset;
    private Smb2ReadResponse response;

    @BeforeEach
    void setUp() {
        mockConfig = mock(Configuration.class);
        outputBuffer = new byte[1024];
        outputBufferOffset = 0;
        response = new Smb2ReadResponse(mockConfig, outputBuffer, outputBufferOffset);
    }

    @Test
    @DisplayName("Should create response with configuration and output buffer")
    void testConstructor() {
        // Given
        byte[] buffer = new byte[512];
        int offset = 10;

        // When
        Smb2ReadResponse resp = new Smb2ReadResponse(mockConfig, buffer, offset);

        // Then
        assertNotNull(resp);
        assertTrue(resp instanceof ServerMessageBlock2Response);
        assertTrue(resp instanceof ServerMessageBlock2);
    }

    @Test
    @DisplayName("Should return correct OVERHEAD constant value")
    void testOverheadConstant() {
        // Then
        assertEquals(Smb2Constants.SMB2_HEADER_LENGTH + 16, Smb2ReadResponse.OVERHEAD);
    }

    @Test
    @DisplayName("Should initially have zero data length")
    void testInitialDataLength() {
        // Then
        assertEquals(0, response.getDataLength());
    }

    @Test
    @DisplayName("Should initially have zero data remaining")
    void testInitialDataRemaining() {
        // Then
        assertEquals(0, response.getDataRemaining());
    }

    @Test
    @DisplayName("Should write empty bytes to wire format")
    void testWriteBytesWireFormat() {
        // Given
        byte[] buffer = new byte[256];
        int offset = 10;

        // When
        int bytesWritten = response.writeBytesWireFormat(buffer, offset);

        // Then
        assertEquals(0, bytesWritten);
    }

    @DisplayName("Should write zero bytes at various offsets")
    @ParameterizedTest
    @ValueSource(ints = { 0, 1, 10, 50, 100, 255 })
    void testWriteBytesWireFormatAtDifferentOffsets(int offset) {
        // Given
        byte[] buffer = new byte[256];

        // When
        int bytesWritten = response.writeBytesWireFormat(buffer, offset);

        // Then
        assertEquals(0, bytesWritten);
    }

    @Test
    @DisplayName("Should handle error response structure size 9")
    void testReadBytesWireFormatErrorResponse() throws Exception {
        // Given
        byte[] buffer = new byte[256];
        int bufferIndex = 0;

        // Write structure size (9) - indicates error response
        SMBUtil.writeInt2(9, buffer, bufferIndex);
        // Write error context and error data
        buffer[bufferIndex + 2] = 1; // Error context count
        buffer[bufferIndex + 3] = 0; // Reserved
        SMBUtil.writeInt4(0, buffer, bufferIndex + 4); // ByteCount (0 for error)

        // Create a custom test response that tracks if readErrorResponse was called
        class TestSmb2ReadResponse extends Smb2ReadResponse {
            boolean errorResponseCalled = false;

            TestSmb2ReadResponse(Configuration config, byte[] outputBuffer, int outputBufferOffset) {
                super(config, outputBuffer, outputBufferOffset);
            }

            @Override
            protected int readErrorResponse(byte[] buf, int bufIndex) throws SMBProtocolDecodingException {
                errorResponseCalled = true;
                return super.readErrorResponse(buf, bufIndex);
            }
        }

        TestSmb2ReadResponse testResponse = new TestSmb2ReadResponse(mockConfig, outputBuffer, outputBufferOffset);

        // When
        int bytesRead = testResponse.readBytesWireFormat(buffer, bufferIndex);

        // Then
        assertTrue(testResponse.errorResponseCalled);
        assertEquals(8, bytesRead); // Error response is 8 bytes
    }

    @DisplayName("Should throw exception for invalid structure size")
    @ParameterizedTest
    @ValueSource(ints = { 0, 1, 8, 10, 16, 18, 100, 65535 })
    void testReadBytesWireFormatInvalidStructureSize(int structureSize) {
        // Given
        byte[] buffer = new byte[256];
        int bufferIndex = 0;

        // Write invalid structure size
        SMBUtil.writeInt2(structureSize, buffer, bufferIndex);

        // When & Then
        SMBProtocolDecodingException exception =
                assertThrows(SMBProtocolDecodingException.class, () -> response.readBytesWireFormat(buffer, bufferIndex));
        assertEquals("Expected structureSize = 17", exception.getMessage());
    }

    @Test
    @DisplayName("Should read valid structure with minimal test")
    void testReadBytesWireFormatBasicStructure() throws Exception {
        // Given - Create a complete SMB2 message with header
        byte[] buffer = new byte[512];
        int headerStart = 0;
        int bodyStart = Smb2Constants.SMB2_HEADER_LENGTH;

        // Write SMB2 header (64 bytes)
        // Protocol ID
        System.arraycopy(new byte[] { (byte) 0xFE, 'S', 'M', 'B' }, 0, buffer, headerStart, 4);
        // Structure size (64)
        SMBUtil.writeInt2(64, buffer, headerStart + 4);
        // Credit charge
        SMBUtil.writeInt2(1, buffer, headerStart + 6);
        // Status
        SMBUtil.writeInt4(0, buffer, headerStart + 8);
        // Command (READ = 0x0008)
        SMBUtil.writeInt2(0x0008, buffer, headerStart + 12);
        // Credit request/response
        SMBUtil.writeInt2(1, buffer, headerStart + 14);
        // Flags
        SMBUtil.writeInt4(0, buffer, headerStart + 16);
        // Next command
        SMBUtil.writeInt4(0, buffer, headerStart + 20);
        // Message ID
        SMBUtil.writeInt8(1, buffer, headerStart + 24);
        // Reserved/Async ID
        SMBUtil.writeInt8(0, buffer, headerStart + 32);
        // Session ID
        SMBUtil.writeInt8(0, buffer, headerStart + 40);
        // Signature
        Arrays.fill(buffer, headerStart + 48, headerStart + 64, (byte) 0);

        // Write READ response body
        int dataLength = 20;
        int dataRemaining = 0;
        int dataOffsetFromHeader = 80;

        // Structure size (17 = 0x11)
        SMBUtil.writeInt2(17, buffer, bodyStart);
        // Data offset (byte - offset from header start)
        buffer[bodyStart + 2] = (byte) dataOffsetFromHeader;
        // Reserved
        buffer[bodyStart + 3] = 0;
        // Data length
        SMBUtil.writeInt4(dataLength, buffer, bodyStart + 4);
        // Data remaining
        SMBUtil.writeInt4(dataRemaining, buffer, bodyStart + 8);
        // Reserved2
        SMBUtil.writeInt4(0, buffer, bodyStart + 12);

        // Write test data at the specified offset
        byte[] testData = new byte[dataLength];
        for (int i = 0; i < dataLength; i++) {
            testData[i] = (byte) (i & 0xFF);
        }
        System.arraycopy(testData, 0, buffer, dataOffsetFromHeader, dataLength);

        // Use reflection to set headerStart
        Field headerStartField = ServerMessageBlock2.class.getDeclaredField("headerStart");
        headerStartField.setAccessible(true);
        headerStartField.set(response, headerStart);

        // When
        int bytesRead = response.readBytesWireFormat(buffer, bodyStart);

        // Then
        assertEquals(dataOffsetFromHeader + dataLength - bodyStart, bytesRead);
        assertEquals(dataLength, response.getDataLength());
        assertEquals(dataRemaining, response.getDataRemaining());

        // Verify data was copied to output buffer
        byte[] copiedData = Arrays.copyOfRange(outputBuffer, 0, dataLength);
        assertArrayEquals(testData, copiedData);
    }

    @Test
    @DisplayName("Should throw exception when output buffer too small")
    void testReadBytesWireFormatBufferTooSmall() throws Exception {
        // Given
        byte[] smallOutputBuffer = new byte[10];
        Smb2ReadResponse smallBufferResponse = new Smb2ReadResponse(mockConfig, smallOutputBuffer, 0);

        byte[] buffer = new byte[256];
        int bodyStart = 0;
        int dataLength = 20; // Larger than output buffer
        int dataOffsetFromHeader = 80;

        // Write valid structure
        SMBUtil.writeInt2(17, buffer, bodyStart);
        buffer[bodyStart + 2] = (byte) dataOffsetFromHeader;
        SMBUtil.writeInt4(dataLength, buffer, bodyStart + 4);
        SMBUtil.writeInt4(0, buffer, bodyStart + 8);
        SMBUtil.writeInt4(0, buffer, bodyStart + 12);

        // Use reflection to set headerStart
        Field headerStartField = ServerMessageBlock2.class.getDeclaredField("headerStart");
        headerStartField.setAccessible(true);
        headerStartField.set(smallBufferResponse, 0);

        // When & Then
        SMBProtocolDecodingException exception =
                assertThrows(SMBProtocolDecodingException.class, () -> smallBufferResponse.readBytesWireFormat(buffer, bodyStart));
        assertEquals("Buffer to small for read response", exception.getMessage());
    }

    @Test
    @DisplayName("Should handle output buffer with offset")
    void testReadBytesWireFormatWithOutputOffset() throws Exception {
        // Given
        int offset = 100;
        byte[] largeOutputBuffer = new byte[1024];
        Smb2ReadResponse offsetResponse = new Smb2ReadResponse(mockConfig, largeOutputBuffer, offset);

        byte[] buffer = new byte[256];
        int bodyStart = 0;
        int dataLength = 50;
        int dataOffsetFromHeader = 80;

        // Write structure
        SMBUtil.writeInt2(17, buffer, bodyStart);
        buffer[bodyStart + 2] = (byte) dataOffsetFromHeader;
        SMBUtil.writeInt4(dataLength, buffer, bodyStart + 4);
        SMBUtil.writeInt4(100, buffer, bodyStart + 8);
        SMBUtil.writeInt4(0, buffer, bodyStart + 12);

        // Write test data
        byte[] testData = new byte[dataLength];
        for (int i = 0; i < dataLength; i++) {
            testData[i] = (byte) (0xAA + i);
        }
        System.arraycopy(testData, 0, buffer, dataOffsetFromHeader, dataLength);

        // Use reflection to set headerStart
        Field headerStartField = ServerMessageBlock2.class.getDeclaredField("headerStart");
        headerStartField.setAccessible(true);
        headerStartField.set(offsetResponse, 0);

        // When
        int bytesRead = offsetResponse.readBytesWireFormat(buffer, bodyStart);

        // Then
        assertEquals(dataOffsetFromHeader + dataLength - bodyStart, bytesRead);
        assertEquals(dataLength, offsetResponse.getDataLength());

        // Verify data was copied to correct offset in output buffer
        byte[] copiedData = Arrays.copyOfRange(largeOutputBuffer, offset, offset + dataLength);
        assertArrayEquals(testData, copiedData);
    }

    @Test
    @DisplayName("Should check if error response for buffer overflow status")
    void testIsErrorResponseStatusBufferOverflow() throws Exception {
        // Given - Use reflection to set status
        Field statusField = ServerMessageBlock2.class.getDeclaredField("status");
        statusField.setAccessible(true);
        statusField.set(response, NtStatus.NT_STATUS_BUFFER_OVERFLOW);

        // When
        boolean isError = response.isErrorResponseStatus();

        // Then
        assertFalse(isError); // Buffer overflow is not considered an error
    }

    @Test
    @DisplayName("Should check if error response for other error status")
    void testIsErrorResponseStatusOtherError() throws Exception {
        // Given - Use reflection to set status
        Field statusField = ServerMessageBlock2.class.getDeclaredField("status");
        statusField.setAccessible(true);
        statusField.set(response, NtStatus.NT_STATUS_ACCESS_DENIED);

        // When
        boolean isError = response.isErrorResponseStatus();

        // Then
        assertTrue(isError);
    }

    @Test
    @DisplayName("Should check if error response for success status")
    void testIsErrorResponseStatusSuccess() throws Exception {
        // Given - Use reflection to set status
        Field statusField = ServerMessageBlock2.class.getDeclaredField("status");
        statusField.setAccessible(true);
        statusField.set(response, NtStatus.NT_STATUS_SUCCESS);

        // When
        boolean isError = response.isErrorResponseStatus();

        // Then
        assertFalse(isError);
    }

    @DisplayName("Should handle various data lengths")
    @ParameterizedTest
    @CsvSource({ "0, 0", "1, 10", "100, 200", "512, 1024" })
    void testReadBytesWireFormatVariousDataLengths(int dataLength, int dataRemaining) throws Exception {
        // Given
        byte[] largeBuffer = new byte[2048];
        byte[] largeOutputBuffer = new byte[2048];
        Smb2ReadResponse largeResponse = new Smb2ReadResponse(mockConfig, largeOutputBuffer, 0);

        int bodyStart = 0;
        int dataOffsetFromHeader = 80;

        // Write structure
        SMBUtil.writeInt2(17, largeBuffer, bodyStart);
        largeBuffer[bodyStart + 2] = (byte) dataOffsetFromHeader;
        SMBUtil.writeInt4(dataLength, largeBuffer, bodyStart + 4);
        SMBUtil.writeInt4(dataRemaining, largeBuffer, bodyStart + 8);
        SMBUtil.writeInt4(0, largeBuffer, bodyStart + 12);

        // Write test data
        if (dataLength > 0) {
            byte[] testData = new byte[dataLength];
            Arrays.fill(testData, (byte) 0x42);
            System.arraycopy(testData, 0, largeBuffer, dataOffsetFromHeader, dataLength);
        }

        // Use reflection to set headerStart
        Field headerStartField = ServerMessageBlock2.class.getDeclaredField("headerStart");
        headerStartField.setAccessible(true);
        headerStartField.set(largeResponse, 0);

        // When
        int bytesRead = largeResponse.readBytesWireFormat(largeBuffer, bodyStart);

        // Then
        assertEquals(Math.max(16, dataOffsetFromHeader + dataLength - bodyStart), bytesRead);
        assertEquals(dataLength, largeResponse.getDataLength());
        assertEquals(dataRemaining, largeResponse.getDataRemaining());
    }

    @Test
    @DisplayName("Should handle empty data correctly")
    void testReadBytesWireFormatEmptyData() throws Exception {
        // Given
        byte[] buffer = new byte[256];
        int bodyStart = 0;
        int dataLength = 0;
        int dataRemaining = 0;
        int dataOffsetFromHeader = 80;

        // Write structure with zero data length
        SMBUtil.writeInt2(17, buffer, bodyStart);
        buffer[bodyStart + 2] = (byte) dataOffsetFromHeader;
        SMBUtil.writeInt4(dataLength, buffer, bodyStart + 4);
        SMBUtil.writeInt4(dataRemaining, buffer, bodyStart + 8);
        SMBUtil.writeInt4(0, buffer, bodyStart + 12);

        // Use reflection to set headerStart
        Field headerStartField = ServerMessageBlock2.class.getDeclaredField("headerStart");
        headerStartField.setAccessible(true);
        headerStartField.set(response, 0);

        // When
        int bytesRead = response.readBytesWireFormat(buffer, bodyStart);

        // Then
        // When dataLength is 0, it returns max(16, dataOffset + 0 - bodyStart) = max(16, 80) = 80
        assertEquals(80, bytesRead);
        assertEquals(0, response.getDataLength());
        assertEquals(0, response.getDataRemaining());
    }

    @Test
    @DisplayName("Should handle data offset byte as unsigned")
    void testReadBytesWireFormatUnsignedDataOffset() throws Exception {
        // Given
        byte[] buffer = new byte[256];
        int bodyStart = 0;
        int dataLength = 5;
        // Use a small offset value that is safe
        byte dataOffsetByte = 100;

        // Write structure
        SMBUtil.writeInt2(17, buffer, bodyStart);
        buffer[bodyStart + 2] = dataOffsetByte;
        SMBUtil.writeInt4(dataLength, buffer, bodyStart + 4);
        SMBUtil.writeInt4(0, buffer, bodyStart + 8);
        SMBUtil.writeInt4(0, buffer, bodyStart + 12);

        // Write data at the offset
        Arrays.fill(buffer, 100, 100 + dataLength, (byte) 0xCC);

        // Use reflection to set headerStart
        Field headerStartField = ServerMessageBlock2.class.getDeclaredField("headerStart");
        headerStartField.setAccessible(true);
        headerStartField.set(response, 0);

        // When
        int bytesRead = response.readBytesWireFormat(buffer, bodyStart);

        // Then
        assertEquals(100 + dataLength - bodyStart, bytesRead);
        assertEquals(dataLength, response.getDataLength());
    }

    @Test
    @DisplayName("Should verify inheritance from ServerMessageBlock2Response")
    void testInheritance() {
        // Then
        assertTrue(response instanceof ServerMessageBlock2Response);
        assertTrue(response instanceof ServerMessageBlock2);
    }

    @Test
    @DisplayName("Should not modify buffer during write operation")
    void testWriteDoesNotModifyBuffer() {
        // Given
        byte[] buffer = new byte[256];
        // Fill buffer with test pattern
        for (int i = 0; i < buffer.length; i++) {
            buffer[i] = (byte) (i & 0xFF);
        }
        byte[] originalBuffer = buffer.clone();

        // When
        int bytesWritten = response.writeBytesWireFormat(buffer, 10);

        // Then
        assertEquals(0, bytesWritten);
        assertArrayEquals(originalBuffer, buffer); // Buffer should remain unchanged
    }

    @Test
    @DisplayName("Should handle null configuration gracefully")
    void testNullConfiguration() {
        // When - constructor accepts null config without throwing
        Smb2ReadResponse responseWithNull = new Smb2ReadResponse(null, outputBuffer, outputBufferOffset);

        // Then - response is created successfully
        assertNotNull(responseWithNull);
    }

    @Test
    @DisplayName("Should handle large data offset value")
    void testReadBytesWireFormatLargeDataOffset() throws Exception {
        // Given
        byte[] buffer = new byte[512];
        int bodyStart = 0;
        int dataLength = 10;
        // Use a large but safe offset value that fits in signed byte range (120)
        int dataOffsetValue = 120;

        // Write structure
        SMBUtil.writeInt2(17, buffer, bodyStart);
        buffer[bodyStart + 2] = (byte) dataOffsetValue;
        SMBUtil.writeInt4(dataLength, buffer, bodyStart + 4);
        SMBUtil.writeInt4(0, buffer, bodyStart + 8);
        SMBUtil.writeInt4(0, buffer, bodyStart + 12);

        // Write test data at the offset
        byte[] testData = new byte[dataLength];
        Arrays.fill(testData, (byte) 0xFF);
        System.arraycopy(testData, 0, buffer, dataOffsetValue, dataLength);

        // Use reflection to set headerStart
        Field headerStartField = ServerMessageBlock2.class.getDeclaredField("headerStart");
        headerStartField.setAccessible(true);
        headerStartField.set(response, 0);

        // When
        int bytesRead = response.readBytesWireFormat(buffer, bodyStart);

        // Then
        assertEquals(dataOffsetValue + dataLength - bodyStart, bytesRead);
        assertEquals(dataLength, response.getDataLength());
    }

    @Test
    @DisplayName("Should validate data fits within buffer bounds")
    void testReadBytesWireFormatDataBoundsValidation() throws Exception {
        // Given
        byte[] smallBuffer = new byte[100];
        int bodyStart = 0;
        int dataLength = 50;
        int dataOffsetValue = 80; // Data would extend beyond buffer

        // Write structure
        SMBUtil.writeInt2(17, smallBuffer, bodyStart);
        smallBuffer[bodyStart + 2] = (byte) dataOffsetValue;
        SMBUtil.writeInt4(dataLength, smallBuffer, bodyStart + 4);
        SMBUtil.writeInt4(0, smallBuffer, bodyStart + 8);
        SMBUtil.writeInt4(0, smallBuffer, bodyStart + 12);

        // Use reflection to set headerStart
        Field headerStartField = ServerMessageBlock2.class.getDeclaredField("headerStart");
        headerStartField.setAccessible(true);
        headerStartField.set(response, 0);

        // When & Then - should throw when trying to read beyond buffer
        assertThrows(ArrayIndexOutOfBoundsException.class, () -> response.readBytesWireFormat(smallBuffer, bodyStart));
    }

    @Test
    @DisplayName("Should handle Reserved2 field correctly")
    void testReadBytesWireFormatReserved2Field() throws Exception {
        // Given
        byte[] buffer = new byte[256];
        int bodyStart = 0;
        int dataOffsetFromHeader = 80;
        int reserved2Value = 0x12345678;

        // Write structure
        SMBUtil.writeInt2(17, buffer, bodyStart);
        buffer[bodyStart + 2] = (byte) dataOffsetFromHeader;
        SMBUtil.writeInt4(10, buffer, bodyStart + 4);
        SMBUtil.writeInt4(0, buffer, bodyStart + 8);
        SMBUtil.writeInt4(reserved2Value, buffer, bodyStart + 12); // Reserved2

        // Write some test data
        Arrays.fill(buffer, dataOffsetFromHeader, dataOffsetFromHeader + 10, (byte) 0x55);

        // Use reflection to set headerStart
        Field headerStartField = ServerMessageBlock2.class.getDeclaredField("headerStart");
        headerStartField.setAccessible(true);
        headerStartField.set(response, 0);

        // When
        int bytesRead = response.readBytesWireFormat(buffer, bodyStart);

        // Then - method should complete without error, Reserved2 is ignored
        assertEquals(dataOffsetFromHeader + 10 - bodyStart, bytesRead);
        assertEquals(10, response.getDataLength());
    }
}
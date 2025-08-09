package jcifs.internal.smb2.tree;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.doThrow;

import java.io.IOException;
import java.lang.reflect.Field;
import java.lang.reflect.Method;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.junit.jupiter.params.provider.CsvSource;

import jcifs.BaseTest;
import jcifs.Configuration;
import jcifs.internal.CommonServerMessageBlockRequest;
import jcifs.internal.CommonServerMessageBlockResponse;
import jcifs.internal.SMBProtocolDecodingException;
import jcifs.internal.smb2.ServerMessageBlock2;
import jcifs.internal.smb2.ServerMessageBlock2Response;
import jcifs.internal.util.SMBUtil;

/**
 * Test class for Smb2TreeDisconnectResponse functionality
 */
@DisplayName("Smb2TreeDisconnectResponse Tests")
class Smb2TreeDisconnectResponseTest extends BaseTest {

    private Configuration mockConfig;
    private Smb2TreeDisconnectResponse response;

    @BeforeEach
    void setUp() {
        mockConfig = mock(Configuration.class);
        response = new Smb2TreeDisconnectResponse(mockConfig);
    }

    @Test
    @DisplayName("Should create response with configuration")
    void testConstructorWithConfiguration() {
        // Given & When
        Smb2TreeDisconnectResponse resp = new Smb2TreeDisconnectResponse(mockConfig);

        // Then
        assertNotNull(resp);
        assertTrue(resp instanceof ServerMessageBlock2Response);
        assertTrue(resp instanceof ServerMessageBlock2);
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
    @ValueSource(ints = {0, 1, 10, 50, 100, 255})
    void testWriteBytesWireFormatAtDifferentOffsets(int offset) {
        // Given
        byte[] buffer = new byte[256];

        // When
        int bytesWritten = response.writeBytesWireFormat(buffer, offset);

        // Then
        assertEquals(0, bytesWritten);
    }

    @Test
    @DisplayName("Should read valid structure from wire format")
    void testReadBytesWireFormatValidStructure() throws SMBProtocolDecodingException {
        // Given
        byte[] buffer = new byte[256];
        int offset = 10;
        
        // Write structure size (4) at offset
        SMBUtil.writeInt2(4, buffer, offset);
        SMBUtil.writeInt2(0, buffer, offset + 2); // Reserved field

        // When
        int bytesRead = response.readBytesWireFormat(buffer, offset);

        // Then
        assertEquals(4, bytesRead);
    }

    @DisplayName("Should throw exception for invalid structure size")
    @ParameterizedTest
    @ValueSource(ints = {0, 1, 2, 3, 5, 10, 100, 65535})
    void testReadBytesWireFormatInvalidStructureSize(int structureSize) {
        // Given
        byte[] buffer = new byte[256];
        int offset = 0;
        
        // Write invalid structure size
        SMBUtil.writeInt2(structureSize, buffer, offset);

        // When & Then
        SMBProtocolDecodingException exception = assertThrows(
            SMBProtocolDecodingException.class, 
            () -> response.readBytesWireFormat(buffer, offset)
        );
        assertEquals("Structure size != 4", exception.getMessage());
    }

    @DisplayName("Should read structure correctly at different offsets")
    @ParameterizedTest
    @ValueSource(ints = {0, 10, 50, 100, 200})
    void testReadBytesWireFormatAtDifferentOffsets(int offset) throws SMBProtocolDecodingException {
        // Given
        byte[] buffer = new byte[256];
        
        // Write valid structure at offset
        SMBUtil.writeInt2(4, buffer, offset);
        SMBUtil.writeInt2(0, buffer, offset + 2);

        // When
        int bytesRead = response.readBytesWireFormat(buffer, offset);

        // Then
        assertEquals(4, bytesRead);
    }

    @Test
    @DisplayName("Should handle minimum buffer size for reading")
    void testReadBytesWireFormatMinimumBuffer() throws SMBProtocolDecodingException {
        // Given
        byte[] buffer = new byte[4];
        
        // Write valid structure
        SMBUtil.writeInt2(4, buffer, 0);
        SMBUtil.writeInt2(0, buffer, 2);

        // When
        int bytesRead = response.readBytesWireFormat(buffer, 0);

        // Then
        assertEquals(4, bytesRead);
    }

    @Test
    @DisplayName("Should throw exception when buffer too small for reading")
    void testReadBytesWireFormatBufferTooSmall() {
        // Given
        byte[] buffer = new byte[1]; // Too small to read structure size

        // When & Then
        assertThrows(ArrayIndexOutOfBoundsException.class, () -> {
            response.readBytesWireFormat(buffer, 0);
        });
    }

    @Test
    @DisplayName("Should throw exception when offset exceeds buffer for reading")
    void testReadBytesWireFormatOffsetTooLarge() {
        // Given
        byte[] buffer = new byte[10];
        int offset = 9; // Only 1 byte remaining, need at least 2 for structure size

        // When & Then
        assertThrows(ArrayIndexOutOfBoundsException.class, () -> {
            response.readBytesWireFormat(buffer, offset);
        });
    }

    @Test
    @DisplayName("Should verify inheritance from ServerMessageBlock2Response")
    void testInheritance() {
        // Then
        assertTrue(response instanceof ServerMessageBlock2Response);
        assertTrue(response instanceof ServerMessageBlock2);
        assertTrue(response instanceof CommonServerMessageBlockResponse);
    }

    @Test
    @DisplayName("Should handle multiple read operations")
    void testMultipleReads() throws SMBProtocolDecodingException {
        // Given
        byte[] buffer1 = new byte[256];
        byte[] buffer2 = new byte[256];
        
        // Prepare both buffers with valid structure
        SMBUtil.writeInt2(4, buffer1, 0);
        SMBUtil.writeInt2(0, buffer1, 2);
        SMBUtil.writeInt2(4, buffer2, 10);
        SMBUtil.writeInt2(0, buffer2, 12);

        // When
        int bytes1 = response.readBytesWireFormat(buffer1, 0);
        int bytes2 = response.readBytesWireFormat(buffer2, 10);

        // Then
        assertEquals(bytes1, bytes2);
        assertEquals(4, bytes1);
    }

    @Test
    @DisplayName("Should verify exact structure size value")
    void testExactStructureSizeValue() throws SMBProtocolDecodingException {
        // Given
        byte[] buffer = new byte[256];
        
        // Write exact structure size value (4)
        buffer[0] = 0x04;
        buffer[1] = 0x00;
        buffer[2] = 0x00;
        buffer[3] = 0x00;

        // When
        int bytesRead = response.readBytesWireFormat(buffer, 0);

        // Then
        assertEquals(4, bytesRead);
    }

    @DisplayName("Should handle structure with different reserved values")
    @ParameterizedTest
    @CsvSource({
        "0, 0",
        "255, 255",
        "0, 65535",
        "100, 200"
    })
    void testReadWithDifferentReservedValues(int byte2, int byte3) throws SMBProtocolDecodingException {
        // Given
        byte[] buffer = new byte[256];
        
        // Write structure size (4)
        SMBUtil.writeInt2(4, buffer, 0);
        // Write reserved field (any value is acceptable)
        buffer[2] = (byte) byte2;
        buffer[3] = (byte) byte3;

        // When
        int bytesRead = response.readBytesWireFormat(buffer, 0);

        // Then - should still read 4 bytes regardless of reserved field value
        assertEquals(4, bytesRead);
    }

    @Test
    @DisplayName("Should handle edge case structure sizes")
    void testEdgeCaseStructureSizes() {
        // Test minimum invalid size (0)
        byte[] buffer = new byte[256];
        SMBUtil.writeInt2(0, buffer, 0);
        
        SMBProtocolDecodingException ex1 = assertThrows(
            SMBProtocolDecodingException.class,
            () -> response.readBytesWireFormat(buffer, 0)
        );
        assertEquals("Structure size != 4", ex1.getMessage());

        // Test maximum 2-byte value (65535)
        SMBUtil.writeInt2(65535, buffer, 0);
        
        SMBProtocolDecodingException ex2 = assertThrows(
            SMBProtocolDecodingException.class,
            () -> response.readBytesWireFormat(buffer, 0)
        );
        assertEquals("Structure size != 4", ex2.getMessage());
    }

    @Test
    @DisplayName("Should verify response state methods from parent")
    void testResponseStateMethods() throws Exception {
        // Test that response inherits state tracking from ServerMessageBlock2Response
        
        // Initially not received
        Method isReceivedMethod = ServerMessageBlock2Response.class.getDeclaredMethod("isReceived");
        isReceivedMethod.setAccessible(true);
        assertFalse((boolean) isReceivedMethod.invoke(response));

        // Test reset method
        response.reset();
        assertFalse((boolean) isReceivedMethod.invoke(response));
    }

    @Test
    @DisplayName("Should handle getNextResponse correctly")
    void testGetNextResponse() {
        // When
        CommonServerMessageBlockResponse nextResponse = response.getNextResponse();

        // Then - should return null as no next response is set
        assertEquals(null, nextResponse);
    }

    @Test
    @DisplayName("Should handle prepare method correctly")
    void testPrepareMethod() {
        // Given
        CommonServerMessageBlockRequest mockRequest = mock(CommonServerMessageBlockRequest.class);

        // When - should not throw exception
        response.prepare(mockRequest);

        // Then - method completes without error
        assertTrue(true);
    }

    @Test
    @DisplayName("Should verify wire format protocol compliance")
    void testWireFormatProtocolCompliance() throws SMBProtocolDecodingException {
        // Given - exact SMB2 TREE_DISCONNECT response structure
        byte[] wireData = new byte[] {
            0x04, 0x00,  // StructureSize (must be 4)
            0x00, 0x00   // Reserved
        };
        
        // When
        int bytesRead = response.readBytesWireFormat(wireData, 0);

        // Then
        assertEquals(4, bytesRead);
        assertEquals(wireData.length, bytesRead);
    }

    @Test
    @DisplayName("Should handle concurrent read operations")
    void testConcurrentReads() throws SMBProtocolDecodingException {
        // Given
        byte[] buffer = new byte[256];
        SMBUtil.writeInt2(4, buffer, 0);
        SMBUtil.writeInt2(0, buffer, 2);

        // When - simulate multiple concurrent reads on same response object
        int read1 = response.readBytesWireFormat(buffer, 0);
        int read2 = response.readBytesWireFormat(buffer, 0);
        int read3 = response.readBytesWireFormat(buffer, 0);

        // Then - all reads should return same result
        assertEquals(4, read1);
        assertEquals(4, read2);
        assertEquals(4, read3);
    }

    @Test
    @DisplayName("Should validate structure size before processing")
    void testStructureSizeValidation() {
        // Given various invalid structure sizes
        int[] invalidSizes = {-1, 0, 1, 2, 3, 5, 6, 8, 16, 32, 64, 128, 256, 512, 1024};
        
        for (int invalidSize : invalidSizes) {
            byte[] buffer = new byte[256];
            
            // Handle negative values (will wrap around in writeInt2)
            if (invalidSize >= 0) {
                SMBUtil.writeInt2(invalidSize, buffer, 0);
                
                // When & Then
                SMBProtocolDecodingException exception = assertThrows(
                    SMBProtocolDecodingException.class,
                    () -> response.readBytesWireFormat(buffer, 0),
                    "Should throw exception for structure size: " + invalidSize
                );
                assertEquals("Structure size != 4", exception.getMessage());
            }
        }
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
        Smb2TreeDisconnectResponse responseWithNull = new Smb2TreeDisconnectResponse(null);
        
        // Then - response is created successfully
        assertNotNull(responseWithNull);
    }

    @Test
    @DisplayName("Should return consistent bytes read for valid structure")
    void testConsistentBytesRead() throws SMBProtocolDecodingException {
        // Given - 10 different valid buffers
        for (int i = 0; i < 10; i++) {
            byte[] buffer = new byte[256];
            SMBUtil.writeInt2(4, buffer, i * 10);
            SMBUtil.writeInt2(i, buffer, i * 10 + 2); // Different reserved values
            
            // When
            int bytesRead = response.readBytesWireFormat(buffer, i * 10);
            
            // Then
            assertEquals(4, bytesRead, "Iteration " + i + " should read 4 bytes");
        }
    }

    @Test
    @DisplayName("Should verify complete response structure parsing")
    void testCompleteResponseParsing() throws SMBProtocolDecodingException {
        // Given - complete SMB2 TREE_DISCONNECT response
        byte[] completeResponse = new byte[] {
            0x04, 0x00,  // StructureSize = 4
            0x00, 0x00   // Reserved = 0
        };

        // When
        int bytesRead = response.readBytesWireFormat(completeResponse, 0);

        // Then
        assertEquals(4, bytesRead);
        assertEquals(completeResponse.length, bytesRead);
    }
}
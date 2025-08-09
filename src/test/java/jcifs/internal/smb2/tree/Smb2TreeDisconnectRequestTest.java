package jcifs.internal.smb2.tree;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.times;

import java.lang.reflect.Field;
import java.lang.reflect.Method;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.junit.jupiter.MockitoExtension;

import jcifs.CIFSContext;
import jcifs.Configuration;
import jcifs.internal.smb2.ServerMessageBlock2;
import jcifs.internal.smb2.ServerMessageBlock2Request;
import jcifs.internal.smb2.Smb2Constants;
import jcifs.internal.util.SMBUtil;

/**
 * Test class for Smb2TreeDisconnectRequest functionality
 */
@DisplayName("Smb2TreeDisconnectRequest Tests")
@ExtendWith(MockitoExtension.class)
class Smb2TreeDisconnectRequestTest {

    private static final short SMB2_TREE_DISCONNECT = 0x0004;

    @Test
    @DisplayName("Should create request with correct command type")
    void testConstructorSetsCorrectCommand() throws Exception {
        // Given
        Configuration mockConfig = mock(Configuration.class);
        
        // When
        Smb2TreeDisconnectRequest req = new Smb2TreeDisconnectRequest(mockConfig);

        // Then - verify command is set correctly using reflection
        Field commandField = ServerMessageBlock2.class.getDeclaredField("command");
        commandField.setAccessible(true);
        int command = (int) commandField.get(req);
        
        assertEquals(SMB2_TREE_DISCONNECT, command);
    }

    @Test
    @DisplayName("Should create proper response object")
    void testCreateResponse() {
        // Given
        Configuration mockConfig = mock(Configuration.class);
        CIFSContext mockContext = mock(CIFSContext.class);
        when(mockContext.getConfig()).thenReturn(mockConfig);
        Smb2TreeDisconnectRequest request = new Smb2TreeDisconnectRequest(mockConfig);
        
        // When
        Smb2TreeDisconnectResponse response = request.createResponse(mockContext, request);

        // Then
        assertNotNull(response);
        assertTrue(response instanceof Smb2TreeDisconnectResponse);
        verify(mockContext, times(1)).getConfig();
    }

    @Test
    @DisplayName("Should calculate correct message size")
    void testSize() {
        // Given
        Configuration mockConfig = mock(Configuration.class);
        Smb2TreeDisconnectRequest request = new Smb2TreeDisconnectRequest(mockConfig);
        
        // When
        int size = request.size();

        // Then
        // SMB2_HEADER_LENGTH + 4 bytes for tree disconnect structure
        int expectedSize = Smb2Constants.SMB2_HEADER_LENGTH + 4;
        // size8 method aligns to 8-byte boundary
        int alignedSize = (expectedSize + 7) & ~7;
        assertEquals(alignedSize, size);
    }

    @Test
    @DisplayName("Should write correct bytes to wire format")
    void testWriteBytesWireFormat() {
        // Given
        Configuration mockConfig = mock(Configuration.class);
        Smb2TreeDisconnectRequest request = new Smb2TreeDisconnectRequest(mockConfig);
        byte[] buffer = new byte[256];
        int offset = 10;

        // When
        int bytesWritten = request.writeBytesWireFormat(buffer, offset);

        // Then
        assertEquals(4, bytesWritten);
        
        // Verify structure size (4) is written at offset
        assertEquals(4, SMBUtil.readInt2(buffer, offset));
        
        // Verify reserved field (0) is written at offset + 2
        assertEquals(0, SMBUtil.readInt2(buffer, offset + 2));
    }

    @Test
    @DisplayName("Should write exact wire format structure")
    void testWriteBytesWireFormatStructure() {
        // Given
        Configuration mockConfig = mock(Configuration.class);
        Smb2TreeDisconnectRequest request = new Smb2TreeDisconnectRequest(mockConfig);
        byte[] buffer = new byte[4];
        int offset = 0;

        // When
        int bytesWritten = request.writeBytesWireFormat(buffer, offset);

        // Then
        assertEquals(4, bytesWritten);
        
        // Expected wire format: [0x04, 0x00, 0x00, 0x00]
        byte[] expected = new byte[] {0x04, 0x00, 0x00, 0x00};
        assertArrayEquals(expected, buffer);
    }

    @Test
    @DisplayName("Should always return 0 for readBytesWireFormat")
    void testReadBytesWireFormat() {
        // Given
        Configuration mockConfig = mock(Configuration.class);
        Smb2TreeDisconnectRequest request = new Smb2TreeDisconnectRequest(mockConfig);
        byte[] buffer = createTestData(256);
        
        // When
        int bytesRead = request.readBytesWireFormat(buffer, 0);
        
        // Then
        assertEquals(0, bytesRead);
    }

    @ParameterizedTest
    @ValueSource(ints = {0, 10, 50, 100, 200})
    @DisplayName("Should write consistent structure at different offsets")
    void testWriteBytesAtDifferentOffsets(int offset) {
        // Given
        Configuration mockConfig = mock(Configuration.class);
        Smb2TreeDisconnectRequest request = new Smb2TreeDisconnectRequest(mockConfig);
        byte[] buffer = new byte[256];

        // When
        int bytesWritten = request.writeBytesWireFormat(buffer, offset);

        // Then
        assertEquals(4, bytesWritten);
        assertEquals(4, SMBUtil.readInt2(buffer, offset));
        assertEquals(0, SMBUtil.readInt2(buffer, offset + 2));
    }

    @Test
    @DisplayName("Should handle boundary conditions for buffer write")
    void testWriteBytesWireFormatBoundary() {
        // Given
        Configuration mockConfig = mock(Configuration.class);
        Smb2TreeDisconnectRequest request = new Smb2TreeDisconnectRequest(mockConfig);
        byte[] buffer = new byte[4];
        
        // When
        int bytesWritten = request.writeBytesWireFormat(buffer, 0);
        
        // Then
        assertEquals(4, bytesWritten);
        assertEquals(4, SMBUtil.readInt2(buffer, 0));
        assertEquals(0, SMBUtil.readInt2(buffer, 2));
    }

    @Test
    @DisplayName("Should throw exception when buffer too small")
    void testWriteBytesWireFormatBufferTooSmall() {
        // Given
        Configuration mockConfig = mock(Configuration.class);
        Smb2TreeDisconnectRequest request = new Smb2TreeDisconnectRequest(mockConfig);
        byte[] buffer = new byte[3]; // Too small for 4 bytes
        
        // When & Then
        assertThrows(ArrayIndexOutOfBoundsException.class, () -> {
            request.writeBytesWireFormat(buffer, 0);
        });
    }

    @Test
    @DisplayName("Should throw exception when offset exceeds buffer")
    void testWriteBytesWireFormatOffsetTooLarge() {
        // Given
        Configuration mockConfig = mock(Configuration.class);
        Smb2TreeDisconnectRequest request = new Smb2TreeDisconnectRequest(mockConfig);
        byte[] buffer = new byte[10];
        int offset = 8; // Only 2 bytes remaining, need 4
        
        // When & Then
        assertThrows(ArrayIndexOutOfBoundsException.class, () -> {
            request.writeBytesWireFormat(buffer, offset);
        });
    }

    @Test
    @DisplayName("Should correctly inherit from ServerMessageBlock2Request")
    void testInheritance() {
        // Given
        Configuration mockConfig = mock(Configuration.class);
        Smb2TreeDisconnectRequest request = new Smb2TreeDisconnectRequest(mockConfig);
        
        // Then
        assertTrue(request instanceof ServerMessageBlock2Request);
        assertTrue(request instanceof ServerMessageBlock2);
    }

    @Test
    @DisplayName("Should handle multiple write operations")
    void testMultipleWrites() {
        // Given
        Configuration mockConfig = mock(Configuration.class);
        Smb2TreeDisconnectRequest request = new Smb2TreeDisconnectRequest(mockConfig);
        byte[] buffer1 = new byte[256];
        byte[] buffer2 = new byte[256];
        
        // When
        int bytes1 = request.writeBytesWireFormat(buffer1, 0);
        int bytes2 = request.writeBytesWireFormat(buffer2, 10);
        
        // Then
        assertEquals(bytes1, bytes2);
        assertEquals(SMBUtil.readInt2(buffer1, 0), SMBUtil.readInt2(buffer2, 10));
    }

    @Test
    @DisplayName("Should maintain immutability of structure size")
    void testStructureSizeImmutability() {
        // Given
        Configuration mockConfig = mock(Configuration.class);
        Smb2TreeDisconnectRequest request = new Smb2TreeDisconnectRequest(mockConfig);
        byte[] buffer = new byte[256];
        
        // When - write multiple times
        for (int i = 0; i < 10; i++) {
            request.writeBytesWireFormat(buffer, i * 10);
        }
        
        // Then - all should have same structure size
        for (int i = 0; i < 10; i++) {
            assertEquals(4, SMBUtil.readInt2(buffer, i * 10));
        }
    }

    @Test
    @DisplayName("Should handle null configuration gracefully in response creation")
    void testCreateResponseWithNullConfig() {
        // Given
        Configuration mockConfig = mock(Configuration.class);
        Smb2TreeDisconnectRequest request = new Smb2TreeDisconnectRequest(mockConfig);
        CIFSContext nullConfigContext = mock(CIFSContext.class);
        when(nullConfigContext.getConfig()).thenReturn(null);
        
        // When
        Smb2TreeDisconnectResponse response = request.createResponse(nullConfigContext, request);
        
        // Then - response is created even with null config
        assertNotNull(response);
    }

    @Test
    @DisplayName("Should verify SMB2 header length constant usage")
    void testSmb2HeaderLengthUsage() {
        // Given
        Configuration mockConfig = mock(Configuration.class);
        Smb2TreeDisconnectRequest request = new Smb2TreeDisconnectRequest(mockConfig);
        
        // When
        int size = request.size();
        
        // Then
        // Verify size includes SMB2_HEADER_LENGTH
        assertTrue(size >= Smb2Constants.SMB2_HEADER_LENGTH);
        
        // The actual calculation: (SMB2_HEADER_LENGTH + 4 + 7) & ~7
        int expectedBase = Smb2Constants.SMB2_HEADER_LENGTH + 4;
        int expectedAligned = (expectedBase + 7) & ~7;
        assertEquals(expectedAligned, size);
    }

    @Test
    @DisplayName("Should write zeros for reserved field")
    void testReservedFieldIsZero() {
        // Given
        Configuration mockConfig = mock(Configuration.class);
        Smb2TreeDisconnectRequest request = new Smb2TreeDisconnectRequest(mockConfig);
        byte[] buffer = new byte[256];
        // Fill with non-zero values first
        for (int i = 0; i < buffer.length; i++) {
            buffer[i] = (byte) 0xFF;
        }
        
        // When
        request.writeBytesWireFormat(buffer, 10);
        
        // Then - verify reserved field is zero
        assertEquals(0, SMBUtil.readInt2(buffer, 12));
    }

    @Test
    @DisplayName("Should verify size8 alignment")
    void testSize8Alignment() throws Exception {
        // Given
        Configuration mockConfig = mock(Configuration.class);
        Smb2TreeDisconnectRequest request = new Smb2TreeDisconnectRequest(mockConfig);
        
        // Access size8 method via reflection
        Method size8Method = ServerMessageBlock2.class.getDeclaredMethod("size8", int.class);
        size8Method.setAccessible(true);
        
        // When & Then - test various sizes for 8-byte alignment
        assertEquals(8, size8Method.invoke(request, 1));
        assertEquals(8, size8Method.invoke(request, 8));
        assertEquals(16, size8Method.invoke(request, 9));
        assertEquals(72, size8Method.invoke(request, 68)); // SMB2_HEADER_LENGTH + 4 = 68
    }

    @Test
    @DisplayName("Should maintain consistent command type")
    void testCommandTypeConsistency() throws Exception {
        // Given
        Configuration mockConfig = mock(Configuration.class);
        Field commandField = ServerMessageBlock2.class.getDeclaredField("command");
        commandField.setAccessible(true);
        
        // When - create multiple instances
        Smb2TreeDisconnectRequest req1 = new Smb2TreeDisconnectRequest(mockConfig);
        Smb2TreeDisconnectRequest req2 = new Smb2TreeDisconnectRequest(mockConfig);
        
        // Then - all should have same command
        int cmd1 = (int) commandField.get(req1);
        int cmd2 = (int) commandField.get(req2);
        
        assertEquals(cmd1, cmd2);
        assertEquals(SMB2_TREE_DISCONNECT, cmd1);
    }

    @Test
    @DisplayName("Should properly implement wire format protocol")
    void testWireFormatProtocol() {
        // Given
        Configuration mockConfig = mock(Configuration.class);
        Smb2TreeDisconnectRequest request = new Smb2TreeDisconnectRequest(mockConfig);
        byte[] expectedStructure = new byte[] {
            0x04, 0x00,  // Structure size (4)
            0x00, 0x00   // Reserved
        };
        
        byte[] buffer = new byte[4];
        
        // When
        int written = request.writeBytesWireFormat(buffer, 0);
        
        // Then
        assertEquals(4, written);
        assertArrayEquals(expectedStructure, buffer);
    }

    @Test
    @DisplayName("Should verify request does not read response data")
    void testRequestDoesNotReadData() {
        // Given
        Configuration mockConfig = mock(Configuration.class);
        Smb2TreeDisconnectRequest request = new Smb2TreeDisconnectRequest(mockConfig);
        
        // Various buffer contents
        byte[] emptyBuffer = new byte[256];
        byte[] fullBuffer = createTestData(256);
        
        // When
        int emptyRead = request.readBytesWireFormat(emptyBuffer, 0);
        int fullRead = request.readBytesWireFormat(fullBuffer, 50);
        
        // Then - always returns 0 as this is a request, not response
        assertEquals(0, emptyRead);
        assertEquals(0, fullRead);
    }
    
    /**
     * Create a test byte array with specified size and pattern
     */
    private byte[] createTestData(int size) {
        byte[] data = new byte[size];
        for (int i = 0; i < size; i++) {
            data[i] = (byte) (i % 256);
        }
        return data;
    }
}
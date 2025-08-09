/*
 * © 2025 jcifs project contributors
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
package jcifs.internal.smb1.trans;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import jcifs.Configuration;
import jcifs.internal.util.SMBUtil;

/**
 * Test class for TransPeekNamedPipeResponse
 */
class TransPeekNamedPipeResponseTest {

    @Mock
    private Configuration mockConfig;

    private TransPeekNamedPipeResponse response;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        response = new TransPeekNamedPipeResponse(mockConfig);
    }

    @Test
    @DisplayName("Constructor should initialize TransPeekNamedPipeResponse")
    void testConstructor() {
        // Assert
        assertNotNull(response);
        assertTrue(response instanceof SmbComTransactionResponse);
        assertEquals(0, response.getAvailable());
    }

    @Test
    @DisplayName("Should verify status constants are correctly defined")
    void testStatusConstants() {
        // Assert
        assertEquals(1, TransPeekNamedPipeResponse.STATUS_DISCONNECTED);
        assertEquals(2, TransPeekNamedPipeResponse.STATUS_LISTENING);
        assertEquals(3, TransPeekNamedPipeResponse.STATUS_CONNECTION_OK);
        assertEquals(4, TransPeekNamedPipeResponse.STATUS_SERVER_END_CLOSED);
    }

    @Test
    @DisplayName("getAvailable should return initial value of 0")
    void testGetAvailableInitialValue() {
        // Assert
        assertEquals(0, response.getAvailable());
    }

    @Test
    @DisplayName("writeSetupWireFormat should return 0")
    void testWriteSetupWireFormat() {
        // Arrange
        byte[] dst = new byte[100];
        int dstIndex = 0;

        // Act
        int result = response.writeSetupWireFormat(dst, dstIndex);

        // Assert
        assertEquals(0, result);
    }

    @Test
    @DisplayName("writeSetupWireFormat with offset should return 0")
    void testWriteSetupWireFormatWithOffset() {
        // Arrange
        byte[] dst = new byte[100];
        int dstIndex = 50;

        // Act
        int result = response.writeSetupWireFormat(dst, dstIndex);

        // Assert
        assertEquals(0, result);
    }

    @Test
    @DisplayName("writeParametersWireFormat should return 0")
    void testWriteParametersWireFormat() {
        // Arrange
        byte[] dst = new byte[100];
        int dstIndex = 0;

        // Act
        int result = response.writeParametersWireFormat(dst, dstIndex);

        // Assert
        assertEquals(0, result);
    }

    @Test
    @DisplayName("writeDataWireFormat should return 0")
    void testWriteDataWireFormat() {
        // Arrange
        byte[] dst = new byte[100];
        int dstIndex = 0;

        // Act
        int result = response.writeDataWireFormat(dst, dstIndex);

        // Assert
        assertEquals(0, result);
    }

    @Test
    @DisplayName("readSetupWireFormat should return 0")
    void testReadSetupWireFormat() {
        // Arrange
        byte[] buffer = new byte[100];
        int bufferIndex = 0;
        int len = 100;

        // Act
        int result = response.readSetupWireFormat(buffer, bufferIndex, len);

        // Assert
        assertEquals(0, result);
    }

    @Test
    @DisplayName("readParametersWireFormat should parse available bytes and status correctly")
    void testReadParametersWireFormat() {
        // Arrange
        byte[] buffer = new byte[10];
        int bufferIndex = 0;
        int len = 6;
        
        // Set up buffer with test data
        // available = 0x1234 (4660 in decimal)
        SMBUtil.writeInt2(0x1234, buffer, bufferIndex);
        // next 2 bytes (ignored in implementation)
        SMBUtil.writeInt2(0xABCD, buffer, bufferIndex + 2);
        // status = STATUS_CONNECTION_OK (3)
        SMBUtil.writeInt2(TransPeekNamedPipeResponse.STATUS_CONNECTION_OK, buffer, bufferIndex + 4);

        // Act
        int result = response.readParametersWireFormat(buffer, bufferIndex, len);

        // Assert
        assertEquals(6, result);
        assertEquals(0x1234, response.getAvailable());
        assertEquals(TransPeekNamedPipeResponse.STATUS_CONNECTION_OK, response.getStatus());
    }

    @Test
    @DisplayName("readParametersWireFormat should handle different status values")
    void testReadParametersWireFormatWithDifferentStatuses() {
        // Test all status constants
        int[] statusValues = {
            TransPeekNamedPipeResponse.STATUS_DISCONNECTED,
            TransPeekNamedPipeResponse.STATUS_LISTENING,
            TransPeekNamedPipeResponse.STATUS_CONNECTION_OK,
            TransPeekNamedPipeResponse.STATUS_SERVER_END_CLOSED
        };

        for (int status : statusValues) {
            // Arrange
            byte[] buffer = new byte[10];
            int bufferIndex = 0;
            
            SMBUtil.writeInt2(100, buffer, bufferIndex);
            SMBUtil.writeInt2(0, buffer, bufferIndex + 2);
            SMBUtil.writeInt2(status, buffer, bufferIndex + 4);
            
            TransPeekNamedPipeResponse testResponse = new TransPeekNamedPipeResponse(mockConfig);

            // Act
            int result = testResponse.readParametersWireFormat(buffer, bufferIndex, 6);

            // Assert
            assertEquals(6, result);
            assertEquals(100, testResponse.getAvailable());
            assertEquals(status, testResponse.getStatus());
        }
    }

    @ParameterizedTest
    @ValueSource(ints = {0, 1, 100, 255, 1000, 32767, 65535})
    @DisplayName("readParametersWireFormat should handle various available values")
    void testReadParametersWireFormatWithVariousAvailableValues(int available) {
        // Arrange
        byte[] buffer = new byte[10];
        int bufferIndex = 0;
        
        SMBUtil.writeInt2(available, buffer, bufferIndex);
        SMBUtil.writeInt2(0, buffer, bufferIndex + 2);
        SMBUtil.writeInt2(TransPeekNamedPipeResponse.STATUS_CONNECTION_OK, buffer, bufferIndex + 4);

        // Act
        int result = response.readParametersWireFormat(buffer, bufferIndex, 6);

        // Assert
        assertEquals(6, result);
        assertEquals(available, response.getAvailable());
    }

    @Test
    @DisplayName("readParametersWireFormat with offset should work correctly")
    void testReadParametersWireFormatWithOffset() {
        // Arrange
        byte[] buffer = new byte[20];
        int bufferIndex = 10;
        
        // Write data at offset
        SMBUtil.writeInt2(500, buffer, bufferIndex);
        SMBUtil.writeInt2(0, buffer, bufferIndex + 2);
        SMBUtil.writeInt2(TransPeekNamedPipeResponse.STATUS_LISTENING, buffer, bufferIndex + 4);

        // Act
        int result = response.readParametersWireFormat(buffer, bufferIndex, 6);

        // Assert
        assertEquals(6, result);
        assertEquals(500, response.getAvailable());
        assertEquals(TransPeekNamedPipeResponse.STATUS_LISTENING, response.getStatus());
    }

    @Test
    @DisplayName("readDataWireFormat should return 0")
    void testReadDataWireFormat() {
        // Arrange
        byte[] buffer = new byte[100];
        int bufferIndex = 0;
        int len = 100;

        // Act
        int result = response.readDataWireFormat(buffer, bufferIndex, len);

        // Assert
        assertEquals(0, result);
    }

    @Test
    @DisplayName("toString should return formatted string")
    void testToString() {
        // Act
        String result = response.toString();

        // Assert
        assertNotNull(result);
        assertTrue(result.contains("TransPeekNamedPipeResponse["));
        assertTrue(result.endsWith("]"));
    }

    @Test
    @DisplayName("toString should include parent class information")
    void testToStringIncludesParentInfo() {
        // Act
        String result = response.toString();

        // Assert
        assertNotNull(result);
        assertTrue(result.contains("TransPeekNamedPipeResponse"));
        // Verify that parent's toString is called (should contain standard fields)
        assertTrue(result.length() > "TransPeekNamedPipeResponse[]".length());
    }

    @Test
    @DisplayName("Multiple instances should be independent")
    void testMultipleInstances() {
        // Arrange
        TransPeekNamedPipeResponse response1 = new TransPeekNamedPipeResponse(mockConfig);
        TransPeekNamedPipeResponse response2 = new TransPeekNamedPipeResponse(mockConfig);

        // Act
        byte[] buffer = new byte[10];
        SMBUtil.writeInt2(100, buffer, 0);
        SMBUtil.writeInt2(0, buffer, 2);
        SMBUtil.writeInt2(TransPeekNamedPipeResponse.STATUS_CONNECTION_OK, buffer, 4);
        
        response1.readParametersWireFormat(buffer, 0, 6);

        // Assert
        assertNotSame(response1, response2);
        assertEquals(100, response1.getAvailable());
        assertEquals(0, response2.getAvailable());
    }

    @Test
    @DisplayName("All write methods should consistently return 0")
    void testAllWriteMethodsReturnZero() {
        // Arrange
        byte[] buffer = new byte[100];

        // Act & Assert
        assertEquals(0, response.writeSetupWireFormat(buffer, 0));
        assertEquals(0, response.writeParametersWireFormat(buffer, 0));
        assertEquals(0, response.writeDataWireFormat(buffer, 0));
    }

    @Test
    @DisplayName("All read methods except readParametersWireFormat should return 0")
    void testReadMethodsReturnValues() {
        // Arrange
        byte[] buffer = new byte[100];
        SMBUtil.writeInt2(0, buffer, 0);
        SMBUtil.writeInt2(0, buffer, 2);
        SMBUtil.writeInt2(0, buffer, 4);

        // Act & Assert
        assertEquals(0, response.readSetupWireFormat(buffer, 0, 100));
        assertEquals(6, response.readParametersWireFormat(buffer, 0, 100));
        assertEquals(0, response.readDataWireFormat(buffer, 0, 100));
    }

    @Test
    @DisplayName("Methods should handle empty buffer")
    void testMethodsWithEmptyBuffer() {
        // Arrange
        byte[] emptyBuffer = new byte[0];

        // Act & Assert - These should not throw exceptions
        assertEquals(0, response.writeSetupWireFormat(emptyBuffer, 0));
        assertEquals(0, response.writeParametersWireFormat(emptyBuffer, 0));
        assertEquals(0, response.writeDataWireFormat(emptyBuffer, 0));
        assertEquals(0, response.readSetupWireFormat(emptyBuffer, 0, 0));
        assertEquals(0, response.readDataWireFormat(emptyBuffer, 0, 0));
        
        // readParametersWireFormat would throw exception due to buffer underflow
        assertThrows(Exception.class, () -> {
            response.readParametersWireFormat(emptyBuffer, 0, 0);
        });
    }

    @Test
    @DisplayName("Test inherited behavior from parent class")
    void testInheritedBehavior() {
        // Test that response inherits from SmbComTransactionResponse
        assertTrue(response.hasMoreElements());
        assertNotNull(response.nextElement());
        
        // Test reset behavior
        response.reset();
        assertTrue(response.hasMoreElements());
    }

    @Test
    @DisplayName("Verify Configuration is passed to parent")
    void testConfigurationPassedToParent() {
        // Arrange
        Configuration testConfig = mock(Configuration.class);
        
        // Act
        TransPeekNamedPipeResponse testResponse = new TransPeekNamedPipeResponse(testConfig);
        
        // Assert
        assertNotNull(testResponse);
    }

    @Test
    @DisplayName("Test state changes after reading parameters")
    void testStateAfterReadingParameters() {
        // Arrange
        byte[] buffer = new byte[10];
        SMBUtil.writeInt2(1500, buffer, 0);
        SMBUtil.writeInt2(0xFFFF, buffer, 2);
        SMBUtil.writeInt2(TransPeekNamedPipeResponse.STATUS_DISCONNECTED, buffer, 4);

        // Act
        response.readParametersWireFormat(buffer, 0, 6);

        // Assert
        assertEquals(1500, response.getAvailable());
        assertEquals(TransPeekNamedPipeResponse.STATUS_DISCONNECTED, response.getStatus());
    }

    @Test
    @DisplayName("Test boundary conditions for available value")
    void testBoundaryAvailableValues() {
        // Test minimum value (0)
        byte[] buffer = new byte[10];
        SMBUtil.writeInt2(0, buffer, 0);
        SMBUtil.writeInt2(0, buffer, 2);
        SMBUtil.writeInt2(TransPeekNamedPipeResponse.STATUS_CONNECTION_OK, buffer, 4);
        
        response.readParametersWireFormat(buffer, 0, 6);
        assertEquals(0, response.getAvailable());
        
        // Test maximum unsigned 16-bit value (65535)
        SMBUtil.writeInt2(0xFFFF, buffer, 0);
        TransPeekNamedPipeResponse response2 = new TransPeekNamedPipeResponse(mockConfig);
        response2.readParametersWireFormat(buffer, 0, 6);
        assertEquals(0xFFFF, response2.getAvailable());
    }

    @Test
    @DisplayName("Test large buffer handling")
    void testLargeBufferHandling() {
        // Arrange
        byte[] largeBuffer = new byte[65536]; // 64KB buffer
        
        // Act & Assert
        assertEquals(0, response.writeSetupWireFormat(largeBuffer, 0));
        assertEquals(0, response.writeParametersWireFormat(largeBuffer, 32768));
        assertEquals(0, response.writeDataWireFormat(largeBuffer, 65535));
        assertEquals(0, response.readSetupWireFormat(largeBuffer, 0, 65536));
        assertEquals(0, response.readDataWireFormat(largeBuffer, 0, 65536));
    }

    @Test
    @DisplayName("Test readParametersWireFormat with insufficient buffer length")
    void testReadParametersWireFormatInsufficientLength() {
        // Arrange
        byte[] buffer = new byte[10];
        SMBUtil.writeInt2(100, buffer, 0);
        SMBUtil.writeInt2(0, buffer, 2);
        SMBUtil.writeInt2(TransPeekNamedPipeResponse.STATUS_CONNECTION_OK, buffer, 4);

        // Act - Still returns 6 even if len is smaller
        int result = response.readParametersWireFormat(buffer, 0, 3);

        // Assert
        assertEquals(6, result);
    }

    @Test
    @DisplayName("Test readParametersWireFormat ignores middle 2 bytes")
    void testReadParametersWireFormatIgnoresMiddleBytes() {
        // Arrange
        byte[] buffer = new byte[10];
        SMBUtil.writeInt2(200, buffer, 0);
        // These bytes should be ignored
        buffer[2] = (byte) 0xFF;
        buffer[3] = (byte) 0xFF;
        SMBUtil.writeInt2(TransPeekNamedPipeResponse.STATUS_LISTENING, buffer, 4);

        // Act
        int result = response.readParametersWireFormat(buffer, 0, 6);

        // Assert
        assertEquals(6, result);
        assertEquals(200, response.getAvailable());
        assertEquals(TransPeekNamedPipeResponse.STATUS_LISTENING, response.getStatus());
        // Middle bytes were read but not used
    }

    @Test
    @DisplayName("Test consecutive reads update state correctly")
    void testConsecutiveReads() {
        // First read
        byte[] buffer1 = new byte[10];
        SMBUtil.writeInt2(100, buffer1, 0);
        SMBUtil.writeInt2(0, buffer1, 2);
        SMBUtil.writeInt2(TransPeekNamedPipeResponse.STATUS_CONNECTION_OK, buffer1, 4);
        
        response.readParametersWireFormat(buffer1, 0, 6);
        assertEquals(100, response.getAvailable());
        assertEquals(TransPeekNamedPipeResponse.STATUS_CONNECTION_OK, response.getStatus());
        
        // Second read - should update values
        byte[] buffer2 = new byte[10];
        SMBUtil.writeInt2(500, buffer2, 0);
        SMBUtil.writeInt2(0, buffer2, 2);
        SMBUtil.writeInt2(TransPeekNamedPipeResponse.STATUS_DISCONNECTED, buffer2, 4);
        
        response.readParametersWireFormat(buffer2, 0, 6);
        assertEquals(500, response.getAvailable());
        assertEquals(TransPeekNamedPipeResponse.STATUS_DISCONNECTED, response.getStatus());
    }
}
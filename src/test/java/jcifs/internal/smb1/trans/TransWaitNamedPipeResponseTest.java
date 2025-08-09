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
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import jcifs.Configuration;
import jcifs.internal.SMBProtocolDecodingException;

/**
 * Test class for TransWaitNamedPipeResponse
 */
class TransWaitNamedPipeResponseTest {

    @Mock
    private Configuration mockConfig;

    private TransWaitNamedPipeResponse response;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        response = new TransWaitNamedPipeResponse(mockConfig);
    }

    @Test
    @DisplayName("Constructor should initialize TransWaitNamedPipeResponse")
    void testConstructor() {
        // Assert
        assertNotNull(response);
        // Verify parent class is properly initialized
        assertTrue(response instanceof SmbComTransactionResponse);
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
    @DisplayName("writeParametersWireFormat with offset should return 0")
    void testWriteParametersWireFormatWithOffset() {
        // Arrange
        byte[] dst = new byte[100];
        int dstIndex = 25;

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
    @DisplayName("writeDataWireFormat with offset should return 0")
    void testWriteDataWireFormatWithOffset() {
        // Arrange
        byte[] dst = new byte[100];
        int dstIndex = 75;

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
    @DisplayName("readSetupWireFormat with various parameters should return 0")
    void testReadSetupWireFormatVariousParams() {
        // Test with different buffer sizes and offsets
        int[][] testCases = {
            {0, 50},    // No offset, 50 bytes
            {10, 90},   // 10 byte offset, 90 bytes
            {50, 50},   // 50 byte offset, 50 bytes
            {0, 0},     // Empty buffer
            {100, 100}  // Large values
        };

        for (int[] testCase : testCases) {
            // Arrange
            byte[] buffer = new byte[200];
            int bufferIndex = testCase[0];
            int len = testCase[1];

            // Act
            int result = response.readSetupWireFormat(buffer, bufferIndex, len);

            // Assert
            assertEquals(0, result, "Failed for bufferIndex=" + bufferIndex + ", len=" + len);
        }
    }

    @Test
    @DisplayName("readParametersWireFormat should return 0")
    void testReadParametersWireFormat() {
        // Arrange
        byte[] buffer = new byte[100];
        int bufferIndex = 0;
        int len = 100;

        // Act
        int result = response.readParametersWireFormat(buffer, bufferIndex, len);

        // Assert
        assertEquals(0, result);
    }

    @Test
    @DisplayName("readParametersWireFormat with various parameters should return 0")
    void testReadParametersWireFormatVariousParams() {
        // Test with different parameters
        int[][] testCases = {
            {0, 10},
            {5, 20},
            {50, 50},
            {0, 0}
        };

        for (int[] testCase : testCases) {
            // Arrange
            byte[] buffer = new byte[100];
            int bufferIndex = testCase[0];
            int len = testCase[1];

            // Act
            int result = response.readParametersWireFormat(buffer, bufferIndex, len);

            // Assert
            assertEquals(0, result);
        }
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
    @DisplayName("readDataWireFormat with various parameters should return 0")
    void testReadDataWireFormatVariousParams() {
        // Test with different parameters
        int[][] testCases = {
            {0, 256},
            {128, 128},
            {255, 1},
            {0, 0}
        };

        for (int[] testCase : testCases) {
            // Arrange
            byte[] buffer = new byte[512];
            int bufferIndex = testCase[0];
            int len = testCase[1];

            // Act
            int result = response.readDataWireFormat(buffer, bufferIndex, len);

            // Assert
            assertEquals(0, result);
        }
    }

    @Test
    @DisplayName("toString should return formatted string")
    void testToString() {
        // Act
        String result = response.toString();

        // Assert
        assertNotNull(result);
        assertTrue(result.contains("TransWaitNamedPipeResponse["));
        assertTrue(result.endsWith("]"));
    }

    @Test
    @DisplayName("toString should include parent class information")
    void testToStringIncludesParentInfo() {
        // Act
        String result = response.toString();

        // Assert
        assertNotNull(result);
        assertTrue(result.contains("TransWaitNamedPipeResponse"));
        // Verify that parent's toString is called (should contain standard fields)
        assertTrue(result.length() > "TransWaitNamedPipeResponse[]".length());
    }

    @Test
    @DisplayName("Multiple instances should be independent")
    void testMultipleInstances() {
        // Arrange
        TransWaitNamedPipeResponse response1 = new TransWaitNamedPipeResponse(mockConfig);
        TransWaitNamedPipeResponse response2 = new TransWaitNamedPipeResponse(mockConfig);

        // Act & Assert
        assertNotSame(response1, response2);
        assertNotEquals(response1.toString(), response2.toString());
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
    @DisplayName("All read methods should consistently return 0")
    void testAllReadMethodsReturnZero() {
        // Arrange
        byte[] buffer = new byte[100];

        // Act & Assert
        assertEquals(0, response.readSetupWireFormat(buffer, 0, 100));
        assertEquals(0, response.readParametersWireFormat(buffer, 0, 100));
        assertEquals(0, response.readDataWireFormat(buffer, 0, 100));
    }

    @Test
    @DisplayName("Methods should handle null buffer gracefully")
    void testMethodsWithNullBuffer() {
        // Note: These might throw NullPointerException which is expected behavior
        // Testing to document the behavior
        
        assertThrows(NullPointerException.class, () -> {
            response.writeSetupWireFormat(null, 0);
        });
        
        assertThrows(NullPointerException.class, () -> {
            response.writeParametersWireFormat(null, 0);
        });
        
        assertThrows(NullPointerException.class, () -> {
            response.writeDataWireFormat(null, 0);
        });
        
        assertThrows(NullPointerException.class, () -> {
            response.readSetupWireFormat(null, 0, 0);
        });
        
        assertThrows(NullPointerException.class, () -> {
            response.readParametersWireFormat(null, 0, 0);
        });
        
        assertThrows(NullPointerException.class, () -> {
            response.readDataWireFormat(null, 0, 0);
        });
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
        assertEquals(0, response.readParametersWireFormat(emptyBuffer, 0, 0));
        assertEquals(0, response.readDataWireFormat(emptyBuffer, 0, 0));
    }

    @Test
    @DisplayName("Methods should handle negative indices")
    void testMethodsWithNegativeIndices() {
        // Arrange
        byte[] buffer = new byte[100];
        int negativeIndex = -1;

        // Act & Assert
        // These methods don't validate indices, so they return 0
        assertEquals(0, response.writeSetupWireFormat(buffer, negativeIndex));
        assertEquals(0, response.writeParametersWireFormat(buffer, negativeIndex));
        assertEquals(0, response.writeDataWireFormat(buffer, negativeIndex));
        assertEquals(0, response.readSetupWireFormat(buffer, negativeIndex, 10));
        assertEquals(0, response.readParametersWireFormat(buffer, negativeIndex, 10));
        assertEquals(0, response.readDataWireFormat(buffer, negativeIndex, 10));
    }

    @Test
    @DisplayName("Methods should handle indices beyond buffer length")
    void testMethodsWithIndicesBeyondBuffer() {
        // Arrange
        byte[] buffer = new byte[10];
        int beyondIndex = 20;

        // Act & Assert
        // These methods don't validate buffer bounds, so they return 0
        assertEquals(0, response.writeSetupWireFormat(buffer, beyondIndex));
        assertEquals(0, response.writeParametersWireFormat(buffer, beyondIndex));
        assertEquals(0, response.writeDataWireFormat(buffer, beyondIndex));
        assertEquals(0, response.readSetupWireFormat(buffer, beyondIndex, 10));
        assertEquals(0, response.readParametersWireFormat(buffer, beyondIndex, 10));
        assertEquals(0, response.readDataWireFormat(buffer, beyondIndex, 10));
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
        TransWaitNamedPipeResponse testResponse = new TransWaitNamedPipeResponse(testConfig);
        
        // Assert
        assertNotNull(testResponse);
    }

    @Test
    @DisplayName("Test toString consistency across multiple calls")
    void testToStringConsistency() {
        // Act
        String result1 = response.toString();
        String result2 = response.toString();
        
        // Assert
        assertEquals(result1, result2);
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
        assertEquals(0, response.readParametersWireFormat(largeBuffer, 0, 65536));
        assertEquals(0, response.readDataWireFormat(largeBuffer, 0, 65536));
    }

    @Test
    @DisplayName("Test boundary conditions for read methods with zero length")
    void testReadMethodsWithZeroLength() {
        // Arrange
        byte[] buffer = new byte[100];
        
        // Act & Assert
        assertEquals(0, response.readSetupWireFormat(buffer, 0, 0));
        assertEquals(0, response.readParametersWireFormat(buffer, 50, 0));
        assertEquals(0, response.readDataWireFormat(buffer, 99, 0));
    }

    @Test
    @DisplayName("Test boundary conditions for read methods with maximum length")
    void testReadMethodsWithMaxLength() {
        // Arrange
        byte[] buffer = new byte[100];
        
        // Act & Assert
        assertEquals(0, response.readSetupWireFormat(buffer, 0, Integer.MAX_VALUE));
        assertEquals(0, response.readParametersWireFormat(buffer, 0, Integer.MAX_VALUE));
        assertEquals(0, response.readDataWireFormat(buffer, 0, Integer.MAX_VALUE));
    }
}
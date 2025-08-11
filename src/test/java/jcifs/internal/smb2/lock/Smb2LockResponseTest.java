package jcifs.internal.smb2.lock;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import jcifs.Configuration;
import jcifs.internal.SMBProtocolDecodingException;
import jcifs.internal.util.SMBUtil;

class Smb2LockResponseTest {

    @Mock
    private Configuration mockConfig;

    private Smb2LockResponse response;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        response = new Smb2LockResponse(mockConfig);
    }

    @Test
    @DisplayName("Constructor should initialize with Configuration")
    void testConstructor() {
        // Given & When
        Smb2LockResponse lockResponse = new Smb2LockResponse(mockConfig);
        
        // Then
        assertNotNull(lockResponse);
        // Verify it's an instance of ServerMessageBlock2Response
        assertTrue(lockResponse instanceof jcifs.internal.smb2.ServerMessageBlock2Response);
    }

    @Test
    @DisplayName("Constructor should handle null configuration")
    void testConstructorWithNullConfig() {
        // Given & When
        Smb2LockResponse lockResponse = new Smb2LockResponse(null);
        
        // Then
        assertNotNull(lockResponse);
    }

    @Nested
    @DisplayName("writeBytesWireFormat tests")
    class WriteBytesWireFormatTests {
        
        @Test
        @DisplayName("Should always return 0 for write bytes")
        void testWriteBytesWireFormat() {
            // Given
            byte[] dst = new byte[100];
            int dstIndex = 0;
            
            // When
            int result = response.writeBytesWireFormat(dst, dstIndex);
            
            // Then
            assertEquals(0, result);
        }
        
        @Test
        @DisplayName("Should return 0 regardless of destination index")
        void testWriteBytesWireFormatWithVariousIndices() {
            // Given
            byte[] dst = new byte[100];
            
            // When & Then
            assertEquals(0, response.writeBytesWireFormat(dst, 0));
            assertEquals(0, response.writeBytesWireFormat(dst, 25));
            assertEquals(0, response.writeBytesWireFormat(dst, 50));
            assertEquals(0, response.writeBytesWireFormat(dst, 75));
            assertEquals(0, response.writeBytesWireFormat(dst, 99));
        }
        
        @Test
        @DisplayName("Should return 0 with empty array")
        void testWriteBytesWireFormatWithEmptyArray() {
            // Given
            byte[] dst = new byte[0];
            
            // When
            int result = response.writeBytesWireFormat(dst, 0);
            
            // Then
            assertEquals(0, result);
        }
        
        @Test
        @DisplayName("Should return 0 with null array")
        void testWriteBytesWireFormatWithNullArray() {
            // Given
            byte[] dst = null;
            
            // When
            int result = response.writeBytesWireFormat(dst, 0);
            
            // Then
            assertEquals(0, result);
        }
        
        @Test
        @DisplayName("Should handle large arrays efficiently")
        void testWriteBytesWireFormatWithLargeArray() {
            // Given
            byte[] dst = new byte[65536]; // 64KB array
            
            // When
            int result = response.writeBytesWireFormat(dst, 32768);
            
            // Then
            assertEquals(0, result);
        }
    }

    @Nested
    @DisplayName("readBytesWireFormat tests")
    class ReadBytesWireFormatTests {
        
        @Test
        @DisplayName("Should read valid structure with size 4")
        void testReadBytesWireFormatValidStructure() throws SMBProtocolDecodingException {
            // Given
            byte[] buffer = new byte[10];
            int bufferIndex = 0;
            SMBUtil.writeInt2(4, buffer, bufferIndex); // Write structure size = 4
            SMBUtil.writeInt2(0, buffer, bufferIndex + 2); // Reserved field
            
            // When
            int bytesRead = response.readBytesWireFormat(buffer, bufferIndex);
            
            // Then
            assertEquals(4, bytesRead);
        }
        
        @Test
        @DisplayName("Should read from various buffer positions")
        void testReadBytesWireFormatAtDifferentPositions() throws SMBProtocolDecodingException {
            // Given
            byte[] buffer = new byte[20];
            int[] positions = {0, 2, 4, 8, 10, 15};
            
            for (int pos : positions) {
                // Clear buffer
                buffer = new byte[20];
                SMBUtil.writeInt2(4, buffer, pos);
                SMBUtil.writeInt2(0, buffer, pos + 2);
                
                // When
                int bytesRead = response.readBytesWireFormat(buffer, pos);
                
                // Then
                assertEquals(4, bytesRead, "Failed at position " + pos);
            }
        }
        
        @Test
        @DisplayName("Should throw exception for invalid structure size")
        void testReadBytesWireFormatInvalidStructureSize() {
            // Given
            byte[] buffer = new byte[10];
            int bufferIndex = 0;
            SMBUtil.writeInt2(5, buffer, bufferIndex); // Invalid structure size
            
            // When & Then
            SMBProtocolDecodingException exception = assertThrows(
                SMBProtocolDecodingException.class,
                () -> response.readBytesWireFormat(buffer, bufferIndex)
            );
            assertEquals("Expected structureSize = 4", exception.getMessage());
        }
        
        @ParameterizedTest
        @ValueSource(ints = {0, 1, 2, 3, 5, 6, 8, 16, 100, 255, 1024, 4096, 65535})
        @DisplayName("Should throw exception for various invalid structure sizes")
        void testReadBytesWireFormatVariousInvalidSizes(int invalidSize) {
            // Given
            byte[] buffer = new byte[10];
            int bufferIndex = 0;
            SMBUtil.writeInt2(invalidSize, buffer, bufferIndex);
            
            // When & Then
            SMBProtocolDecodingException exception = assertThrows(
                SMBProtocolDecodingException.class,
                () -> response.readBytesWireFormat(buffer, bufferIndex)
            );
            assertEquals("Expected structureSize = 4", exception.getMessage());
        }
        
        @Test
        @DisplayName("Should handle buffer with exact required size")
        void testReadBytesWireFormatExactBufferSize() throws SMBProtocolDecodingException {
            // Given
            byte[] buffer = new byte[4];
            SMBUtil.writeInt2(4, buffer, 0);
            SMBUtil.writeInt2(0, buffer, 2);
            
            // When
            int bytesRead = response.readBytesWireFormat(buffer, 0);
            
            // Then
            assertEquals(4, bytesRead);
        }
        
        @Test
        @DisplayName("Should throw exception with buffer too small to read structure size")
        void testReadBytesWireFormatInsufficientBufferForStructureSize() {
            // Given
            byte[] buffer = new byte[1]; // Too small to read 2-byte structure size
            
            // When & Then
            assertThrows(
                ArrayIndexOutOfBoundsException.class,
                () -> response.readBytesWireFormat(buffer, 0)
            );
        }
        
        @Test
        @DisplayName("Should throw exception when buffer index out of bounds")
        void testReadBytesWireFormatBufferIndexOutOfBounds() {
            // Given
            byte[] buffer = new byte[10];
            
            // When & Then
            assertThrows(
                ArrayIndexOutOfBoundsException.class,
                () -> response.readBytesWireFormat(buffer, 9) // Not enough space to read 2 bytes
            );
        }
        
        @Test
        @DisplayName("Should handle negative values as unsigned")
        void testReadBytesWireFormatNegativeAsUnsigned() {
            // Given
            byte[] buffer = new byte[10];
            // Write -1 which will be read as 65535 unsigned
            buffer[0] = (byte) 0xFF;
            buffer[1] = (byte) 0xFF;
            
            // When & Then
            SMBProtocolDecodingException exception = assertThrows(
                SMBProtocolDecodingException.class,
                () -> response.readBytesWireFormat(buffer, 0)
            );
            assertEquals("Expected structureSize = 4", exception.getMessage());
        }
        
        @Test
        @DisplayName("Should handle signed byte value correctly")
        void testReadBytesWireFormatSignedByteValue() {
            // Given
            byte[] buffer = new byte[10];
            // Write 4 in little-endian format
            buffer[0] = 0x04;
            buffer[1] = 0x00;
            
            // When & Then
            assertDoesNotThrow(() -> {
                int bytesRead = response.readBytesWireFormat(buffer, 0);
                assertEquals(4, bytesRead);
            });
        }
    }
    
    @Nested
    @DisplayName("Integration tests")
    class IntegrationTests {
        
        @Test
        @DisplayName("Should handle complete read-write cycle")
        void testCompleteReadWriteCycle() throws SMBProtocolDecodingException {
            // Given
            byte[] writeBuffer = new byte[100];
            byte[] readBuffer = new byte[100];
            
            // Prepare valid read buffer with structure size = 4
            SMBUtil.writeInt2(4, readBuffer, 10);
            SMBUtil.writeInt2(0, readBuffer, 12); // Reserved bytes
            
            // When
            int written = response.writeBytesWireFormat(writeBuffer, 5);
            int read = response.readBytesWireFormat(readBuffer, 10);
            
            // Then
            assertEquals(0, written);
            assertEquals(4, read);
        }
        
        @Test
        @DisplayName("Should inherit ServerMessageBlock2Response properties")
        void testInheritedProperties() {
            // Verify that the response inherits from ServerMessageBlock2Response
            assertTrue(response instanceof jcifs.internal.smb2.ServerMessageBlock2Response);
            
            // Test some inherited methods
            assertFalse(response.isReceived());
            assertFalse(response.isError());
            assertNull(response.getExpiration());
        }
        
        @Test
        @DisplayName("Should handle multiple configurations")
        void testMultipleConfigurations() throws SMBProtocolDecodingException {
            // Given - create multiple configurations
            Configuration config1 = mock(Configuration.class);
            Configuration config2 = mock(Configuration.class);
            
            Smb2LockResponse response1 = new Smb2LockResponse(config1);
            Smb2LockResponse response2 = new Smb2LockResponse(config2);
            
            byte[] buffer = new byte[10];
            SMBUtil.writeInt2(4, buffer, 0);
            
            // When
            int read1 = response1.readBytesWireFormat(buffer, 0);
            int read2 = response2.readBytesWireFormat(buffer, 0);
            
            // Then
            assertEquals(4, read1);
            assertEquals(4, read2);
        }
    }
    
    @Nested
    @DisplayName("Edge case tests")
    class EdgeCaseTests {
        
        @Test
        @DisplayName("Should handle maximum buffer index")
        void testMaxBufferIndex() throws SMBProtocolDecodingException {
            // Given
            int bufferSize = 10000;
            byte[] buffer = new byte[bufferSize];
            int bufferIndex = bufferSize - 4;
            SMBUtil.writeInt2(4, buffer, bufferIndex);
            SMBUtil.writeInt2(0, buffer, bufferIndex + 2);
            
            // When
            int bytesRead = response.readBytesWireFormat(buffer, bufferIndex);
            
            // Then
            assertEquals(4, bytesRead);
        }
        
        @Test
        @DisplayName("Should handle concurrent access safely")
        void testConcurrentAccess() throws InterruptedException {
            // Given
            int threadCount = 10;
            Thread[] threads = new Thread[threadCount];
            boolean[] success = new boolean[threadCount];
            
            for (int i = 0; i < threadCount; i++) {
                final int index = i;
                threads[i] = new Thread(() -> {
                    try {
                        byte[] buffer = new byte[10];
                        if (index % 2 == 0) {
                            // Even threads do read operations
                            SMBUtil.writeInt2(4, buffer, 0);
                            response.readBytesWireFormat(buffer, 0);
                        } else {
                            // Odd threads do write operations
                            response.writeBytesWireFormat(buffer, 0);
                        }
                        success[index] = true;
                    } catch (Exception e) {
                        success[index] = false;
                    }
                });
            }
            
            // When
            for (Thread thread : threads) {
                thread.start();
            }
            for (Thread thread : threads) {
                thread.join();
            }
            
            // Then
            for (int i = 0; i < threadCount; i++) {
                assertTrue(success[i], "Thread " + i + " failed");
            }
        }
        
        @Test
        @DisplayName("Should handle boundary values for structure size")
        void testBoundaryValuesForStructureSize() {
            // Test boundary values around 4
            int[] boundaryValues = {3, 4, 5};
            
            for (int value : boundaryValues) {
                byte[] buffer = new byte[10];
                SMBUtil.writeInt2(value, buffer, 0);
                
                if (value == 4) {
                    // Should succeed
                    assertDoesNotThrow(() -> {
                        int result = response.readBytesWireFormat(buffer, 0);
                        assertEquals(4, result);
                    });
                } else {
                    // Should throw exception
                    SMBProtocolDecodingException exception = assertThrows(
                        SMBProtocolDecodingException.class,
                        () -> response.readBytesWireFormat(buffer, 0)
                    );
                    assertEquals("Expected structureSize = 4", exception.getMessage());
                }
            }
        }
        
        @Test
        @DisplayName("Should handle repeated operations")
        void testRepeatedOperations() throws SMBProtocolDecodingException {
            // Given
            byte[] buffer = new byte[10];
            SMBUtil.writeInt2(4, buffer, 0);
            
            // When - perform multiple read operations
            for (int i = 0; i < 100; i++) {
                int bytesRead = response.readBytesWireFormat(buffer, 0);
                // Then
                assertEquals(4, bytesRead, "Failed at iteration " + i);
            }
            
            // When - perform multiple write operations
            for (int i = 0; i < 100; i++) {
                int bytesWritten = response.writeBytesWireFormat(buffer, 0);
                // Then
                assertEquals(0, bytesWritten, "Failed at iteration " + i);
            }
        }
    }
    
    @Nested
    @DisplayName("Error handling tests")
    class ErrorHandlingTests {
        
        @Test
        @DisplayName("Should provide clear error message for invalid structure size")
        void testClearErrorMessage() {
            // Given
            byte[] buffer = new byte[10];
            SMBUtil.writeInt2(10, buffer, 0);
            
            // When & Then
            SMBProtocolDecodingException exception = assertThrows(
                SMBProtocolDecodingException.class,
                () -> response.readBytesWireFormat(buffer, 0)
            );
            
            // Verify error message is clear and helpful
            assertNotNull(exception.getMessage());
            assertTrue(exception.getMessage().contains("Expected structureSize = 4"));
        }
        
        @Test
        @DisplayName("Should handle zero structure size")
        void testZeroStructureSize() {
            // Given
            byte[] buffer = new byte[10];
            SMBUtil.writeInt2(0, buffer, 0);
            
            // When & Then
            SMBProtocolDecodingException exception = assertThrows(
                SMBProtocolDecodingException.class,
                () -> response.readBytesWireFormat(buffer, 0)
            );
            assertEquals("Expected structureSize = 4", exception.getMessage());
        }
        
        @Test
        @DisplayName("Should handle malformed buffer gracefully")
        void testMalformedBuffer() {
            // Given - buffer with random data
            byte[] buffer = new byte[10];
            for (int i = 0; i < buffer.length; i++) {
                buffer[i] = (byte)(Math.random() * 256);
            }
            
            // When & Then
            // Should either read successfully if random data happens to be 4,
            // or throw SMBProtocolDecodingException
            try {
                int result = response.readBytesWireFormat(buffer, 0);
                assertEquals(4, result); // If it succeeds, it must return 4
            } catch (SMBProtocolDecodingException e) {
                assertEquals("Expected structureSize = 4", e.getMessage());
            }
        }
    }
}

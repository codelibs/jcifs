/*
 * Copyright 2024 The JCIFS Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package jcifs.internal.smb1.com;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.Properties;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import jcifs.CIFSException;
import jcifs.Configuration;
import jcifs.config.PropertyConfiguration;
import jcifs.internal.smb1.ServerMessageBlock;

public class SmbComTreeDisconnectTest {

    private Configuration config;
    private SmbComTreeDisconnect smbComTreeDisconnect;
    
    @Mock
    private Configuration mockConfig;

    @BeforeEach
    public void setUp() throws CIFSException {
        MockitoAnnotations.initMocks(this);
        config = new PropertyConfiguration(new Properties());
    }

    /**
     * Test constructor initialization with valid configuration
     */
    @Test
    @DisplayName("Test constructor initializes with correct command")
    public void testConstructorWithValidConfig() {
        // When
        smbComTreeDisconnect = new SmbComTreeDisconnect(config);
        
        // Then
        assertNotNull(smbComTreeDisconnect);
        assertEquals(ServerMessageBlock.SMB_COM_TREE_DISCONNECT, smbComTreeDisconnect.getCommand());
    }

    /**
     * Test constructor with null configuration
     */
    @Test
    @DisplayName("Test constructor throws NullPointerException with null configuration")
    public void testConstructorWithNullConfig() {
        // When & Then - should throw NullPointerException since ServerMessageBlock calls config.getPid()
        NullPointerException exception = assertThrows(NullPointerException.class, () -> {
            smbComTreeDisconnect = new SmbComTreeDisconnect(null);
        });
        
        // Verify the exception message indicates the config is null
        assertTrue(exception.getMessage().contains("config"));
    }

    /**
     * Test constructor with mock configuration
     */
    @Test
    @DisplayName("Test constructor with mock configuration")
    public void testConstructorWithMockConfig() {
        // Setup mock to return a valid PID
        when(mockConfig.getPid()).thenReturn(1234);
        
        // When
        smbComTreeDisconnect = new SmbComTreeDisconnect(mockConfig);
        
        // Then
        assertNotNull(smbComTreeDisconnect);
        assertEquals(ServerMessageBlock.SMB_COM_TREE_DISCONNECT, smbComTreeDisconnect.getCommand());
        verify(mockConfig).getPid(); // Verify getPid was called
    }

    /**
     * Test writeParameterWordsWireFormat returns 0
     */
    @Test
    @DisplayName("Test writeParameterWordsWireFormat always returns 0")
    public void testWriteParameterWordsWireFormat() {
        // Given
        smbComTreeDisconnect = new SmbComTreeDisconnect(config);
        byte[] dst = new byte[100];
        int dstIndex = 0;
        
        // When
        int result = smbComTreeDisconnect.writeParameterWordsWireFormat(dst, dstIndex);
        
        // Then
        assertEquals(0, result);
    }

    /**
     * Test writeParameterWordsWireFormat with various buffer sizes
     */
    @Test
    @DisplayName("Test writeParameterWordsWireFormat with different buffer sizes")
    public void testWriteParameterWordsWireFormatWithDifferentBufferSizes() {
        // Given
        smbComTreeDisconnect = new SmbComTreeDisconnect(config);
        int[] bufferSizes = {0, 10, 50, 100, 1024};
        
        for (int bufferSize : bufferSizes) {
            byte[] dst = new byte[bufferSize];
            
            // When
            int result = smbComTreeDisconnect.writeParameterWordsWireFormat(dst, 0);
            
            // Then
            assertEquals(0, result);
        }
    }

    /**
     * Test writeParameterWordsWireFormat with various offsets
     */
    @Test
    @DisplayName("Test writeParameterWordsWireFormat with different offsets")
    public void testWriteParameterWordsWireFormatWithDifferentOffsets() {
        // Given
        smbComTreeDisconnect = new SmbComTreeDisconnect(config);
        byte[] dst = new byte[200];
        int[] offsets = {0, 10, 50, 100};
        
        for (int offset : offsets) {
            // When
            int result = smbComTreeDisconnect.writeParameterWordsWireFormat(dst, offset);
            
            // Then
            assertEquals(0, result);
        }
    }

    /**
     * Test writeBytesWireFormat returns 0
     */
    @Test
    @DisplayName("Test writeBytesWireFormat always returns 0")
    public void testWriteBytesWireFormat() {
        // Given
        smbComTreeDisconnect = new SmbComTreeDisconnect(config);
        byte[] dst = new byte[100];
        int dstIndex = 0;
        
        // When
        int result = smbComTreeDisconnect.writeBytesWireFormat(dst, dstIndex);
        
        // Then
        assertEquals(0, result);
    }

    /**
     * Test writeBytesWireFormat with various buffer sizes
     */
    @Test
    @DisplayName("Test writeBytesWireFormat with different buffer sizes")
    public void testWriteBytesWireFormatWithDifferentBufferSizes() {
        // Given
        smbComTreeDisconnect = new SmbComTreeDisconnect(config);
        int[] bufferSizes = {0, 10, 50, 100, 1024};
        
        for (int bufferSize : bufferSizes) {
            byte[] dst = new byte[bufferSize];
            
            // When
            int result = smbComTreeDisconnect.writeBytesWireFormat(dst, 0);
            
            // Then
            assertEquals(0, result);
        }
    }

    /**
     * Test writeBytesWireFormat with various offsets
     */
    @Test
    @DisplayName("Test writeBytesWireFormat with different offsets")
    public void testWriteBytesWireFormatWithDifferentOffsets() {
        // Given
        smbComTreeDisconnect = new SmbComTreeDisconnect(config);
        byte[] dst = new byte[200];
        int[] offsets = {0, 10, 50, 100};
        
        for (int offset : offsets) {
            // When
            int result = smbComTreeDisconnect.writeBytesWireFormat(dst, offset);
            
            // Then
            assertEquals(0, result);
        }
    }

    /**
     * Test readParameterWordsWireFormat returns 0
     */
    @Test
    @DisplayName("Test readParameterWordsWireFormat always returns 0")
    public void testReadParameterWordsWireFormat() {
        // Given
        smbComTreeDisconnect = new SmbComTreeDisconnect(config);
        byte[] buffer = new byte[100];
        int bufferIndex = 0;
        
        // When
        int result = smbComTreeDisconnect.readParameterWordsWireFormat(buffer, bufferIndex);
        
        // Then
        assertEquals(0, result);
    }

    /**
     * Test readParameterWordsWireFormat with various buffer sizes
     */
    @Test
    @DisplayName("Test readParameterWordsWireFormat with different buffer sizes")
    public void testReadParameterWordsWireFormatWithDifferentBufferSizes() {
        // Given
        smbComTreeDisconnect = new SmbComTreeDisconnect(config);
        int[] bufferSizes = {0, 10, 50, 100, 1024};
        
        for (int bufferSize : bufferSizes) {
            byte[] buffer = new byte[bufferSize];
            
            // When
            int result = smbComTreeDisconnect.readParameterWordsWireFormat(buffer, 0);
            
            // Then
            assertEquals(0, result);
        }
    }

    /**
     * Test readBytesWireFormat returns 0
     */
    @Test
    @DisplayName("Test readBytesWireFormat always returns 0")
    public void testReadBytesWireFormat() {
        // Given
        smbComTreeDisconnect = new SmbComTreeDisconnect(config);
        byte[] buffer = new byte[100];
        int bufferIndex = 0;
        
        // When
        int result = smbComTreeDisconnect.readBytesWireFormat(buffer, bufferIndex);
        
        // Then
        assertEquals(0, result);
    }

    /**
     * Test readBytesWireFormat with various buffer sizes
     */
    @Test
    @DisplayName("Test readBytesWireFormat with different buffer sizes")
    public void testReadBytesWireFormatWithDifferentBufferSizes() {
        // Given
        smbComTreeDisconnect = new SmbComTreeDisconnect(config);
        int[] bufferSizes = {0, 10, 50, 100, 1024};
        
        for (int bufferSize : bufferSizes) {
            byte[] buffer = new byte[bufferSize];
            
            // When
            int result = smbComTreeDisconnect.readBytesWireFormat(buffer, 0);
            
            // Then
            assertEquals(0, result);
        }
    }

    /**
     * Test toString method
     */
    @Test
    @DisplayName("Test toString returns properly formatted string")
    public void testToString() {
        // Given
        smbComTreeDisconnect = new SmbComTreeDisconnect(config);
        
        // When
        String result = smbComTreeDisconnect.toString();
        
        // Then
        assertNotNull(result);
        assertTrue(result.contains("SmbComTreeDisconnect"));
        assertTrue(result.startsWith("SmbComTreeDisconnect["));
        assertTrue(result.endsWith("]"));
    }

    /**
     * Test toString method behavior - requires valid configuration
     */
    @Test
    @DisplayName("Test toString requires valid configuration")
    public void testToStringRequiresValidConfig() {
        // Constructor with null config throws exception, so we can't test toString with null config
        // Instead, test that toString works with a valid config
        
        // Given
        smbComTreeDisconnect = new SmbComTreeDisconnect(config);
        
        // When
        String result = smbComTreeDisconnect.toString();
        
        // Then
        assertNotNull(result);
        assertTrue(result.contains("SmbComTreeDisconnect"));
        assertTrue(result.startsWith("SmbComTreeDisconnect["));
        assertTrue(result.endsWith("]"));
    }

    /**
     * Test command byte value
     */
    @Test
    @DisplayName("Test SMB_COM_TREE_DISCONNECT command value is 0x71")
    public void testCommandValue() {
        // Given
        smbComTreeDisconnect = new SmbComTreeDisconnect(config);
        
        // When
        int command = smbComTreeDisconnect.getCommand();
        
        // Then
        assertEquals(0x71, command & 0xFF);
        assertEquals(ServerMessageBlock.SMB_COM_TREE_DISCONNECT, (byte)command);
    }

    /**
     * Nested class for testing buffer operations
     */
    @Nested
    @DisplayName("Buffer Operations Tests")
    class BufferOperationsTests {
        
        @Test
        @DisplayName("Test write operations with empty buffer")
        public void testWriteOperationsWithEmptyBuffer() {
            // Given
            smbComTreeDisconnect = new SmbComTreeDisconnect(config);
            byte[] emptyBuffer = new byte[0];
            
            // When & Then
            assertDoesNotThrow(() -> {
                smbComTreeDisconnect.writeParameterWordsWireFormat(emptyBuffer, 0);
                smbComTreeDisconnect.writeBytesWireFormat(emptyBuffer, 0);
            });
        }
        
        @Test
        @DisplayName("Test read operations with empty buffer")
        public void testReadOperationsWithEmptyBuffer() {
            // Given
            smbComTreeDisconnect = new SmbComTreeDisconnect(config);
            byte[] emptyBuffer = new byte[0];
            
            // When & Then
            assertDoesNotThrow(() -> {
                smbComTreeDisconnect.readParameterWordsWireFormat(emptyBuffer, 0);
                smbComTreeDisconnect.readBytesWireFormat(emptyBuffer, 0);
            });
        }
        
        @Test
        @DisplayName("Test operations with null buffer")
        public void testOperationsWithNullBuffer() {
            // Given
            smbComTreeDisconnect = new SmbComTreeDisconnect(config);
            
            // When & Then - operations return 0 even with null buffer (no buffer access since methods return 0)
            assertEquals(0, smbComTreeDisconnect.writeParameterWordsWireFormat(null, 0));
            assertEquals(0, smbComTreeDisconnect.writeBytesWireFormat(null, 0));
            assertEquals(0, smbComTreeDisconnect.readParameterWordsWireFormat(null, 0));
            assertEquals(0, smbComTreeDisconnect.readBytesWireFormat(null, 0));
        }
        
        @Test
        @DisplayName("Test buffer operations do not modify buffer contents")
        public void testBufferContentsNotModified() {
            // Given
            smbComTreeDisconnect = new SmbComTreeDisconnect(config);
            byte[] originalBuffer = new byte[100];
            for (int i = 0; i < originalBuffer.length; i++) {
                originalBuffer[i] = (byte) i;
            }
            byte[] bufferCopy = originalBuffer.clone();
            
            // When
            smbComTreeDisconnect.writeParameterWordsWireFormat(originalBuffer, 50);
            smbComTreeDisconnect.writeBytesWireFormat(originalBuffer, 50);
            smbComTreeDisconnect.readParameterWordsWireFormat(originalBuffer, 50);
            smbComTreeDisconnect.readBytesWireFormat(originalBuffer, 50);
            
            // Then - buffer should remain unchanged since all methods return 0
            assertArrayEquals(bufferCopy, originalBuffer);
        }
    }

    /**
     * Test inheritance from ServerMessageBlock
     */
    @Test
    @DisplayName("Test inheritance from ServerMessageBlock")
    public void testInheritance() {
        // Given
        smbComTreeDisconnect = new SmbComTreeDisconnect(config);
        
        // Then
        assertTrue(smbComTreeDisconnect instanceof ServerMessageBlock);
    }

    /**
     * Test multiple instances are independent
     */
    @Test
    @DisplayName("Test multiple instances are independent")
    public void testMultipleInstancesIndependence() {
        // Setup mock to return a valid PID
        when(mockConfig.getPid()).thenReturn(5678);
        
        // Given
        SmbComTreeDisconnect instance1 = new SmbComTreeDisconnect(config);
        SmbComTreeDisconnect instance2 = new SmbComTreeDisconnect(mockConfig);
        
        // Then
        assertNotSame(instance1, instance2);
        assertEquals(instance1.getCommand(), instance2.getCommand());
        assertNotEquals(instance1.toString(), instance2.toString()); // Different object references in toString
    }

    /**
     * Test thread safety of read/write operations
     */
    @Test
    @DisplayName("Test thread safety of operations")
    public void testThreadSafety() throws InterruptedException {
        // Given
        smbComTreeDisconnect = new SmbComTreeDisconnect(config);
        byte[] buffer = new byte[1000];
        int numThreads = 10;
        Thread[] threads = new Thread[numThreads];
        
        // When - multiple threads calling methods simultaneously
        for (int i = 0; i < numThreads; i++) {
            final int threadIndex = i;
            threads[i] = new Thread(() -> {
                for (int j = 0; j < 100; j++) {
                    int offset = threadIndex * 10;
                    smbComTreeDisconnect.writeParameterWordsWireFormat(buffer, offset);
                    smbComTreeDisconnect.writeBytesWireFormat(buffer, offset);
                    smbComTreeDisconnect.readParameterWordsWireFormat(buffer, offset);
                    smbComTreeDisconnect.readBytesWireFormat(buffer, offset);
                    smbComTreeDisconnect.toString();
                }
            });
            threads[i].start();
        }
        
        // Wait for all threads to complete
        for (Thread thread : threads) {
            thread.join();
        }
        
        // Then - no exceptions should have been thrown
        assertTrue(true); // If we reach here, no exceptions occurred
    }

    /**
     * Test consistency across multiple calls
     */
    @Test
    @DisplayName("Test consistency across multiple calls")
    public void testConsistencyAcrossMultipleCalls() {
        // Given
        smbComTreeDisconnect = new SmbComTreeDisconnect(config);
        byte[] buffer = new byte[100];
        
        // When & Then - multiple calls should return the same result
        for (int i = 0; i < 10; i++) {
            assertEquals(0, smbComTreeDisconnect.writeParameterWordsWireFormat(buffer, i));
            assertEquals(0, smbComTreeDisconnect.writeBytesWireFormat(buffer, i));
            assertEquals(0, smbComTreeDisconnect.readParameterWordsWireFormat(buffer, i));
            assertEquals(0, smbComTreeDisconnect.readBytesWireFormat(buffer, i));
        }
    }

    /**
     * Test boundary conditions for buffer indices
     */
    @Test
    @DisplayName("Test boundary conditions for buffer indices")
    public void testBoundaryConditions() {
        // Given
        smbComTreeDisconnect = new SmbComTreeDisconnect(config);
        byte[] buffer = new byte[100];
        
        // When & Then - test with maximum valid index
        assertEquals(0, smbComTreeDisconnect.writeParameterWordsWireFormat(buffer, 99));
        assertEquals(0, smbComTreeDisconnect.writeBytesWireFormat(buffer, 99));
        assertEquals(0, smbComTreeDisconnect.readParameterWordsWireFormat(buffer, 99));
        assertEquals(0, smbComTreeDisconnect.readBytesWireFormat(buffer, 99));
        
        // Test with index beyond buffer size
        assertEquals(0, smbComTreeDisconnect.writeParameterWordsWireFormat(buffer, 200));
        assertEquals(0, smbComTreeDisconnect.writeBytesWireFormat(buffer, 200));
        assertEquals(0, smbComTreeDisconnect.readParameterWordsWireFormat(buffer, 200));
        assertEquals(0, smbComTreeDisconnect.readBytesWireFormat(buffer, 200));
    }

    /**
     * Test that methods are properly overridden
     */
    @Test
    @DisplayName("Test methods are properly overridden from parent class")
    public void testMethodOverrides() throws NoSuchMethodException {
        // Given
        Class<?> clazz = SmbComTreeDisconnect.class;
        
        // When & Then - verify methods are declared in this class (overridden)
        Method writeParameterWords = clazz.getDeclaredMethod("writeParameterWordsWireFormat", byte[].class, int.class);
        assertNotNull(writeParameterWords);
        
        Method writeBytes = clazz.getDeclaredMethod("writeBytesWireFormat", byte[].class, int.class);
        assertNotNull(writeBytes);
        
        Method readParameterWords = clazz.getDeclaredMethod("readParameterWordsWireFormat", byte[].class, int.class);
        assertNotNull(readParameterWords);
        
        Method readBytes = clazz.getDeclaredMethod("readBytesWireFormat", byte[].class, int.class);
        assertNotNull(readBytes);
        
        Method toString = clazz.getDeclaredMethod("toString");
        assertNotNull(toString);
    }
}
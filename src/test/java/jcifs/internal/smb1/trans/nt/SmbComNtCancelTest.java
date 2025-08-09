/*
 * © 2017 AgNO3 Gmbh & Co. KG
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
package jcifs.internal.smb1.trans.nt;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInfo;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import jcifs.Configuration;
import jcifs.internal.smb1.ServerMessageBlock;

/**
 * Test class for SmbComNtCancel
 * 
 * @author test
 */
class SmbComNtCancelTest {

    private Configuration mockConfig;
    private static final byte SMB_COM_NT_CANCEL = (byte) 0xA4;
    
    @BeforeEach
    void setUp() {
        mockConfig = mock(Configuration.class);
    }

    @Test
    @DisplayName("Test constructor initializes with correct command and MID")
    void testConstructor() throws Exception {
        // Given
        int testMid = 42;
        
        // When - using reflection to access protected constructor
        Constructor<SmbComNtCancel> constructor = SmbComNtCancel.class.getDeclaredConstructor(Configuration.class, int.class);
        constructor.setAccessible(true);
        SmbComNtCancel cancel = constructor.newInstance(mockConfig, testMid);
        
        // Then
        assertNotNull(cancel);
        assertEquals(testMid, cancel.getMid());
        
        // Verify command is set correctly using reflection
        Field commandField = ServerMessageBlock.class.getDeclaredField("command");
        commandField.setAccessible(true);
        assertEquals(SMB_COM_NT_CANCEL, commandField.getByte(cancel));
    }

    @Test
    @DisplayName("Test isCancel returns true")
    void testIsCancel() throws Exception {
        // Given
        Constructor<SmbComNtCancel> constructor = SmbComNtCancel.class.getDeclaredConstructor(Configuration.class, int.class);
        constructor.setAccessible(true);
        SmbComNtCancel cancel = constructor.newInstance(mockConfig, 1);
        
        // When
        boolean result = cancel.isCancel();
        
        // Then
        assertTrue(result);
    }

    @Test
    @DisplayName("Test writeParameterWordsWireFormat returns 0")
    void testWriteParameterWordsWireFormat() throws Exception {
        // Given
        Constructor<SmbComNtCancel> constructor = SmbComNtCancel.class.getDeclaredConstructor(Configuration.class, int.class);
        constructor.setAccessible(true);
        SmbComNtCancel cancel = constructor.newInstance(mockConfig, 1);
        byte[] dst = new byte[100];
        int dstIndex = 10;
        
        // When
        Method method = SmbComNtCancel.class.getDeclaredMethod("writeParameterWordsWireFormat", byte[].class, int.class);
        method.setAccessible(true);
        int result = (int) method.invoke(cancel, dst, dstIndex);
        
        // Then
        assertEquals(0, result);
    }

    @Test
    @DisplayName("Test writeBytesWireFormat returns 0")
    void testWriteBytesWireFormat() throws Exception {
        // Given
        Constructor<SmbComNtCancel> constructor = SmbComNtCancel.class.getDeclaredConstructor(Configuration.class, int.class);
        constructor.setAccessible(true);
        SmbComNtCancel cancel = constructor.newInstance(mockConfig, 1);
        byte[] dst = new byte[100];
        int dstIndex = 10;
        
        // When
        Method method = SmbComNtCancel.class.getDeclaredMethod("writeBytesWireFormat", byte[].class, int.class);
        method.setAccessible(true);
        int result = (int) method.invoke(cancel, dst, dstIndex);
        
        // Then
        assertEquals(0, result);
    }

    @Test
    @DisplayName("Test readParameterWordsWireFormat returns 0")
    void testReadParameterWordsWireFormat() throws Exception {
        // Given
        Constructor<SmbComNtCancel> constructor = SmbComNtCancel.class.getDeclaredConstructor(Configuration.class, int.class);
        constructor.setAccessible(true);
        SmbComNtCancel cancel = constructor.newInstance(mockConfig, 1);
        byte[] buffer = new byte[100];
        int bufferIndex = 10;
        
        // When
        Method method = SmbComNtCancel.class.getDeclaredMethod("readParameterWordsWireFormat", byte[].class, int.class);
        method.setAccessible(true);
        int result = (int) method.invoke(cancel, buffer, bufferIndex);
        
        // Then
        assertEquals(0, result);
    }

    @Test
    @DisplayName("Test readBytesWireFormat returns 0")
    void testReadBytesWireFormat() throws Exception {
        // Given
        Constructor<SmbComNtCancel> constructor = SmbComNtCancel.class.getDeclaredConstructor(Configuration.class, int.class);
        constructor.setAccessible(true);
        SmbComNtCancel cancel = constructor.newInstance(mockConfig, 1);
        byte[] buffer = new byte[100];
        int bufferIndex = 10;
        
        // When
        Method method = SmbComNtCancel.class.getDeclaredMethod("readBytesWireFormat", byte[].class, int.class);
        method.setAccessible(true);
        int result = (int) method.invoke(cancel, buffer, bufferIndex);
        
        // Then
        assertEquals(0, result);
    }

    @ParameterizedTest
    @ValueSource(ints = {0, 1, 100, 255, 65535})
    @DisplayName("Test constructor with different MID values")
    void testConstructorWithDifferentMids(int mid) throws Exception {
        // When
        Constructor<SmbComNtCancel> constructor = SmbComNtCancel.class.getDeclaredConstructor(Configuration.class, int.class);
        constructor.setAccessible(true);
        SmbComNtCancel cancel = constructor.newInstance(mockConfig, mid);
        
        // Then
        assertNotNull(cancel);
        assertEquals(mid, cancel.getMid());
    }

    @Test
    @DisplayName("Test write operations do not modify destination array")
    void testWriteOperationsDoNotModifyArray() throws Exception {
        // Given
        Constructor<SmbComNtCancel> constructor = SmbComNtCancel.class.getDeclaredConstructor(Configuration.class, int.class);
        constructor.setAccessible(true);
        SmbComNtCancel cancel = constructor.newInstance(mockConfig, 1);
        
        byte[] originalDst = new byte[100];
        byte[] dst = originalDst.clone();
        
        // When
        Method writeParams = SmbComNtCancel.class.getDeclaredMethod("writeParameterWordsWireFormat", byte[].class, int.class);
        writeParams.setAccessible(true);
        writeParams.invoke(cancel, dst, 0);
        
        Method writeBytes = SmbComNtCancel.class.getDeclaredMethod("writeBytesWireFormat", byte[].class, int.class);
        writeBytes.setAccessible(true);
        writeBytes.invoke(cancel, dst, 0);
        
        // Then - array should remain unchanged since methods return 0 and don't write anything
        assertArrayEquals(originalDst, dst);
    }

    @Test
    @DisplayName("Test read operations do not modify buffer array")
    void testReadOperationsDoNotModifyArray() throws Exception {
        // Given
        Constructor<SmbComNtCancel> constructor = SmbComNtCancel.class.getDeclaredConstructor(Configuration.class, int.class);
        constructor.setAccessible(true);
        SmbComNtCancel cancel = constructor.newInstance(mockConfig, 1);
        
        byte[] originalBuffer = new byte[100];
        for (int i = 0; i < originalBuffer.length; i++) {
            originalBuffer[i] = (byte) i;
        }
        byte[] buffer = originalBuffer.clone();
        
        // When
        Method readParams = SmbComNtCancel.class.getDeclaredMethod("readParameterWordsWireFormat", byte[].class, int.class);
        readParams.setAccessible(true);
        readParams.invoke(cancel, buffer, 0);
        
        Method readBytes = SmbComNtCancel.class.getDeclaredMethod("readBytesWireFormat", byte[].class, int.class);
        readBytes.setAccessible(true);
        readBytes.invoke(cancel, buffer, 0);
        
        // Then - buffer should remain unchanged since methods just return 0
        assertArrayEquals(originalBuffer, buffer);
    }

    @Test
    @DisplayName("Test with null configuration")
    void testWithNullConfiguration() throws Exception {
        // Given
        Configuration nullConfig = null;
        int testMid = 10;
        
        // When
        Constructor<SmbComNtCancel> constructor = SmbComNtCancel.class.getDeclaredConstructor(Configuration.class, int.class);
        constructor.setAccessible(true);
        SmbComNtCancel cancel = constructor.newInstance(nullConfig, testMid);
        
        // Then - should still create instance (parent class handles null config)
        assertNotNull(cancel);
        assertEquals(testMid, cancel.getMid());
        assertTrue(cancel.isCancel());
    }

    @Test
    @DisplayName("Test all wire format methods with various buffer positions")
    void testWireFormatMethodsWithDifferentPositions() throws Exception {
        // Given
        Constructor<SmbComNtCancel> constructor = SmbComNtCancel.class.getDeclaredConstructor(Configuration.class, int.class);
        constructor.setAccessible(true);
        SmbComNtCancel cancel = constructor.newInstance(mockConfig, 1);
        
        int[] positions = {0, 50, 99};
        
        for (int pos : positions) {
            byte[] buffer = new byte[100];
            
            // Test write parameter words
            Method writeParams = SmbComNtCancel.class.getDeclaredMethod("writeParameterWordsWireFormat", byte[].class, int.class);
            writeParams.setAccessible(true);
            assertEquals(0, writeParams.invoke(cancel, buffer, pos));
            
            // Test write bytes
            Method writeBytes = SmbComNtCancel.class.getDeclaredMethod("writeBytesWireFormat", byte[].class, int.class);
            writeBytes.setAccessible(true);
            assertEquals(0, writeBytes.invoke(cancel, buffer, pos));
            
            // Test read parameter words
            Method readParams = SmbComNtCancel.class.getDeclaredMethod("readParameterWordsWireFormat", byte[].class, int.class);
            readParams.setAccessible(true);
            assertEquals(0, readParams.invoke(cancel, buffer, pos));
            
            // Test read bytes
            Method readBytes = SmbComNtCancel.class.getDeclaredMethod("readBytesWireFormat", byte[].class, int.class);
            readBytes.setAccessible(true);
            assertEquals(0, readBytes.invoke(cancel, buffer, pos));
        }
    }
}
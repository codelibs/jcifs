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
import java.util.Properties;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import jcifs.CIFSException;
import jcifs.Configuration;
import jcifs.SmbConstants;
import jcifs.config.PropertyConfiguration;
import jcifs.internal.smb1.ServerMessageBlock;

public class SmbComRenameTest {

    private Configuration config;
    private SmbComRename smbComRename;
    
    @Mock
    private Configuration mockConfig;

    @BeforeEach
    public void setUp() throws CIFSException {
        MockitoAnnotations.openMocks(this);
        config = new PropertyConfiguration(new Properties());
    }

    /**
     * Test constructor initialization with valid parameters
     */
    @Test
    @DisplayName("Test constructor initializes fields correctly")
    public void testConstructor() throws Exception {
        // Given
        String oldFileName = "oldFile.txt";
        String newFileName = "newFile.txt";
        
        // When
        smbComRename = new SmbComRename(config, oldFileName, newFileName);
        
        // Then
        assertEquals(ServerMessageBlock.SMB_COM_RENAME, smbComRename.getCommand());
        
        // Use reflection to verify private fields
        Field oldFileNameField = SmbComRename.class.getDeclaredField("oldFileName");
        oldFileNameField.setAccessible(true);
        assertEquals(oldFileName, oldFileNameField.get(smbComRename));
        
        Field newFileNameField = SmbComRename.class.getDeclaredField("newFileName");
        newFileNameField.setAccessible(true);
        assertEquals(newFileName, newFileNameField.get(smbComRename));
        
        Field searchAttributesField = SmbComRename.class.getDeclaredField("searchAttributes");
        searchAttributesField.setAccessible(true);
        int expectedAttributes = SmbConstants.ATTR_HIDDEN | SmbConstants.ATTR_SYSTEM | SmbConstants.ATTR_DIRECTORY;
        assertEquals(expectedAttributes, searchAttributesField.get(smbComRename));
    }

    /**
     * Test writeParameterWordsWireFormat method
     */
    @Test
    @DisplayName("Test writeParameterWordsWireFormat writes search attributes correctly")
    public void testWriteParameterWordsWireFormat() {
        // Given
        byte[] dst = new byte[10];
        smbComRename = new SmbComRename(config, "old.txt", "new.txt");
        int dstIndex = 2;
        
        // When
        int result = smbComRename.writeParameterWordsWireFormat(dst, dstIndex);
        
        // Then
        assertEquals(2, result);
        
        // Verify that search attributes are written correctly
        int expectedAttributes = SmbConstants.ATTR_HIDDEN | SmbConstants.ATTR_SYSTEM | SmbConstants.ATTR_DIRECTORY;
        assertEquals((byte)(expectedAttributes & 0xFF), dst[dstIndex]);
        assertEquals((byte)((expectedAttributes >> 8) & 0xFF), dst[dstIndex + 1]);
    }

    /**
     * Test writeBytesWireFormat with ASCII encoding
     */
    @Test
    @DisplayName("Test writeBytesWireFormat writes file names correctly in ASCII")
    public void testWriteBytesWireFormatAscii() throws Exception {
        // Given
        String oldFileName = "oldFile.txt";
        String newFileName = "newFile.txt";
        byte[] dst = new byte[100];
        smbComRename = new SmbComRename(config, oldFileName, newFileName);
        
        // Set unicode to false
        Field useUnicodeField = ServerMessageBlock.class.getDeclaredField("useUnicode");
        useUnicodeField.setAccessible(true);
        useUnicodeField.setBoolean(smbComRename, false);
        
        int dstIndex = 0;
        
        // When
        int result = smbComRename.writeBytesWireFormat(dst, dstIndex);
        
        // Then
        assertTrue(result > 0);
        assertEquals((byte)0x04, dst[0]); // First buffer format byte
        
        // Find the second buffer format byte
        int secondBufferFormatIndex = oldFileName.length() + 2; // 1 for first 0x04, 1 for null terminator
        assertEquals((byte)0x04, dst[secondBufferFormatIndex]);
    }

    /**
     * Test writeBytesWireFormat with Unicode encoding
     */
    @Test
    @DisplayName("Test writeBytesWireFormat writes file names correctly in Unicode")
    public void testWriteBytesWireFormatUnicode() throws Exception {
        // Given
        String oldFileName = "oldFile.txt";
        String newFileName = "newFile.txt";
        byte[] dst = new byte[200];
        smbComRename = new SmbComRename(config, oldFileName, newFileName);
        
        // Set unicode to true
        Field useUnicodeField = ServerMessageBlock.class.getDeclaredField("useUnicode");
        useUnicodeField.setAccessible(true);
        useUnicodeField.setBoolean(smbComRename, true);
        
        int dstIndex = 0;
        
        // When
        int result = smbComRename.writeBytesWireFormat(dst, dstIndex);
        
        // Then
        assertTrue(result > 0);
        assertEquals((byte)0x04, dst[0]); // First buffer format byte
        
        // In Unicode mode, there should be an extra null byte after the second 0x04
        int oldFileNameLengthInBytes = (oldFileName.length() + 1) * 2; // Unicode chars + null terminator
        int secondBufferFormatIndex = 1 + oldFileNameLengthInBytes;
        assertEquals((byte)0x04, dst[secondBufferFormatIndex]);
        assertEquals((byte)0x00, dst[secondBufferFormatIndex + 1]); // Extra null byte for Unicode alignment
    }

    /**
     * Test writeBytesWireFormat with empty file names
     */
    @Test
    @DisplayName("Test writeBytesWireFormat with empty file names")
    public void testWriteBytesWireFormatEmptyFileNames() {
        // Given
        byte[] dst = new byte[100];
        smbComRename = new SmbComRename(config, "", "");
        int dstIndex = 0;
        
        // When
        int result = smbComRename.writeBytesWireFormat(dst, dstIndex);
        
        // Then
        assertTrue(result > 0);
        assertEquals((byte)0x04, dst[0]); // First buffer format byte
        assertEquals((byte)0x00, dst[1]); // Null terminator for empty old file name
        assertEquals((byte)0x04, dst[2]); // Second buffer format byte
    }

    /**
     * Test writeBytesWireFormat with special characters in file names
     */
    @Test
    @DisplayName("Test writeBytesWireFormat with special characters in file names")
    public void testWriteBytesWireFormatSpecialCharacters() {
        // Given
        String oldFileName = "file with spaces.txt";
        String newFileName = "file@#$%.doc";
        byte[] dst = new byte[200];
        smbComRename = new SmbComRename(config, oldFileName, newFileName);
        int dstIndex = 0;
        
        // When
        int result = smbComRename.writeBytesWireFormat(dst, dstIndex);
        
        // Then
        assertTrue(result > 0);
        assertEquals((byte)0x04, dst[0]); // First buffer format byte
    }

    /**
     * Test readParameterWordsWireFormat method
     */
    @Test
    @DisplayName("Test readParameterWordsWireFormat always returns 0")
    public void testReadParameterWordsWireFormat() {
        // Given
        byte[] buffer = new byte[10];
        smbComRename = new SmbComRename(config, "old.txt", "new.txt");
        
        // When
        int result = smbComRename.readParameterWordsWireFormat(buffer, 0);
        
        // Then
        assertEquals(0, result);
    }

    /**
     * Test readBytesWireFormat method
     */
    @Test
    @DisplayName("Test readBytesWireFormat always returns 0")
    public void testReadBytesWireFormat() {
        // Given
        byte[] buffer = new byte[10];
        smbComRename = new SmbComRename(config, "old.txt", "new.txt");
        
        // When
        int result = smbComRename.readBytesWireFormat(buffer, 0);
        
        // Then
        assertEquals(0, result);
    }

    /**
     * Test toString method
     */
    @Test
    @DisplayName("Test toString returns properly formatted string")
    public void testToString() {
        // Given
        String oldFileName = "oldFile.txt";
        String newFileName = "newFile.txt";
        smbComRename = new SmbComRename(config, oldFileName, newFileName);
        
        // When
        String result = smbComRename.toString();
        
        // Then
        assertNotNull(result);
        assertTrue(result.contains("SmbComRename"));
        assertTrue(result.contains("searchAttributes=0x"));
        assertTrue(result.contains("oldFileName=" + oldFileName));
        assertTrue(result.contains("newFileName=" + newFileName));
    }

    /**
     * Test with null configuration
     */
    @Test
    @DisplayName("Test constructor with null configuration")
    public void testConstructorWithNullConfig() {
        // Given
        String oldFileName = "old.txt";
        String newFileName = "new.txt";
        
        // When & Then - should not throw exception
        assertDoesNotThrow(() -> {
            new SmbComRename(null, oldFileName, newFileName);
        });
    }

    /**
     * Test with null file names
     */
    @Test
    @DisplayName("Test constructor with null file names")
    public void testConstructorWithNullFileNames() {
        // When & Then - should not throw exception during construction
        assertDoesNotThrow(() -> {
            new SmbComRename(config, null, null);
        });
    }

    /**
     * Test with very long file names
     */
    @Test
    @DisplayName("Test writeBytesWireFormat with very long file names")
    public void testWriteBytesWireFormatLongFileNames() {
        // Given
        String longOldFileName = "a".repeat(255); // Max filename length
        String longNewFileName = "b".repeat(255);
        byte[] dst = new byte[1024];
        smbComRename = new SmbComRename(config, longOldFileName, longNewFileName);
        int dstIndex = 0;
        
        // When
        int result = smbComRename.writeBytesWireFormat(dst, dstIndex);
        
        // Then
        assertTrue(result > 0);
        assertTrue(result < dst.length);
        assertEquals((byte)0x04, dst[0]); // First buffer format byte
    }

    /**
     * Test writeBytesWireFormat with different buffer offsets
     */
    @Test
    @DisplayName("Test writeBytesWireFormat with different buffer offsets")
    public void testWriteBytesWireFormatWithOffset() {
        // Given
        String oldFileName = "old.txt";
        String newFileName = "new.txt";
        byte[] dst = new byte[200];
        smbComRename = new SmbComRename(config, oldFileName, newFileName);
        int dstIndex = 50; // Start at offset 50
        
        // When
        int result = smbComRename.writeBytesWireFormat(dst, dstIndex);
        
        // Then
        assertTrue(result > 0);
        assertEquals((byte)0x04, dst[dstIndex]); // First buffer format byte at offset
    }

    /**
     * Test that search attributes are set correctly
     */
    @Test
    @DisplayName("Test search attributes include HIDDEN, SYSTEM, and DIRECTORY")
    public void testSearchAttributesValue() throws Exception {
        // Given
        smbComRename = new SmbComRename(config, "old.txt", "new.txt");
        
        // When
        Field searchAttributesField = SmbComRename.class.getDeclaredField("searchAttributes");
        searchAttributesField.setAccessible(true);
        int searchAttributes = (int) searchAttributesField.get(smbComRename);
        
        // Then
        assertTrue((searchAttributes & SmbConstants.ATTR_HIDDEN) != 0);
        assertTrue((searchAttributes & SmbConstants.ATTR_SYSTEM) != 0);
        assertTrue((searchAttributes & SmbConstants.ATTR_DIRECTORY) != 0);
    }

    /**
     * Test writeString method indirectly through writeBytesWireFormat
     */
    @Test
    @DisplayName("Test writeString handles path separators correctly")
    public void testWriteStringWithPathSeparators() {
        // Given
        String oldFileName = "folder\\oldFile.txt";
        String newFileName = "folder\\newFile.txt";
        byte[] dst = new byte[200];
        smbComRename = new SmbComRename(config, oldFileName, newFileName);
        int dstIndex = 0;
        
        // When
        int result = smbComRename.writeBytesWireFormat(dst, dstIndex);
        
        // Then
        assertTrue(result > 0);
        assertEquals((byte)0x04, dst[0]);
    }
}
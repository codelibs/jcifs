/*
 * Copyright 2024 Shinsuke Ogawa
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
package jcifs.internal.smb1.trans2;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import jcifs.CIFSException;
import jcifs.Configuration;
import jcifs.config.PropertyConfiguration;
import jcifs.internal.SMBProtocolDecodingException;
import jcifs.internal.fscc.FileFsFullSizeInformation;
import jcifs.internal.fscc.FileFsSizeInformation;
import jcifs.internal.fscc.FileSystemInformation;
import jcifs.internal.fscc.SmbInfoAllocation;
import jcifs.internal.smb1.ServerMessageBlock;
import jcifs.internal.smb1.trans.SmbComTransaction;
import jcifs.internal.util.SMBUtil;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.Properties;

class Trans2QueryFSInformationResponseTest {

    private Trans2QueryFSInformationResponse response;
    private Configuration config;
    
    @Mock
    private Configuration mockConfig;
    
    @BeforeEach
    void setUp() throws Exception {
        MockitoAnnotations.openMocks(this);
        Properties props = new Properties();
        config = new PropertyConfiguration(props);
    }

    @Test
    void testConstructor() {
        // Test constructor with SMB_INFO_ALLOCATION
        response = new Trans2QueryFSInformationResponse(config, FileSystemInformation.SMB_INFO_ALLOCATION);
        
        assertNotNull(response);
        assertEquals(FileSystemInformation.SMB_INFO_ALLOCATION, response.getInformationLevel());
        assertEquals(ServerMessageBlock.SMB_COM_TRANSACTION2, response.getCommand());
        assertEquals(SmbComTransaction.TRANS2_QUERY_FS_INFORMATION, response.getSubCommand());
    }

    @ParameterizedTest
    @ValueSource(ints = {
        FileSystemInformation.SMB_INFO_ALLOCATION,
        FileSystemInformation.FS_SIZE_INFO,
        FileSystemInformation.FS_FULL_SIZE_INFO
    })
    void testConstructorWithDifferentInformationLevels(int informationLevel) {
        // Test constructor with different information levels
        response = new Trans2QueryFSInformationResponse(config, informationLevel);
        
        assertNotNull(response);
        assertEquals(informationLevel, response.getInformationLevel());
        assertEquals(ServerMessageBlock.SMB_COM_TRANSACTION2, response.getCommand());
        assertEquals(SmbComTransaction.TRANS2_QUERY_FS_INFORMATION, response.getSubCommand());
    }

    @Test
    void testGetInformationLevel() {
        // Test getInformationLevel method
        response = new Trans2QueryFSInformationResponse(config, FileSystemInformation.FS_SIZE_INFO);
        
        assertEquals(FileSystemInformation.FS_SIZE_INFO, response.getInformationLevel());
    }

    @Test
    void testGetInfo() {
        // Test getInfo method when info is null
        response = new Trans2QueryFSInformationResponse(config, FileSystemInformation.SMB_INFO_ALLOCATION);
        
        assertNull(response.getInfo());
    }

    @Test
    void testGetInfoWithClass_Compatible() throws CIFSException {
        // Test getInfo with compatible class
        response = new Trans2QueryFSInformationResponse(config, FileSystemInformation.SMB_INFO_ALLOCATION);
        
        // Simulate setting info using reflection
        SmbInfoAllocation allocation = new SmbInfoAllocation();
        setInfoField(response, allocation);
        
        SmbInfoAllocation result = response.getInfo(SmbInfoAllocation.class);
        assertNotNull(result);
        assertSame(allocation, result);
    }

    @Test
    void testGetInfoWithClass_Incompatible() throws Exception {
        // Test getInfo with incompatible class throws exception
        response = new Trans2QueryFSInformationResponse(config, FileSystemInformation.SMB_INFO_ALLOCATION);
        
        // Set info to SmbInfoAllocation
        SmbInfoAllocation allocation = new SmbInfoAllocation();
        setInfoField(response, allocation);
        
        // Try to get as FileFsSizeInformation (incompatible)
        assertThrows(CIFSException.class, () -> {
            response.getInfo(FileFsSizeInformation.class);
        });
    }

    @Test
    void testGetInfoWithClass_BaseClass() throws CIFSException {
        // Test getInfo with base class
        response = new Trans2QueryFSInformationResponse(config, FileSystemInformation.SMB_INFO_ALLOCATION);
        
        SmbInfoAllocation allocation = new SmbInfoAllocation();
        setInfoField(response, allocation);
        
        FileSystemInformation result = response.getInfo(FileSystemInformation.class);
        assertNotNull(result);
        assertSame(allocation, result);
    }

    @Test
    void testWriteSetupWireFormat() {
        // Test writeSetupWireFormat returns 0
        response = new Trans2QueryFSInformationResponse(config, FileSystemInformation.SMB_INFO_ALLOCATION);
        
        byte[] buffer = new byte[10];
        int written = response.writeSetupWireFormat(buffer, 0);
        
        assertEquals(0, written);
    }

    @Test
    void testWriteParametersWireFormat() {
        // Test writeParametersWireFormat returns 0
        response = new Trans2QueryFSInformationResponse(config, FileSystemInformation.SMB_INFO_ALLOCATION);
        
        byte[] buffer = new byte[10];
        int written = response.writeParametersWireFormat(buffer, 0);
        
        assertEquals(0, written);
    }

    @Test
    void testWriteDataWireFormat() {
        // Test writeDataWireFormat returns 0
        response = new Trans2QueryFSInformationResponse(config, FileSystemInformation.SMB_INFO_ALLOCATION);
        
        byte[] buffer = new byte[10];
        int written = response.writeDataWireFormat(buffer, 0);
        
        assertEquals(0, written);
    }

    @Test
    void testReadSetupWireFormat() {
        // Test readSetupWireFormat returns 0
        response = new Trans2QueryFSInformationResponse(config, FileSystemInformation.SMB_INFO_ALLOCATION);
        
        byte[] buffer = new byte[10];
        int read = response.readSetupWireFormat(buffer, 0, 10);
        
        assertEquals(0, read);
    }

    @Test
    void testReadParametersWireFormat() {
        // Test readParametersWireFormat returns 0
        response = new Trans2QueryFSInformationResponse(config, FileSystemInformation.SMB_INFO_ALLOCATION);
        
        byte[] buffer = new byte[10];
        int read = response.readParametersWireFormat(buffer, 0, 10);
        
        assertEquals(0, read);
    }

    @Test
    void testReadDataWireFormat_SmbInfoAllocation() throws Exception {
        // Test reading SMB_INFO_ALLOCATION data
        response = new Trans2QueryFSInformationResponse(config, FileSystemInformation.SMB_INFO_ALLOCATION);
        
        // Prepare buffer with SmbInfoAllocation data
        byte[] buffer = new byte[100];
        int offset = 0;
        
        // idFileSystem (4 bytes) - skipped in decode
        SMBUtil.writeInt4(0, buffer, offset);
        offset += 4;
        
        // sectPerAlloc (4 bytes)
        SMBUtil.writeInt4(8, buffer, offset);
        offset += 4;
        
        // alloc (4 bytes)
        SMBUtil.writeInt4(1000000, buffer, offset);
        offset += 4;
        
        // free (4 bytes)
        SMBUtil.writeInt4(500000, buffer, offset);
        offset += 4;
        
        // bytesPerSect (2 bytes + 2 padding)
        SMBUtil.writeInt2(512, buffer, offset);
        offset += 4;
        
        // Set dataCount using reflection
        setDataCount(response, offset);
        
        int bytesRead = response.readDataWireFormat(buffer, 0, offset);
        
        assertEquals(offset, bytesRead);
        assertNotNull(response.getInfo());
        assertTrue(response.getInfo() instanceof SmbInfoAllocation);
        
        SmbInfoAllocation info = (SmbInfoAllocation) response.getInfo();
        assertEquals(8L * 1000000L * 512L, info.getCapacity());
        assertEquals(8L * 500000L * 512L, info.getFree());
    }

    @Test
    void testReadDataWireFormat_FileFsSizeInformation() throws Exception {
        // Test reading FS_SIZE_INFO data
        response = new Trans2QueryFSInformationResponse(config, FileSystemInformation.FS_SIZE_INFO);
        
        // Prepare buffer with FileFsSizeInformation data
        byte[] buffer = new byte[100];
        int offset = 0;
        
        // totalAllocationUnits (8 bytes)
        SMBUtil.writeInt8(1000000L, buffer, offset);
        offset += 8;
        
        // availableAllocationUnits (8 bytes)
        SMBUtil.writeInt8(500000L, buffer, offset);
        offset += 8;
        
        // sectorsPerAllocationUnit (4 bytes)
        SMBUtil.writeInt4(8, buffer, offset);
        offset += 4;
        
        // bytesPerSector (4 bytes)
        SMBUtil.writeInt4(512, buffer, offset);
        offset += 4;
        
        // Set dataCount using reflection
        setDataCount(response, offset);
        
        int bytesRead = response.readDataWireFormat(buffer, 0, offset);
        
        assertEquals(offset, bytesRead);
        assertNotNull(response.getInfo());
        assertTrue(response.getInfo() instanceof FileFsSizeInformation);
        
        FileFsSizeInformation info = (FileFsSizeInformation) response.getInfo();
        assertEquals(1000000L * 8L * 512L, info.getCapacity());
        assertEquals(500000L * 8L * 512L, info.getFree());
    }

    @Test
    void testReadDataWireFormat_FileFsFullSizeInformation() throws Exception {
        // Test reading FS_FULL_SIZE_INFO data
        response = new Trans2QueryFSInformationResponse(config, FileSystemInformation.FS_FULL_SIZE_INFO);
        
        // Prepare buffer with FileFsFullSizeInformation data
        byte[] buffer = new byte[100];
        int offset = 0;
        
        // totalAllocationUnits (8 bytes)
        SMBUtil.writeInt8(2000000L, buffer, offset);
        offset += 8;
        
        // callerAvailableAllocationUnits (8 bytes)
        SMBUtil.writeInt8(800000L, buffer, offset);
        offset += 8;
        
        // actualAvailableAllocationUnits (8 bytes)
        SMBUtil.writeInt8(900000L, buffer, offset);
        offset += 8;
        
        // sectorsPerAllocationUnit (4 bytes)
        SMBUtil.writeInt4(16, buffer, offset);
        offset += 4;
        
        // bytesPerSector (4 bytes)
        SMBUtil.writeInt4(4096, buffer, offset);
        offset += 4;
        
        // Set dataCount using reflection
        setDataCount(response, offset);
        
        int bytesRead = response.readDataWireFormat(buffer, 0, offset);
        
        assertEquals(offset, bytesRead);
        assertNotNull(response.getInfo());
        assertTrue(response.getInfo() instanceof FileFsFullSizeInformation);
        
        FileFsFullSizeInformation info = (FileFsFullSizeInformation) response.getInfo();
        assertEquals(2000000L * 16L * 4096L, info.getCapacity());
        assertEquals(800000L * 16L * 4096L, info.getFree()); // This is caller available allocation units
    }

    @Test
    void testReadDataWireFormat_UnsupportedInformationLevel() throws Exception {
        // Test with unsupported information level
        response = new Trans2QueryFSInformationResponse(config, 0x999); // Invalid level
        
        byte[] buffer = new byte[100];
        
        // Set dataCount using reflection
        setDataCount(response, 20);
        
        int bytesRead = response.readDataWireFormat(buffer, 0, 20);
        
        assertEquals(0, bytesRead);
        assertNull(response.getInfo());
    }

    @Test
    void testReadDataWireFormat_EmptyBuffer() throws Exception {
        // Test with empty dataCount but decode still processes buffer
        // Note: SmbInfoAllocation.decode() doesn't check len parameter, always reads 20 bytes
        response = new Trans2QueryFSInformationResponse(config, FileSystemInformation.SMB_INFO_ALLOCATION);
        
        byte[] buffer = new byte[100];
        // Initialize buffer with zeros to avoid random data
        java.util.Arrays.fill(buffer, (byte)0);
        
        // Set dataCount to 0 - but decode still runs
        setDataCount(response, 0);
        
        int bytesRead = response.readDataWireFormat(buffer, 0, 0);
        
        // SmbInfoAllocation.decode() always returns 20 bytes regardless of len parameter
        assertEquals(20, bytesRead);
        assertNotNull(response.getInfo());
        
        // The info should be created with zero values
        SmbInfoAllocation info = (SmbInfoAllocation) response.getInfo();
        assertEquals(0, info.getCapacity());
        assertEquals(0, info.getFree());
    }

    @Test
    void testReadDataWireFormat_BufferTooSmall() throws Exception {
        // Test with buffer too small for complete data
        response = new Trans2QueryFSInformationResponse(config, FileSystemInformation.SMB_INFO_ALLOCATION);
        
        byte[] buffer = new byte[10]; // Too small for SmbInfoAllocation
        
        // Set dataCount
        setDataCount(response, 10);
        
        // This should throw an exception during decode
        assertThrows(Exception.class, () -> {
            response.readDataWireFormat(buffer, 0, 10);
        });
    }

    @Test
    void testToString() {
        // Test toString method
        response = new Trans2QueryFSInformationResponse(config, FileSystemInformation.SMB_INFO_ALLOCATION);
        
        String result = response.toString();
        
        assertNotNull(result);
        assertTrue(result.contains("Trans2QueryFSInformationResponse"));
    }

    @Test
    void testCreateInfo_AllInformationLevels() throws Exception {
        // Test createInfo private method with all supported levels
        Method createInfoMethod = Trans2QueryFSInformationResponse.class.getDeclaredMethod("createInfo");
        createInfoMethod.setAccessible(true);
        
        // Test SMB_INFO_ALLOCATION
        response = new Trans2QueryFSInformationResponse(config, FileSystemInformation.SMB_INFO_ALLOCATION);
        Object result = createInfoMethod.invoke(response);
        assertNotNull(result);
        assertTrue(result instanceof SmbInfoAllocation);
        
        // Test FS_SIZE_INFO
        response = new Trans2QueryFSInformationResponse(config, FileSystemInformation.FS_SIZE_INFO);
        result = createInfoMethod.invoke(response);
        assertNotNull(result);
        assertTrue(result instanceof FileFsSizeInformation);
        
        // Test FS_FULL_SIZE_INFO
        response = new Trans2QueryFSInformationResponse(config, FileSystemInformation.FS_FULL_SIZE_INFO);
        result = createInfoMethod.invoke(response);
        assertNotNull(result);
        assertTrue(result instanceof FileFsFullSizeInformation);
        
        // Test unsupported level
        response = new Trans2QueryFSInformationResponse(config, 0x999);
        result = createInfoMethod.invoke(response);
        assertNull(result);
    }

    @Test
    void testMultipleReadDataWireFormat() throws Exception {
        // Test multiple calls to readDataWireFormat
        response = new Trans2QueryFSInformationResponse(config, FileSystemInformation.SMB_INFO_ALLOCATION);
        
        // Prepare buffer
        byte[] buffer = prepareAllocationInfoBuffer();
        
        // Set dataCount
        setDataCount(response, 20);
        
        // First read
        int bytesRead1 = response.readDataWireFormat(buffer, 0, 20);
        FileSystemInformation info1 = response.getInfo();
        
        // Second read with different data
        buffer = prepareAllocationInfoBuffer();
        buffer[8] = 10; // Change some data
        
        int bytesRead2 = response.readDataWireFormat(buffer, 0, 20);
        FileSystemInformation info2 = response.getInfo();
        
        // Info should be updated
        assertNotSame(info1, info2);
    }

    @Test
    void testReadDataWireFormat_WithOffset() throws Exception {
        // Test reading data with non-zero buffer offset
        response = new Trans2QueryFSInformationResponse(config, FileSystemInformation.SMB_INFO_ALLOCATION);
        
        byte[] buffer = new byte[100];
        int offset = 20;
        
        // Prepare data at offset
        int dataOffset = offset;
        SMBUtil.writeInt4(0, buffer, dataOffset);
        dataOffset += 4;
        SMBUtil.writeInt4(8, buffer, dataOffset);
        dataOffset += 4;
        SMBUtil.writeInt4(1000000, buffer, dataOffset);
        dataOffset += 4;
        SMBUtil.writeInt4(500000, buffer, dataOffset);
        dataOffset += 4;
        SMBUtil.writeInt2(512, buffer, dataOffset);
        
        // Set dataCount
        setDataCount(response, 20);
        
        int bytesRead = response.readDataWireFormat(buffer, offset, 20);
        
        assertEquals(20, bytesRead);
        assertNotNull(response.getInfo());
    }

    @Test
    void testInformationLevelConstants() {
        // Verify information level constants are correctly used
        assertEquals((byte)-1, FileSystemInformation.SMB_INFO_ALLOCATION);
        assertEquals((byte)3, FileSystemInformation.FS_SIZE_INFO);
        assertEquals((byte)7, FileSystemInformation.FS_FULL_SIZE_INFO);
    }

    // Helper methods
    
    private void setInfoField(Trans2QueryFSInformationResponse response, FileSystemInformation info) {
        try {
            Field infoField = Trans2QueryFSInformationResponse.class.getDeclaredField("info");
            infoField.setAccessible(true);
            infoField.set(response, info);
        } catch (Exception e) {
            fail("Failed to set info field: " + e.getMessage());
        }
    }
    
    private void setDataCount(Trans2QueryFSInformationResponse response, int dataCount) {
        // Use the public setDataCount method from SmbComTransactionResponse
        response.setDataCount(dataCount);
    }
    
    private byte[] prepareAllocationInfoBuffer() {
        byte[] buffer = new byte[100];
        int offset = 0;
        
        // idFileSystem (4 bytes)
        SMBUtil.writeInt4(0, buffer, offset);
        offset += 4;
        
        // sectPerAlloc (4 bytes)
        SMBUtil.writeInt4(8, buffer, offset);
        offset += 4;
        
        // alloc (4 bytes)
        SMBUtil.writeInt4(1000000, buffer, offset);
        offset += 4;
        
        // free (4 bytes)
        SMBUtil.writeInt4(500000, buffer, offset);
        offset += 4;
        
        // bytesPerSect (2 bytes + 2 padding)
        SMBUtil.writeInt2(512, buffer, offset);
        
        return buffer;
    }
}
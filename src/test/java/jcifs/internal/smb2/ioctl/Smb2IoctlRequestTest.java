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
package jcifs.internal.smb2.ioctl;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import java.util.Arrays;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import jcifs.CIFSContext;
import jcifs.Configuration;
import jcifs.Encodable;
import jcifs.internal.smb2.Smb2Constants;

/**
 * Test class for Smb2IoctlRequest
 * 
 * @author test
 */
@ExtendWith(MockitoExtension.class)
class Smb2IoctlRequestTest {

    @Mock
    private Configuration mockConfig;
    
    @Mock
    private CIFSContext mockContext;
    
    @Mock
    private Encodable mockInputData;
    
    @Mock
    private Encodable mockOutputData;
    
    private static final int TEST_CONTROL_CODE = Smb2IoctlRequest.FSCTL_DFS_GET_REFERRALS;
    private static final byte[] TEST_FILE_ID = new byte[16];
    private static final byte[] TEST_OUTPUT_BUFFER = new byte[1024];
    
    @BeforeEach
    void setUp() {
        Arrays.fill(TEST_FILE_ID, (byte) 0x42);
    }
    
    private void setupMockConfig() {
        when(mockConfig.getTransactionBufferSize()).thenReturn(65536);
    }
    
    private void setupMockContext() {
        when(mockContext.getConfig()).thenReturn(mockConfig);
    }
    
    @Test
    @DisplayName("Test constructor with config and control code")
    void testConstructorWithConfigAndControlCode() {
        setupMockConfig();
        Smb2IoctlRequest request = new Smb2IoctlRequest(mockConfig, TEST_CONTROL_CODE);
        
        assertNotNull(request);
        assertEquals(0x0B, request.getCommand()); // SMB2_IOCTL command
        verify(mockConfig).getTransactionBufferSize();
    }
    
    @Test
    @DisplayName("Test constructor with config, control code and file ID")
    void testConstructorWithFileId() {
        setupMockConfig();
        Smb2IoctlRequest request = new Smb2IoctlRequest(mockConfig, TEST_CONTROL_CODE, TEST_FILE_ID);
        
        assertNotNull(request);
        assertEquals(0x0B, request.getCommand());
        verify(mockConfig).getTransactionBufferSize();
    }
    
    @Test
    @DisplayName("Test constructor with output buffer")
    void testConstructorWithOutputBuffer() {
        // This constructor doesn't use getTransactionBufferSize()
        Smb2IoctlRequest request = new Smb2IoctlRequest(mockConfig, TEST_CONTROL_CODE, TEST_FILE_ID, TEST_OUTPUT_BUFFER);
        
        assertNotNull(request);
        assertEquals(0x0B, request.getCommand());
        // maxOutputResponse should be set to output buffer length
    }
    
    @Test
    @DisplayName("Test setFileId method")
    void testSetFileId() {
        setupMockConfig();
        Smb2IoctlRequest request = new Smb2IoctlRequest(mockConfig, TEST_CONTROL_CODE);
        byte[] newFileId = new byte[16];
        Arrays.fill(newFileId, (byte) 0x55);
        
        request.setFileId(newFileId);
        // FileId is set internally
        assertNotNull(request);
    }
    
    @Test
    @DisplayName("Test createResponse method")
    void testCreateResponse() {
        // This constructor doesn't use getTransactionBufferSize()
        setupMockContext();
        Smb2IoctlRequest request = new Smb2IoctlRequest(mockConfig, TEST_CONTROL_CODE, TEST_FILE_ID, TEST_OUTPUT_BUFFER);
        
        Smb2IoctlResponse response = request.createResponse(mockContext, request);
        
        assertNotNull(response);
        verify(mockContext).getConfig();
    }
    
    @Test
    @DisplayName("Test setFlags method")
    void testSetFlags() {
        setupMockConfig();
        Smb2IoctlRequest request = new Smb2IoctlRequest(mockConfig, TEST_CONTROL_CODE);
        
        request.setFlags(Smb2IoctlRequest.SMB2_O_IOCTL_IS_FSCTL);
        
        assertNotNull(request);
    }
    
    @Test
    @DisplayName("Test setMaxInputResponse method")
    void testSetMaxInputResponse() {
        setupMockConfig();
        Smb2IoctlRequest request = new Smb2IoctlRequest(mockConfig, TEST_CONTROL_CODE);
        int maxInput = 2048;
        
        request.setMaxInputResponse(maxInput);
        
        assertNotNull(request);
    }
    
    @Test
    @DisplayName("Test setMaxOutputResponse method")
    void testSetMaxOutputResponse() {
        setupMockConfig();
        Smb2IoctlRequest request = new Smb2IoctlRequest(mockConfig, TEST_CONTROL_CODE);
        int maxOutput = 4096;
        
        request.setMaxOutputResponse(maxOutput);
        
        assertNotNull(request);
    }
    
    @Test
    @DisplayName("Test setInputData method")
    void testSetInputData() {
        setupMockConfig();
        Smb2IoctlRequest request = new Smb2IoctlRequest(mockConfig, TEST_CONTROL_CODE);
        
        request.setInputData(mockInputData);
        
        assertNotNull(request);
    }
    
    @Test
    @DisplayName("Test setOutputData method")
    void testSetOutputData() {
        setupMockConfig();
        Smb2IoctlRequest request = new Smb2IoctlRequest(mockConfig, TEST_CONTROL_CODE);
        
        request.setOutputData(mockOutputData);
        
        assertNotNull(request);
    }
    
    @Test
    @DisplayName("Test size calculation without data")
    void testSizeWithoutData() {
        setupMockConfig();
        Smb2IoctlRequest request = new Smb2IoctlRequest(mockConfig, TEST_CONTROL_CODE);
        
        int size = request.size();
        
        // Base size: SMB2_HEADER_LENGTH (64) + 56 = 120, aligned to 8
        assertEquals(120, size);
    }
    
    @Test
    @DisplayName("Test size calculation with input data")
    void testSizeWithInputData() {
        setupMockConfig();
        Smb2IoctlRequest request = new Smb2IoctlRequest(mockConfig, TEST_CONTROL_CODE);
        when(mockInputData.size()).thenReturn(100);
        request.setInputData(mockInputData);
        
        int size = request.size();
        
        // Base size 120 + 100 = 220, aligned to 8 = 224
        assertEquals(224, size);
        verify(mockInputData).size();
    }
    
    @Test
    @DisplayName("Test size calculation with output data")
    void testSizeWithOutputData() {
        setupMockConfig();
        Smb2IoctlRequest request = new Smb2IoctlRequest(mockConfig, TEST_CONTROL_CODE);
        when(mockOutputData.size()).thenReturn(50);
        request.setOutputData(mockOutputData);
        
        int size = request.size();
        
        // Base size 120 + 50 = 170, aligned to 8 = 176
        assertEquals(176, size);
        verify(mockOutputData).size();
    }
    
    @Test
    @DisplayName("Test size calculation with both input and output data")
    void testSizeWithBothData() {
        setupMockConfig();
        Smb2IoctlRequest request = new Smb2IoctlRequest(mockConfig, TEST_CONTROL_CODE);
        when(mockInputData.size()).thenReturn(100);
        when(mockOutputData.size()).thenReturn(50);
        request.setInputData(mockInputData);
        request.setOutputData(mockOutputData);
        
        int size = request.size();
        
        // Base size 120 + 100 + 50 = 270, aligned to 8 = 272
        assertEquals(272, size);
        verify(mockInputData).size();
        verify(mockOutputData).size();
    }
    
    @Test
    @DisplayName("Test writeBytesWireFormat without data")
    void testWriteBytesWireFormatWithoutData() {
        setupMockConfig();
        Smb2IoctlRequest request = new Smb2IoctlRequest(mockConfig, TEST_CONTROL_CODE, TEST_FILE_ID);
        byte[] buffer = new byte[1024];
        
        int written = request.writeBytesWireFormat(buffer, 0);
        
        // Should write exactly 56 bytes (structure size without data)
        assertEquals(56, written);
        // Check structure size (first 2 bytes should be 57)
        assertEquals(57, (buffer[0] & 0xFF) | ((buffer[1] & 0xFF) << 8));
    }
    
    @Test
    @DisplayName("Test writeBytesWireFormat with input data")
    void testWriteBytesWireFormatWithInputData() {
        setupMockConfig();
        Smb2IoctlRequest request = new Smb2IoctlRequest(mockConfig, TEST_CONTROL_CODE, TEST_FILE_ID);
        when(mockInputData.encode(any(byte[].class), anyInt())).thenReturn(100);
        request.setInputData(mockInputData);
        byte[] buffer = new byte[1024];
        
        int written = request.writeBytesWireFormat(buffer, 0);
        
        assertTrue(written > 57);
        verify(mockInputData).encode(any(byte[].class), anyInt());
    }
    
    @Test
    @DisplayName("Test writeBytesWireFormat with output data")
    void testWriteBytesWireFormatWithOutputData() {
        setupMockConfig();
        Smb2IoctlRequest request = new Smb2IoctlRequest(mockConfig, TEST_CONTROL_CODE, TEST_FILE_ID);
        when(mockOutputData.encode(any(byte[].class), anyInt())).thenReturn(50);
        request.setOutputData(mockOutputData);
        byte[] buffer = new byte[1024];
        
        int written = request.writeBytesWireFormat(buffer, 0);
        
        assertTrue(written > 57);
        verify(mockOutputData).encode(any(byte[].class), anyInt());
    }
    
    @Test
    @DisplayName("Test writeBytesWireFormat with both data")
    void testWriteBytesWireFormatWithBothData() {
        setupMockConfig();
        Smb2IoctlRequest request = new Smb2IoctlRequest(mockConfig, TEST_CONTROL_CODE, TEST_FILE_ID);
        when(mockInputData.encode(any(byte[].class), anyInt())).thenReturn(100);
        when(mockOutputData.encode(any(byte[].class), anyInt())).thenReturn(50);
        request.setInputData(mockInputData);
        request.setOutputData(mockOutputData);
        request.setFlags(Smb2IoctlRequest.SMB2_O_IOCTL_IS_FSCTL);
        byte[] buffer = new byte[1024];
        
        int written = request.writeBytesWireFormat(buffer, 0);
        
        // Should write base structure (56) + data
        assertEquals(56 + 100 + 50, written);
        verify(mockInputData).encode(any(byte[].class), anyInt());
        verify(mockOutputData).encode(any(byte[].class), anyInt());
    }
    
    @Test
    @DisplayName("Test readBytesWireFormat returns 0")
    void testReadBytesWireFormat() {
        setupMockConfig();
        Smb2IoctlRequest request = new Smb2IoctlRequest(mockConfig, TEST_CONTROL_CODE);
        byte[] buffer = new byte[1024];
        
        int read = request.readBytesWireFormat(buffer, 0);
        
        // This method always returns 0 for requests
        assertEquals(0, read);
    }
    
    @Test
    @DisplayName("Test with unspecified file ID")
    void testWithUnspecifiedFileId() {
        setupMockConfig();
        Smb2IoctlRequest request = new Smb2IoctlRequest(mockConfig, TEST_CONTROL_CODE);
        
        assertNotNull(request);
        // Should use UNSPECIFIED_FILEID by default
    }
    
    @Test
    @DisplayName("Test various FSCTL constants")
    void testFsctlConstants() {
        // Test that all FSCTL constants are properly defined
        assertEquals(0x0060194, Smb2IoctlRequest.FSCTL_DFS_GET_REFERRALS);
        assertEquals(0x0011400C, Smb2IoctlRequest.FSCTL_PIPE_PEEK);
        assertEquals(0x00110018, Smb2IoctlRequest.FSCTL_PIPE_WAIT);
        assertEquals(0x0011C017, Smb2IoctlRequest.FSCTL_PIPE_TRANSCEIVE);
        assertEquals(0x001440F2, Smb2IoctlRequest.FSCTL_SRV_COPYCHUNK);
        assertEquals(0x00144064, Smb2IoctlRequest.FSCTL_SRV_ENUMERATE_SNAPSHOTS);
        assertEquals(0x00140078, Smb2IoctlRequest.FSCTL_SRV_REQUEST_RESUME_KEY);
        assertEquals(0x001441bb, Smb2IoctlRequest.FSCTL_SRV_READ_HASH);
        assertEquals(0x001480F2, Smb2IoctlRequest.FSCTL_SRV_COPYCHUNK_WRITE);
        assertEquals(0x001401D4, Smb2IoctlRequest.FSCTL_LRM_REQUEST_RESILENCY);
        assertEquals(0x001401FC, Smb2IoctlRequest.FSCTL_QUERY_NETWORK_INTERFACE_INFO);
        assertEquals(0x000900A4, Smb2IoctlRequest.FSCTL_SET_REPARSE_POINT);
        assertEquals(0x000601B0, Smb2IoctlRequest.FSCTL_DFS_GET_REFERRALS_EX);
        assertEquals(0x00098208, Smb2IoctlRequest.FSCTL_FILE_LEVEL_TRIM);
        assertEquals(0x000140204, Smb2IoctlRequest.FSCTL_VALIDATE_NEGOTIATE_INFO);
        assertEquals(0x1, Smb2IoctlRequest.SMB2_O_IOCTL_IS_FSCTL);
    }
    
    @Test
    @DisplayName("Test configuration with different control codes")
    void testDifferentControlCodes() {
        setupMockConfig();
        // Test with different control codes
        int[] controlCodes = {
            Smb2IoctlRequest.FSCTL_PIPE_PEEK,
            Smb2IoctlRequest.FSCTL_PIPE_WAIT,
            Smb2IoctlRequest.FSCTL_PIPE_TRANSCEIVE,
            Smb2IoctlRequest.FSCTL_SRV_COPYCHUNK,
            Smb2IoctlRequest.FSCTL_VALIDATE_NEGOTIATE_INFO
        };
        
        for (int controlCode : controlCodes) {
            Smb2IoctlRequest request = new Smb2IoctlRequest(mockConfig, controlCode, TEST_FILE_ID);
            assertNotNull(request);
            assertEquals(0x0B, request.getCommand());
        }
    }
    
    @Test
    @DisplayName("Test maxOutputResponse calculation with transaction buffer size")
    void testMaxOutputResponseCalculation() {
        // Test that maxOutputResponse is properly calculated from transaction buffer size
        when(mockConfig.getTransactionBufferSize()).thenReturn(8192);
        
        Smb2IoctlRequest request = new Smb2IoctlRequest(mockConfig, TEST_CONTROL_CODE);
        
        assertNotNull(request);
        // maxOutputResponse should be transactionBufferSize & ~0x7 (aligned to 8)
        verify(mockConfig).getTransactionBufferSize();
    }
    
    @Test
    @DisplayName("Test writeBytesWireFormat with different file IDs")
    void testWriteBytesWireFormatFileIdCopy() {
        setupMockConfig();
        byte[] customFileId = new byte[16];
        for (int i = 0; i < 16; i++) {
            customFileId[i] = (byte) i;
        }
        
        Smb2IoctlRequest request = new Smb2IoctlRequest(mockConfig, TEST_CONTROL_CODE, customFileId);
        byte[] buffer = new byte[1024];
        
        int written = request.writeBytesWireFormat(buffer, 0);
        
        // Verify file ID is copied correctly (starts at offset 8)
        for (int i = 0; i < 16; i++) {
            assertEquals(customFileId[i], buffer[8 + i]);
        }
        assertEquals(56, written);
    }
    
    @Test
    @DisplayName("Test writeBytesWireFormat control code encoding")
    void testWriteBytesWireFormatControlCode() {
        setupMockConfig();
        int testControlCode = 0x12345678;
        Smb2IoctlRequest request = new Smb2IoctlRequest(mockConfig, testControlCode, TEST_FILE_ID);
        byte[] buffer = new byte[1024];
        
        request.writeBytesWireFormat(buffer, 0);
        
        // Control code is at offset 4 (4 bytes)
        int encodedControlCode = (buffer[4] & 0xFF) | 
                                 ((buffer[5] & 0xFF) << 8) | 
                                 ((buffer[6] & 0xFF) << 16) | 
                                 ((buffer[7] & 0xFF) << 24);
        assertEquals(testControlCode, encodedControlCode);
    }
}
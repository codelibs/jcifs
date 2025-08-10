package jcifs.internal.smb2.info;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.times;

import java.lang.reflect.Field;
import java.lang.reflect.Method;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import jcifs.CIFSContext;
import jcifs.Configuration;
import jcifs.Encodable;
import jcifs.internal.fscc.FileInformation;
import jcifs.internal.smb2.ServerMessageBlock2;
import jcifs.internal.smb2.ServerMessageBlock2Request;
import jcifs.internal.smb2.Smb2Constants;
import jcifs.internal.util.SMBUtil;

/**
 * Test class for Smb2SetInfoRequest functionality
 */
@DisplayName("Smb2SetInfoRequest Tests")
@MockitoSettings(strictness = Strictness.LENIENT)
class Smb2SetInfoRequestTest {

    private Configuration mockConfig;
    private CIFSContext mockContext;
    private Smb2SetInfoRequest request;
    private byte[] testFileId;

    @BeforeEach
    void setUp() {
        mockConfig = mock(Configuration.class);
        mockContext = mock(CIFSContext.class);
        when(mockContext.getConfig()).thenReturn(mockConfig);
        
        testFileId = new byte[16];
        for (int i = 0; i < 16; i++) {
            testFileId[i] = (byte) i;
        }
    }

    @Test
    @DisplayName("Test constructor with Configuration only")
    void testConstructorWithConfigOnly() {
        request = new Smb2SetInfoRequest(mockConfig);
        
        assertNotNull(request);
        // SMB2_SET_INFO command value is 0x0011
        assertEquals((short) 0x0011, request.getCommand());
        
        // Verify that default file ID is set
        byte[] expectedFileId = Smb2Constants.UNSPECIFIED_FILEID;
        Field fileIdField;
        try {
            fileIdField = Smb2SetInfoRequest.class.getDeclaredField("fileId");
            fileIdField.setAccessible(true);
            byte[] actualFileId = (byte[]) fileIdField.get(request);
            assertArrayEquals(expectedFileId, actualFileId);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    @DisplayName("Test constructor with Configuration and FileId")
    void testConstructorWithConfigAndFileId() {
        request = new Smb2SetInfoRequest(mockConfig, testFileId);
        
        assertNotNull(request);
        // SMB2_SET_INFO command value is 0x0011
        assertEquals((short) 0x0011, request.getCommand());
        
        // Verify file ID is set correctly
        Field fileIdField;
        try {
            fileIdField = Smb2SetInfoRequest.class.getDeclaredField("fileId");
            fileIdField.setAccessible(true);
            byte[] actualFileId = (byte[]) fileIdField.get(request);
            assertArrayEquals(testFileId, actualFileId);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    @DisplayName("Test setFileId method")
    void testSetFileId() {
        request = new Smb2SetInfoRequest(mockConfig);
        byte[] newFileId = new byte[16];
        for (int i = 0; i < 16; i++) {
            newFileId[i] = (byte) (i + 10);
        }
        
        request.setFileId(newFileId);
        
        // Verify file ID was updated
        Field fileIdField;
        try {
            fileIdField = Smb2SetInfoRequest.class.getDeclaredField("fileId");
            fileIdField.setAccessible(true);
            byte[] actualFileId = (byte[]) fileIdField.get(request);
            assertArrayEquals(newFileId, actualFileId);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    @DisplayName("Test setInfoType method")
    void testSetInfoType() {
        request = new Smb2SetInfoRequest(mockConfig);
        byte testInfoType = (byte) 0x01;
        
        request.setInfoType(testInfoType);
        
        // Verify info type was set
        Field infoTypeField;
        try {
            infoTypeField = Smb2SetInfoRequest.class.getDeclaredField("infoType");
            infoTypeField.setAccessible(true);
            byte actualInfoType = (byte) infoTypeField.get(request);
            assertEquals(testInfoType, actualInfoType);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    @DisplayName("Test setFileInfoClass method")
    void testSetFileInfoClass() {
        request = new Smb2SetInfoRequest(mockConfig);
        byte testFileInfoClass = (byte) 0x10;
        
        request.setFileInfoClass(testFileInfoClass);
        
        // Verify file info class was set
        Field fileInfoClassField;
        try {
            fileInfoClassField = Smb2SetInfoRequest.class.getDeclaredField("fileInfoClass");
            fileInfoClassField.setAccessible(true);
            byte actualFileInfoClass = (byte) fileInfoClassField.get(request);
            assertEquals(testFileInfoClass, actualFileInfoClass);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    @DisplayName("Test setAdditionalInformation method")
    void testSetAdditionalInformation() {
        request = new Smb2SetInfoRequest(mockConfig);
        int testAdditionalInfo = 0x12345678;
        
        request.setAdditionalInformation(testAdditionalInfo);
        
        // Verify additional information was set
        Field additionalInfoField;
        try {
            additionalInfoField = Smb2SetInfoRequest.class.getDeclaredField("additionalInformation");
            additionalInfoField.setAccessible(true);
            int actualAdditionalInfo = (int) additionalInfoField.get(request);
            assertEquals(testAdditionalInfo, actualAdditionalInfo);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    @DisplayName("Test setFileInformation method")
    void testSetFileInformation() {
        request = new Smb2SetInfoRequest(mockConfig);
        
        // Create a mock FileInformation that is also Encodable
        TestFileInformation mockFileInfo = mock(TestFileInformation.class);
        byte expectedLevel = (byte) 0x04;
        when(mockFileInfo.getFileInformationLevel()).thenReturn(expectedLevel);
        
        request.setFileInformation(mockFileInfo);
        
        // Verify the info type, file info class, and info object were set
        try {
            Field infoTypeField = Smb2SetInfoRequest.class.getDeclaredField("infoType");
            infoTypeField.setAccessible(true);
            byte actualInfoType = (byte) infoTypeField.get(request);
            assertEquals(Smb2Constants.SMB2_0_INFO_FILE, actualInfoType);
            
            Field fileInfoClassField = Smb2SetInfoRequest.class.getDeclaredField("fileInfoClass");
            fileInfoClassField.setAccessible(true);
            byte actualFileInfoClass = (byte) fileInfoClassField.get(request);
            assertEquals(expectedLevel, actualFileInfoClass);
            
            Field infoField = Smb2SetInfoRequest.class.getDeclaredField("info");
            infoField.setAccessible(true);
            Encodable actualInfo = (Encodable) infoField.get(request);
            assertEquals(mockFileInfo, actualInfo);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    @DisplayName("Test setInfo method")
    void testSetInfo() {
        request = new Smb2SetInfoRequest(mockConfig);
        Encodable mockInfo = mock(Encodable.class);
        
        request.setInfo(mockInfo);
        
        // Verify info object was set
        Field infoField;
        try {
            infoField = Smb2SetInfoRequest.class.getDeclaredField("info");
            infoField.setAccessible(true);
            Encodable actualInfo = (Encodable) infoField.get(request);
            assertEquals(mockInfo, actualInfo);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    @DisplayName("Test createResponse method")
    void testCreateResponse() {
        request = new Smb2SetInfoRequest(mockConfig);
        
        Smb2SetInfoResponse response = request.createResponse(mockContext, request);
        
        assertNotNull(response);
        verify(mockContext, times(1)).getConfig();
    }

    @Test
    @DisplayName("Test size method")
    void testSize() {
        request = new Smb2SetInfoRequest(mockConfig);
        Encodable mockInfo = mock(Encodable.class);
        when(mockInfo.size()).thenReturn(100);
        request.setInfo(mockInfo);
        
        int size = request.size();
        
        // Expected size calculation: size8(SMB2_HEADER_LENGTH + 32 + info.size())
        // size8 rounds up to nearest multiple of 8
        int expectedRawSize = Smb2Constants.SMB2_HEADER_LENGTH + 32 + 100;
        int expectedSize = (expectedRawSize + 7) & ~7; // Round up to nearest 8
        assertEquals(expectedSize, size);
    }

    @Test
    @DisplayName("Test writeBytesWireFormat method")
    void testWriteBytesWireFormat() {
        request = new Smb2SetInfoRequest(mockConfig, testFileId);
        request.setInfoType((byte) 0x01);
        request.setFileInfoClass((byte) 0x04);
        request.setAdditionalInformation(0x12345678);
        
        Encodable mockInfo = mock(Encodable.class);
        when(mockInfo.encode(any(byte[].class), anyInt())).thenReturn(20);
        when(mockInfo.size()).thenReturn(20);
        request.setInfo(mockInfo);
        
        // Set up header start for offset calculation
        try {
            Method getHeaderStartMethod = ServerMessageBlock2.class.getDeclaredMethod("getHeaderStart");
            getHeaderStartMethod.setAccessible(true);
            
            // Create a buffer and write
            byte[] buffer = new byte[256];
            int bytesWritten = request.writeBytesWireFormat(buffer, 64);
            
            // Verify structure size (should be 33)
            assertEquals(33, SMBUtil.readInt2(buffer, 64));
            
            // Verify info type and file info class
            assertEquals((byte) 0x01, buffer[66]);
            assertEquals((byte) 0x04, buffer[67]);
            
            // Verify additional information
            assertEquals(0x12345678, SMBUtil.readInt4(buffer, 76));
            
            // Verify file ID
            byte[] actualFileId = new byte[16];
            System.arraycopy(buffer, 80, actualFileId, 0, 16);
            assertArrayEquals(testFileId, actualFileId);
            
            // Verify that info.encode was called
            verify(mockInfo, times(1)).encode(any(byte[].class), anyInt());
            
            // Verify total bytes written
            assertTrue(bytesWritten > 32); // At least the fixed part plus some info
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @ParameterizedTest
    @DisplayName("Test writeBytesWireFormat with different info sizes")
    @ValueSource(ints = {0, 10, 50, 100, 255})
    void testWriteBytesWireFormatWithDifferentSizes(int infoSize) {
        request = new Smb2SetInfoRequest(mockConfig, testFileId);
        
        Encodable mockInfo = mock(Encodable.class);
        when(mockInfo.encode(any(byte[].class), anyInt())).thenReturn(infoSize);
        when(mockInfo.size()).thenReturn(infoSize);
        request.setInfo(mockInfo);
        
        byte[] buffer = new byte[512];
        int bytesWritten = request.writeBytesWireFormat(buffer, 64);
        
        // Verify buffer length field contains the info size
        int bufferLength = SMBUtil.readInt4(buffer, 68);
        assertEquals(infoSize, bufferLength);
        
        // Verify total bytes written
        assertEquals(32 + infoSize, bytesWritten);
    }

    @Test
    @DisplayName("Test readBytesWireFormat returns 0")
    void testReadBytesWireFormat() {
        request = new Smb2SetInfoRequest(mockConfig);
        byte[] buffer = new byte[256];
        
        int bytesRead = request.readBytesWireFormat(buffer, 0);
        
        // This method should always return 0 as the request doesn't read responses
        assertEquals(0, bytesRead);
    }

    @Test
    @DisplayName("Test complete flow with all setters")
    void testCompleteFlow() {
        request = new Smb2SetInfoRequest(mockConfig);
        
        // Set all fields
        byte[] newFileId = new byte[16];
        for (int i = 0; i < 16; i++) {
            newFileId[i] = (byte) (0xFF - i);
        }
        request.setFileId(newFileId);
        request.setInfoType((byte) 0x02);
        request.setFileInfoClass((byte) 0x08);
        request.setAdditionalInformation(0xABCDEF00);
        
        Encodable mockInfo = mock(Encodable.class);
        when(mockInfo.size()).thenReturn(64);
        when(mockInfo.encode(any(byte[].class), anyInt())).thenReturn(64);
        request.setInfo(mockInfo);
        
        // Test size calculation
        int size = request.size();
        int expectedRawSize = Smb2Constants.SMB2_HEADER_LENGTH + 32 + 64;
        int expectedSize = (expectedRawSize + 7) & ~7;
        assertEquals(expectedSize, size);
        
        // Test wire format writing
        byte[] buffer = new byte[512];
        int bytesWritten = request.writeBytesWireFormat(buffer, 64);
        
        // Verify all fields in the buffer
        assertEquals(33, SMBUtil.readInt2(buffer, 64)); // Structure size
        assertEquals((byte) 0x02, buffer[66]); // Info type
        assertEquals((byte) 0x08, buffer[67]); // File info class
        assertEquals(64, SMBUtil.readInt4(buffer, 68)); // Buffer length
        assertEquals(0xABCDEF00, SMBUtil.readInt4(buffer, 76)); // Additional information
        
        // Verify file ID
        byte[] actualFileId = new byte[16];
        System.arraycopy(buffer, 80, actualFileId, 0, 16);
        assertArrayEquals(newFileId, actualFileId);
        
        assertEquals(96, bytesWritten); // 32 bytes header + 64 bytes info
    }

    // Helper interface for testing
    private interface TestFileInformation extends FileInformation, Encodable {
    }
}
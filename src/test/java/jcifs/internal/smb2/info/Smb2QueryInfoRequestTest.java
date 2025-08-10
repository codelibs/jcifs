package jcifs.internal.smb2.info;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
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
import jcifs.internal.smb2.ServerMessageBlock2;
import jcifs.internal.smb2.ServerMessageBlock2Request;
import jcifs.internal.smb2.Smb2Constants;
import jcifs.internal.util.SMBUtil;

/**
 * Test class for Smb2QueryInfoRequest functionality
 */
@DisplayName("Smb2QueryInfoRequest Tests")
@MockitoSettings(strictness = Strictness.LENIENT)
class Smb2QueryInfoRequestTest {

    private Configuration mockConfig;
    private CIFSContext mockContext;
    private Smb2QueryInfoRequest request;
    private byte[] testFileId;

    @BeforeEach
    void setUp() {
        mockConfig = mock(Configuration.class);
        mockContext = mock(CIFSContext.class);
        when(mockContext.getConfig()).thenReturn(mockConfig);
        when(mockConfig.getMaximumBufferSize()).thenReturn(65536);
        when(mockConfig.getListSize()).thenReturn(65536);
        
        testFileId = new byte[16];
        for (int i = 0; i < 16; i++) {
            testFileId[i] = (byte) i;
        }
    }

    @Test
    @DisplayName("Test constructor with Configuration only")
    void testConstructorWithConfigOnly() {
        request = new Smb2QueryInfoRequest(mockConfig);
        
        assertNotNull(request);
        // SMB2_QUERY_INFO command value is 0x0010
        assertEquals((short) 0x0010, request.getCommand());
        
        // Verify that default file ID is set
        byte[] expectedFileId = Smb2Constants.UNSPECIFIED_FILEID;
        Field fileIdField;
        try {
            fileIdField = Smb2QueryInfoRequest.class.getDeclaredField("fileId");
            fileIdField.setAccessible(true);
            byte[] actualFileId = (byte[]) fileIdField.get(request);
            assertArrayEquals(expectedFileId, actualFileId);
            
            // Verify outputBufferLength is calculated correctly
            Field outputBufferLengthField = Smb2QueryInfoRequest.class.getDeclaredField("outputBufferLength");
            outputBufferLengthField.setAccessible(true);
            int actualOutputBufferLength = (int) outputBufferLengthField.get(request);
            int expectedLength = (Math.min(65536, 65536) - Smb2QueryInfoResponse.OVERHEAD) & ~0x7;
            assertEquals(expectedLength, actualOutputBufferLength);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    @DisplayName("Test constructor with Configuration and FileId")
    void testConstructorWithConfigAndFileId() {
        request = new Smb2QueryInfoRequest(mockConfig, testFileId);
        
        assertNotNull(request);
        // SMB2_QUERY_INFO command value is 0x0010
        assertEquals((short) 0x0010, request.getCommand());
        
        // Verify file ID is set correctly
        Field fileIdField;
        try {
            fileIdField = Smb2QueryInfoRequest.class.getDeclaredField("fileId");
            fileIdField.setAccessible(true);
            byte[] actualFileId = (byte[]) fileIdField.get(request);
            assertArrayEquals(testFileId, actualFileId);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    @DisplayName("Test constructor with different buffer sizes")
    void testConstructorWithDifferentBufferSizes() {
        when(mockConfig.getMaximumBufferSize()).thenReturn(32768);
        when(mockConfig.getListSize()).thenReturn(16384);
        
        request = new Smb2QueryInfoRequest(mockConfig);
        
        try {
            Field outputBufferLengthField = Smb2QueryInfoRequest.class.getDeclaredField("outputBufferLength");
            outputBufferLengthField.setAccessible(true);
            int actualOutputBufferLength = (int) outputBufferLengthField.get(request);
            
            // Should use the minimum of the two values
            int expectedLength = (Math.min(32768, 16384) - Smb2QueryInfoResponse.OVERHEAD) & ~0x7;
            assertEquals(expectedLength, actualOutputBufferLength);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    @DisplayName("Test setFileId method")
    void testSetFileId() {
        request = new Smb2QueryInfoRequest(mockConfig);
        byte[] newFileId = new byte[16];
        for (int i = 0; i < 16; i++) {
            newFileId[i] = (byte) (i + 10);
        }
        
        request.setFileId(newFileId);
        
        // Verify file ID was updated
        Field fileIdField;
        try {
            fileIdField = Smb2QueryInfoRequest.class.getDeclaredField("fileId");
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
        request = new Smb2QueryInfoRequest(mockConfig);
        byte testInfoType = (byte) 0x01;
        
        request.setInfoType(testInfoType);
        
        // Verify info type was set
        Field infoTypeField;
        try {
            infoTypeField = Smb2QueryInfoRequest.class.getDeclaredField("infoType");
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
        request = new Smb2QueryInfoRequest(mockConfig);
        byte testFileInfoClass = (byte) 0x10;
        
        request.setFileInfoClass(testFileInfoClass);
        
        // Verify file info class was set and info type was set to SMB2_0_INFO_FILE
        try {
            Field fileInfoClassField = Smb2QueryInfoRequest.class.getDeclaredField("fileInfoClass");
            fileInfoClassField.setAccessible(true);
            byte actualFileInfoClass = (byte) fileInfoClassField.get(request);
            assertEquals(testFileInfoClass, actualFileInfoClass);
            
            Field infoTypeField = Smb2QueryInfoRequest.class.getDeclaredField("infoType");
            infoTypeField.setAccessible(true);
            byte actualInfoType = (byte) infoTypeField.get(request);
            assertEquals(Smb2Constants.SMB2_0_INFO_FILE, actualInfoType);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    @DisplayName("Test setFilesystemInfoClass method")
    void testSetFilesystemInfoClass() {
        request = new Smb2QueryInfoRequest(mockConfig);
        byte testFileInfoClass = (byte) 0x05;
        
        request.setFilesystemInfoClass(testFileInfoClass);
        
        // Verify file info class was set and info type was set to SMB2_0_INFO_FILESYSTEM
        try {
            Field fileInfoClassField = Smb2QueryInfoRequest.class.getDeclaredField("fileInfoClass");
            fileInfoClassField.setAccessible(true);
            byte actualFileInfoClass = (byte) fileInfoClassField.get(request);
            assertEquals(testFileInfoClass, actualFileInfoClass);
            
            Field infoTypeField = Smb2QueryInfoRequest.class.getDeclaredField("infoType");
            infoTypeField.setAccessible(true);
            byte actualInfoType = (byte) infoTypeField.get(request);
            assertEquals(Smb2Constants.SMB2_0_INFO_FILESYSTEM, actualInfoType);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    @DisplayName("Test setAdditionalInformation method")
    void testSetAdditionalInformation() {
        request = new Smb2QueryInfoRequest(mockConfig);
        int testAdditionalInfo = 0x12345678;
        
        request.setAdditionalInformation(testAdditionalInfo);
        
        // Verify additional information was set
        Field additionalInfoField;
        try {
            additionalInfoField = Smb2QueryInfoRequest.class.getDeclaredField("additionalInformation");
            additionalInfoField.setAccessible(true);
            int actualAdditionalInfo = (int) additionalInfoField.get(request);
            assertEquals(testAdditionalInfo, actualAdditionalInfo);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    @DisplayName("Test setQueryFlags method")
    void testSetQueryFlags() {
        request = new Smb2QueryInfoRequest(mockConfig);
        int testQueryFlags = 0xABCDEF00;
        
        request.setQueryFlags(testQueryFlags);
        
        // Verify query flags were set
        Field queryFlagsField;
        try {
            queryFlagsField = Smb2QueryInfoRequest.class.getDeclaredField("queryFlags");
            queryFlagsField.setAccessible(true);
            int actualQueryFlags = (int) queryFlagsField.get(request);
            assertEquals(testQueryFlags, actualQueryFlags);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    @DisplayName("Test createResponse method")
    void testCreateResponse() {
        request = new Smb2QueryInfoRequest(mockConfig);
        request.setInfoType((byte) 0x01);
        request.setFileInfoClass((byte) 0x04);
        
        Smb2QueryInfoResponse response = request.createResponse(mockContext, request);
        
        assertNotNull(response);
        verify(mockContext, times(1)).getConfig();
    }

    @Test
    @DisplayName("Test size method without input buffer")
    void testSizeWithoutInputBuffer() {
        request = new Smb2QueryInfoRequest(mockConfig);
        
        int size = request.size();
        
        // Expected size calculation: size8(SMB2_HEADER_LENGTH + 40)
        // size8 rounds up to nearest multiple of 8
        int expectedRawSize = Smb2Constants.SMB2_HEADER_LENGTH + 40;
        int expectedSize = (expectedRawSize + 7) & ~7; // Round up to nearest 8
        assertEquals(expectedSize, size);
    }

    @Test
    @DisplayName("Test size method with input buffer")
    void testSizeWithInputBuffer() {
        request = new Smb2QueryInfoRequest(mockConfig);
        
        // Set an input buffer using reflection
        Encodable mockInputBuffer = mock(Encodable.class);
        when(mockInputBuffer.size()).thenReturn(100);
        
        try {
            Field inputBufferField = Smb2QueryInfoRequest.class.getDeclaredField("inputBuffer");
            inputBufferField.setAccessible(true);
            inputBufferField.set(request, mockInputBuffer);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        
        int size = request.size();
        
        // Expected size calculation: size8(SMB2_HEADER_LENGTH + 40 + inputBuffer.size())
        int expectedRawSize = Smb2Constants.SMB2_HEADER_LENGTH + 40 + 100;
        int expectedSize = (expectedRawSize + 7) & ~7;
        assertEquals(expectedSize, size);
    }

    @Test
    @DisplayName("Test writeBytesWireFormat method without input buffer")
    void testWriteBytesWireFormatWithoutInputBuffer() {
        request = new Smb2QueryInfoRequest(mockConfig, testFileId);
        request.setInfoType((byte) 0x01);
        request.setFileInfoClass((byte) 0x04);
        request.setAdditionalInformation(0x12345678);
        request.setQueryFlags(0xABCDEF00);
        
        try {
            // Set outputBufferLength for testing
            Field outputBufferLengthField = Smb2QueryInfoRequest.class.getDeclaredField("outputBufferLength");
            outputBufferLengthField.setAccessible(true);
            outputBufferLengthField.set(request, 0x8000);
            
            // Create a buffer and write
            byte[] buffer = new byte[256];
            int bytesWritten = request.writeBytesWireFormat(buffer, 64);
            
            // Verify structure size (should be 41)
            assertEquals(41, SMBUtil.readInt2(buffer, 64));
            
            // Verify info type and file info class
            assertEquals((byte) 0x01, buffer[66]);
            assertEquals((byte) 0x04, buffer[67]);
            
            // Verify output buffer length
            assertEquals(0x8000, SMBUtil.readInt4(buffer, 68));
            
            // Verify input buffer offset (should be 0 when no input buffer)
            assertEquals(0, SMBUtil.readInt2(buffer, 72));
            
            // Verify input buffer length (should be 0 when no input buffer)
            assertEquals(0, SMBUtil.readInt4(buffer, 76));
            
            // Verify additional information
            assertEquals(0x12345678, SMBUtil.readInt4(buffer, 80));
            
            // Verify query flags
            assertEquals(0xABCDEF00, SMBUtil.readInt4(buffer, 84));
            
            // Verify file ID
            byte[] actualFileId = new byte[16];
            System.arraycopy(buffer, 88, actualFileId, 0, 16);
            assertArrayEquals(testFileId, actualFileId);
            
            // Verify total bytes written
            assertEquals(40, bytesWritten);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    @DisplayName("Test writeBytesWireFormat method with input buffer")
    void testWriteBytesWireFormatWithInputBuffer() {
        request = new Smb2QueryInfoRequest(mockConfig, testFileId);
        request.setInfoType((byte) 0x02);
        request.setFileInfoClass((byte) 0x08);
        
        Encodable mockInputBuffer = mock(Encodable.class);
        when(mockInputBuffer.encode(any(byte[].class), anyInt())).thenReturn(50);
        when(mockInputBuffer.size()).thenReturn(50);
        
        try {
            Field inputBufferField = Smb2QueryInfoRequest.class.getDeclaredField("inputBuffer");
            inputBufferField.setAccessible(true);
            inputBufferField.set(request, mockInputBuffer);
            
            Field outputBufferLengthField = Smb2QueryInfoRequest.class.getDeclaredField("outputBufferLength");
            outputBufferLengthField.setAccessible(true);
            outputBufferLengthField.set(request, 0x4000);
            
            Method getHeaderStartMethod = ServerMessageBlock2.class.getDeclaredMethod("getHeaderStart");
            getHeaderStartMethod.setAccessible(true);
            
            // Create a buffer and write
            byte[] buffer = new byte[512];
            int bytesWritten = request.writeBytesWireFormat(buffer, 64);
            
            // Verify structure size
            assertEquals(41, SMBUtil.readInt2(buffer, 64));
            
            // Verify info type and file info class
            // setFileInfoClass sets the info type to SMB2_0_INFO_FILE (1)
            assertEquals(Smb2Constants.SMB2_0_INFO_FILE, buffer[66]);
            assertEquals((byte) 0x08, buffer[67]);
            
            // Verify output buffer length
            assertEquals(0x4000, SMBUtil.readInt4(buffer, 68));
            
            // Verify input buffer length
            assertEquals(50, SMBUtil.readInt4(buffer, 76));
            
            // Verify that inputBuffer.encode was called
            verify(mockInputBuffer).encode(any(byte[].class), anyInt());
            
            // Verify total bytes written
            assertEquals(90, bytesWritten); // 40 bytes header + 50 bytes input buffer
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @ParameterizedTest
    @DisplayName("Test writeBytesWireFormat with different input buffer sizes")
    @ValueSource(ints = {0, 10, 50, 100, 255})
    void testWriteBytesWireFormatWithDifferentBufferSizes(int bufferSize) {
        request = new Smb2QueryInfoRequest(mockConfig, testFileId);
        
        if (bufferSize > 0) {
            Encodable mockInputBuffer = mock(Encodable.class);
            when(mockInputBuffer.encode(any(byte[].class), anyInt())).thenReturn(bufferSize);
            when(mockInputBuffer.size()).thenReturn(bufferSize);
            
            try {
                Field inputBufferField = Smb2QueryInfoRequest.class.getDeclaredField("inputBuffer");
                inputBufferField.setAccessible(true);
                inputBufferField.set(request, mockInputBuffer);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }
        
        byte[] buffer = new byte[512];
        int bytesWritten = request.writeBytesWireFormat(buffer, 64);
        
        // Verify input buffer length field
        int inputBufferLength = SMBUtil.readInt4(buffer, 76);
        assertEquals(bufferSize, inputBufferLength);
        
        // Verify total bytes written
        assertEquals(40 + bufferSize, bytesWritten);
    }

    @Test
    @DisplayName("Test readBytesWireFormat returns 0")
    void testReadBytesWireFormat() {
        request = new Smb2QueryInfoRequest(mockConfig);
        byte[] buffer = new byte[256];
        
        int bytesRead = request.readBytesWireFormat(buffer, 0);
        
        // This method should always return 0 as the request doesn't read responses
        assertEquals(0, bytesRead);
    }

    @Test
    @DisplayName("Test complete flow with all setters")
    void testCompleteFlow() {
        request = new Smb2QueryInfoRequest(mockConfig);
        
        // Set all fields
        byte[] newFileId = new byte[16];
        for (int i = 0; i < 16; i++) {
            newFileId[i] = (byte) (0xFF - i);
        }
        request.setFileId(newFileId);
        request.setFileInfoClass((byte) 0x0A); // This will set info type to SMB2_0_INFO_FILE
        request.setAdditionalInformation(0xDEADBEEF);
        request.setQueryFlags(0xCAFEBABE);
        
        // Add input buffer
        Encodable mockInputBuffer = mock(Encodable.class);
        when(mockInputBuffer.size()).thenReturn(64);
        when(mockInputBuffer.encode(any(byte[].class), anyInt())).thenReturn(64);
        
        try {
            Field inputBufferField = Smb2QueryInfoRequest.class.getDeclaredField("inputBuffer");
            inputBufferField.setAccessible(true);
            inputBufferField.set(request, mockInputBuffer);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        
        // Test size calculation
        int size = request.size();
        int expectedRawSize = Smb2Constants.SMB2_HEADER_LENGTH + 40 + 64;
        int expectedSize = (expectedRawSize + 7) & ~7;
        assertEquals(expectedSize, size);
        
        // Test wire format writing
        byte[] buffer = new byte[512];
        int bytesWritten = request.writeBytesWireFormat(buffer, 64);
        
        // Verify all fields in the buffer
        assertEquals(41, SMBUtil.readInt2(buffer, 64)); // Structure size
        assertEquals(Smb2Constants.SMB2_0_INFO_FILE, buffer[66]); // Info type (set by setFileInfoClass)
        assertEquals((byte) 0x0A, buffer[67]); // File info class
        assertEquals(64, SMBUtil.readInt4(buffer, 76)); // Input buffer length
        assertEquals(0xDEADBEEF, SMBUtil.readInt4(buffer, 80)); // Additional information
        assertEquals(0xCAFEBABE, SMBUtil.readInt4(buffer, 84)); // Query flags
        
        // Verify file ID
        byte[] actualFileId = new byte[16];
        System.arraycopy(buffer, 88, actualFileId, 0, 16);
        assertArrayEquals(newFileId, actualFileId);
        
        assertEquals(104, bytesWritten); // 40 bytes header + 64 bytes input buffer
    }

    @Test
    @DisplayName("Test setFileInfoClass sets correct info type")
    void testSetFileInfoClassSetsCorrectInfoType() {
        request = new Smb2QueryInfoRequest(mockConfig);
        
        // Initially set a different info type
        request.setInfoType((byte) 0x05);
        
        // Call setFileInfoClass which should override info type
        request.setFileInfoClass((byte) 0x10);
        
        try {
            Field infoTypeField = Smb2QueryInfoRequest.class.getDeclaredField("infoType");
            infoTypeField.setAccessible(true);
            byte actualInfoType = (byte) infoTypeField.get(request);
            
            // Should be set to SMB2_0_INFO_FILE
            assertEquals(Smb2Constants.SMB2_0_INFO_FILE, actualInfoType);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    @DisplayName("Test setFilesystemInfoClass sets correct info type")
    void testSetFilesystemInfoClassSetsCorrectInfoType() {
        request = new Smb2QueryInfoRequest(mockConfig);
        
        // Initially set a different info type
        request.setInfoType((byte) 0x05);
        
        // Call setFilesystemInfoClass which should override info type
        request.setFilesystemInfoClass((byte) 0x08);
        
        try {
            Field infoTypeField = Smb2QueryInfoRequest.class.getDeclaredField("infoType");
            infoTypeField.setAccessible(true);
            byte actualInfoType = (byte) infoTypeField.get(request);
            
            // Should be set to SMB2_0_INFO_FILESYSTEM
            assertEquals(Smb2Constants.SMB2_0_INFO_FILESYSTEM, actualInfoType);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    @DisplayName("Test with null file ID in constructor")
    void testWithNullFileIdInConstructor() {
        // This should use UNSPECIFIED_FILEID internally
        request = new Smb2QueryInfoRequest(mockConfig, null);
        
        try {
            Field fileIdField = Smb2QueryInfoRequest.class.getDeclaredField("fileId");
            fileIdField.setAccessible(true);
            byte[] actualFileId = (byte[]) fileIdField.get(request);
            
            // Should be null as passed
            assertNull(actualFileId);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    @DisplayName("Test buffer size edge cases")
    void testBufferSizeEdgeCases() {
        // Test with very small buffer sizes
        when(mockConfig.getMaximumBufferSize()).thenReturn(256);
        when(mockConfig.getListSize()).thenReturn(128);
        
        request = new Smb2QueryInfoRequest(mockConfig);
        
        try {
            Field outputBufferLengthField = Smb2QueryInfoRequest.class.getDeclaredField("outputBufferLength");
            outputBufferLengthField.setAccessible(true);
            int actualOutputBufferLength = (int) outputBufferLengthField.get(request);
            
            // Should use minimum and apply mask
            int expectedLength = (Math.min(256, 128) - Smb2QueryInfoResponse.OVERHEAD) & ~0x7;
            assertEquals(expectedLength, actualOutputBufferLength);
            
            // Result should be aligned to 8 bytes
            assertEquals(0, actualOutputBufferLength % 8);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
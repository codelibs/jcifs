package jcifs.internal.smb2.info;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import java.lang.reflect.Method;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import jcifs.CIFSException;
import jcifs.Configuration;
import jcifs.Decodable;
import jcifs.internal.SMBProtocolDecodingException;
import jcifs.internal.dtyp.SecurityDescriptor;
import jcifs.internal.fscc.FileFsFullSizeInformation;
import jcifs.internal.fscc.FileFsSizeInformation;
import jcifs.internal.fscc.FileInformation;
import jcifs.internal.fscc.FileInternalInfo;
import jcifs.internal.fscc.FileSystemInformation;
import jcifs.internal.smb2.ServerMessageBlock2;
import jcifs.internal.smb2.ServerMessageBlock2Response;
import jcifs.internal.smb2.Smb2Constants;
import jcifs.internal.util.SMBUtil;

/**
 * Test class for Smb2QueryInfoResponse functionality
 */
@DisplayName("Smb2QueryInfoResponse Tests")
@MockitoSettings(strictness = Strictness.LENIENT)
class Smb2QueryInfoResponseTest {

    @Mock
    private Configuration mockConfig;
    
    @Mock
    private Decodable mockDecodable;
    
    private Smb2QueryInfoResponse response;
    
    @BeforeEach
    void setUp() {
        mockConfig = mock(Configuration.class);
    }

    @Test
    @DisplayName("Test constructor initializes with config and info type/class")
    void testConstructor() {
        byte infoType = Smb2Constants.SMB2_0_INFO_FILE;
        byte infoClass = FileInformation.FILE_INTERNAL_INFO;
        
        response = new Smb2QueryInfoResponse(mockConfig, infoType, infoClass);
        
        assertNotNull(response);
        assertNull(response.getInfo()); // Should be null before decoding
    }

    @Test
    @DisplayName("Test getInfo returns decoded information")
    void testGetInfo() throws Exception {
        response = new Smb2QueryInfoResponse(mockConfig, (byte)1, (byte)2);
        
        // Use reflection to set the info field
        var infoField = Smb2QueryInfoResponse.class.getDeclaredField("info");
        infoField.setAccessible(true);
        infoField.set(response, mockDecodable);
        
        assertEquals(mockDecodable, response.getInfo());
    }

    @Test
    @DisplayName("Test getInfo with class type - matching class")
    void testGetInfoWithClassMatching() throws Exception {
        response = new Smb2QueryInfoResponse(mockConfig, (byte)1, (byte)2);
        
        FileInternalInfo fileInfo = new FileInternalInfo();
        
        // Use reflection to set the info field
        var infoField = Smb2QueryInfoResponse.class.getDeclaredField("info");
        infoField.setAccessible(true);
        infoField.set(response, fileInfo);
        
        FileInternalInfo result = response.getInfo(FileInternalInfo.class);
        assertEquals(fileInfo, result);
    }

    @Test
    @DisplayName("Test getInfo with class type - incompatible class throws exception")
    void testGetInfoWithClassIncompatible() throws Exception {
        response = new Smb2QueryInfoResponse(mockConfig, (byte)1, (byte)2);
        
        FileInternalInfo fileInfo = new FileInternalInfo();
        
        // Use reflection to set the info field
        var infoField = Smb2QueryInfoResponse.class.getDeclaredField("info");
        infoField.setAccessible(true);
        infoField.set(response, fileInfo);
        
        CIFSException exception = assertThrows(
            CIFSException.class,
            () -> response.getInfo(FileFsSizeInformation.class),
            "Should throw CIFSException for incompatible class"
        );
        
        assertEquals("Incompatible file information class", exception.getMessage());
    }

    @Test
    @DisplayName("Test writeBytesWireFormat returns 0")
    void testWriteBytesWireFormat() {
        response = new Smb2QueryInfoResponse(mockConfig, (byte)1, (byte)2);
        byte[] dst = new byte[1024];
        int dstIndex = 0;
        
        int result = response.writeBytesWireFormat(dst, dstIndex);
        
        assertEquals(0, result);
    }

    @Test
    @DisplayName("Test readBytesWireFormat with valid structure size")
    void testReadBytesWireFormatValidStructureSize() throws Exception {
        response = new Smb2QueryInfoResponse(mockConfig, 
            Smb2Constants.SMB2_0_INFO_FILE, 
            FileInformation.FILE_INTERNAL_INFO);
        
        byte[] buffer = new byte[1024];
        int bufferIndex = 100; // Start at non-zero index
        
        // Set structure size to 9 (valid)
        SMBUtil.writeInt2(9, buffer, bufferIndex);
        // Set buffer offset (relative to header start)
        SMBUtil.writeInt2(50, buffer, bufferIndex + 2);
        // Set buffer length
        SMBUtil.writeInt4(8, buffer, bufferIndex + 4);
        
        // Mock getHeaderStart
        response = spy(response);
        when(response.getHeaderStart()).thenReturn(0);
        
        // Write FileInternalInfo data at the buffer offset
        // FileInternalInfo expects 8 bytes (IndexNumber as int8)
        SMBUtil.writeInt8(0x123456789ABCDEFL, buffer, 50);
        
        int result = response.readBytesWireFormat(buffer, bufferIndex);
        
        assertTrue(result >= 8);
        assertNotNull(response.getInfo());
        assertTrue(response.getInfo() instanceof FileInternalInfo);
    }

    @Test
    @DisplayName("Test readBytesWireFormat with invalid structure size throws exception")
    void testReadBytesWireFormatInvalidStructureSize() {
        response = new Smb2QueryInfoResponse(mockConfig, (byte)1, (byte)2);
        byte[] buffer = new byte[1024];
        int bufferIndex = 0;
        
        // Set structure size to 10 (invalid, should be 9)
        SMBUtil.writeInt2(10, buffer, bufferIndex);
        
        SMBProtocolDecodingException exception = assertThrows(
            SMBProtocolDecodingException.class,
            () -> response.readBytesWireFormat(buffer, bufferIndex),
            "Should throw SMBProtocolDecodingException for invalid structure size"
        );
        
        assertEquals("Expected structureSize = 9", exception.getMessage());
    }

    @ParameterizedTest
    @ValueSource(ints = {0, 1, 2, 3, 4, 5, 6, 7, 8, 10, 11, 100, 255, 256, 65535})
    @DisplayName("Test readBytesWireFormat with various invalid structure sizes")
    void testReadBytesWireFormatVariousInvalidSizes(int invalidSize) {
        response = new Smb2QueryInfoResponse(mockConfig, (byte)1, (byte)2);
        byte[] buffer = new byte[1024];
        int bufferIndex = 0;
        
        SMBUtil.writeInt2(invalidSize, buffer, bufferIndex);
        
        SMBProtocolDecodingException exception = assertThrows(
            SMBProtocolDecodingException.class,
            () -> response.readBytesWireFormat(buffer, bufferIndex),
            "Should throw SMBProtocolDecodingException for structure size " + invalidSize
        );
        
        assertEquals("Expected structureSize = 9", exception.getMessage());
    }

    @Test
    @DisplayName("Test readBytesWireFormat with FILE info type")
    void testReadBytesWireFormatFileInfoType() throws Exception {
        response = new Smb2QueryInfoResponse(mockConfig, 
            Smb2Constants.SMB2_0_INFO_FILE, 
            FileInformation.FILE_INTERNAL_INFO);
        
        byte[] buffer = new byte[1024];
        int bufferIndex = 0;
        
        // Set structure size to 9
        SMBUtil.writeInt2(9, buffer, bufferIndex);
        // Set buffer offset
        SMBUtil.writeInt2(20, buffer, bufferIndex + 2);
        // Set buffer length
        SMBUtil.writeInt4(8, buffer, bufferIndex + 4);
        
        response = spy(response);
        when(response.getHeaderStart()).thenReturn(0);
        
        // Write FileInternalInfo data
        SMBUtil.writeInt8(0xABCDEF1234567890L, buffer, 20);
        
        int result = response.readBytesWireFormat(buffer, bufferIndex);
        
        assertNotNull(response.getInfo());
        assertTrue(response.getInfo() instanceof FileInternalInfo);
    }

    @Test
    @DisplayName("Test readBytesWireFormat with FILESYSTEM info type - FS_SIZE_INFO")
    void testReadBytesWireFormatFilesystemSizeInfo() throws Exception {
        response = new Smb2QueryInfoResponse(mockConfig, 
            Smb2Constants.SMB2_0_INFO_FILESYSTEM, 
            FileSystemInformation.FS_SIZE_INFO);
        
        byte[] buffer = new byte[1024];
        int bufferIndex = 0;
        
        // Set structure size to 9
        SMBUtil.writeInt2(9, buffer, bufferIndex);
        // Set buffer offset
        SMBUtil.writeInt2(20, buffer, bufferIndex + 2);
        // Set buffer length (FileFsSizeInformation is 24 bytes)
        SMBUtil.writeInt4(24, buffer, bufferIndex + 4);
        
        response = spy(response);
        when(response.getHeaderStart()).thenReturn(0);
        
        // Write FileFsSizeInformation data (24 bytes)
        SMBUtil.writeInt8(1000000, buffer, 20); // Total allocation units
        SMBUtil.writeInt8(500000, buffer, 28);  // Available allocation units
        SMBUtil.writeInt4(512, buffer, 36);     // Sectors per unit
        SMBUtil.writeInt4(4096, buffer, 40);    // Bytes per sector
        
        int result = response.readBytesWireFormat(buffer, bufferIndex);
        
        assertNotNull(response.getInfo());
        assertTrue(response.getInfo() instanceof FileFsSizeInformation);
    }

    @Test
    @DisplayName("Test readBytesWireFormat with FILESYSTEM info type - FS_FULL_SIZE_INFO")
    void testReadBytesWireFormatFilesystemFullSizeInfo() throws Exception {
        response = new Smb2QueryInfoResponse(mockConfig, 
            Smb2Constants.SMB2_0_INFO_FILESYSTEM, 
            FileSystemInformation.FS_FULL_SIZE_INFO);
        
        byte[] buffer = new byte[1024];
        int bufferIndex = 0;
        
        // Set structure size to 9
        SMBUtil.writeInt2(9, buffer, bufferIndex);
        // Set buffer offset
        SMBUtil.writeInt2(20, buffer, bufferIndex + 2);
        // Set buffer length (FileFsFullSizeInformation is 32 bytes)
        SMBUtil.writeInt4(32, buffer, bufferIndex + 4);
        
        response = spy(response);
        when(response.getHeaderStart()).thenReturn(0);
        
        // Write FileFsFullSizeInformation data (32 bytes)
        SMBUtil.writeInt8(1000000, buffer, 20);  // Total allocation units
        SMBUtil.writeInt8(500000, buffer, 28);   // Caller available units
        SMBUtil.writeInt8(600000, buffer, 36);   // Actual available units
        SMBUtil.writeInt4(512, buffer, 44);      // Sectors per unit
        SMBUtil.writeInt4(4096, buffer, 48);     // Bytes per sector
        
        int result = response.readBytesWireFormat(buffer, bufferIndex);
        
        assertNotNull(response.getInfo());
        assertTrue(response.getInfo() instanceof FileFsFullSizeInformation);
    }

    @Test
    @DisplayName("Test readBytesWireFormat with SECURITY info type")
    void testReadBytesWireFormatSecurityInfo() throws Exception {
        response = new Smb2QueryInfoResponse(mockConfig, 
            Smb2Constants.SMB2_0_INFO_SECURITY, 
            (byte)0);
        
        byte[] buffer = new byte[1024];
        int bufferIndex = 0;
        
        // Set structure size to 9
        SMBUtil.writeInt2(9, buffer, bufferIndex);
        // Set buffer offset
        SMBUtil.writeInt2(20, buffer, bufferIndex + 2);
        // Set buffer length (minimal SecurityDescriptor)
        SMBUtil.writeInt4(20, buffer, bufferIndex + 4);
        
        response = spy(response);
        when(response.getHeaderStart()).thenReturn(0);
        
        // Write minimal SecurityDescriptor header (20 bytes)
        buffer[20] = 1; // Revision
        buffer[21] = 0; // Sbz1
        SMBUtil.writeInt2(0x8004, buffer, 22); // Control flags
        SMBUtil.writeInt4(0, buffer, 24); // Owner offset
        SMBUtil.writeInt4(0, buffer, 28); // Group offset
        SMBUtil.writeInt4(0, buffer, 32); // SACL offset
        SMBUtil.writeInt4(0, buffer, 36); // DACL offset
        
        int result = response.readBytesWireFormat(buffer, bufferIndex);
        
        assertNotNull(response.getInfo());
        assertTrue(response.getInfo() instanceof SecurityDescriptor);
    }

    @Test
    @DisplayName("Test readBytesWireFormat with QUOTA info type throws exception")
    void testReadBytesWireFormatQuotaInfo() {
        response = new Smb2QueryInfoResponse(mockConfig, 
            Smb2Constants.SMB2_0_INFO_QUOTA, 
            (byte)0);
        
        byte[] buffer = new byte[1024];
        int bufferIndex = 0;
        
        // Set structure size to 9
        SMBUtil.writeInt2(9, buffer, bufferIndex);
        // Set buffer offset
        SMBUtil.writeInt2(20, buffer, bufferIndex + 2);
        // Set buffer length
        SMBUtil.writeInt4(10, buffer, bufferIndex + 4);
        
        response = spy(response);
        when(response.getHeaderStart()).thenReturn(0);
        
        SMBProtocolDecodingException exception = assertThrows(
            SMBProtocolDecodingException.class,
            () -> response.readBytesWireFormat(buffer, bufferIndex),
            "Should throw exception for unknown quota info class"
        );
        
        assertTrue(exception.getMessage().contains("Unknown quota info class"));
    }

    @Test
    @DisplayName("Test readBytesWireFormat with unknown info type throws exception")
    void testReadBytesWireFormatUnknownInfoType() {
        response = new Smb2QueryInfoResponse(mockConfig, 
            (byte)99, // Unknown info type
            (byte)0);
        
        byte[] buffer = new byte[1024];
        int bufferIndex = 0;
        
        // Set structure size to 9
        SMBUtil.writeInt2(9, buffer, bufferIndex);
        // Set buffer offset
        SMBUtil.writeInt2(20, buffer, bufferIndex + 2);
        // Set buffer length
        SMBUtil.writeInt4(10, buffer, bufferIndex + 4);
        
        response = spy(response);
        when(response.getHeaderStart()).thenReturn(0);
        
        SMBProtocolDecodingException exception = assertThrows(
            SMBProtocolDecodingException.class,
            () -> response.readBytesWireFormat(buffer, bufferIndex),
            "Should throw exception for unknown info type"
        );
        
        assertEquals("Unknwon information type 99", exception.getMessage());
    }

    @Test
    @DisplayName("Test readBytesWireFormat with unknown file info class throws exception")
    void testReadBytesWireFormatUnknownFileInfoClass() {
        response = new Smb2QueryInfoResponse(mockConfig, 
            Smb2Constants.SMB2_0_INFO_FILE, 
            (byte)99); // Unknown file info class
        
        byte[] buffer = new byte[1024];
        int bufferIndex = 0;
        
        // Set structure size to 9
        SMBUtil.writeInt2(9, buffer, bufferIndex);
        // Set buffer offset
        SMBUtil.writeInt2(20, buffer, bufferIndex + 2);
        // Set buffer length
        SMBUtil.writeInt4(10, buffer, bufferIndex + 4);
        
        response = spy(response);
        when(response.getHeaderStart()).thenReturn(0);
        
        SMBProtocolDecodingException exception = assertThrows(
            SMBProtocolDecodingException.class,
            () -> response.readBytesWireFormat(buffer, bufferIndex),
            "Should throw exception for unknown file info class"
        );
        
        assertEquals("Unknown file info class 99", exception.getMessage());
    }

    @Test
    @DisplayName("Test readBytesWireFormat with unknown filesystem info class throws exception")
    void testReadBytesWireFormatUnknownFilesystemInfoClass() {
        response = new Smb2QueryInfoResponse(mockConfig, 
            Smb2Constants.SMB2_0_INFO_FILESYSTEM, 
            (byte)99); // Unknown filesystem info class
        
        byte[] buffer = new byte[1024];
        int bufferIndex = 0;
        
        // Set structure size to 9
        SMBUtil.writeInt2(9, buffer, bufferIndex);
        // Set buffer offset
        SMBUtil.writeInt2(20, buffer, bufferIndex + 2);
        // Set buffer length
        SMBUtil.writeInt4(10, buffer, bufferIndex + 4);
        
        response = spy(response);
        when(response.getHeaderStart()).thenReturn(0);
        
        SMBProtocolDecodingException exception = assertThrows(
            SMBProtocolDecodingException.class,
            () -> response.readBytesWireFormat(buffer, bufferIndex),
            "Should throw exception for unknown filesystem info class"
        );
        
        assertEquals("Unknown filesystem info class 99", exception.getMessage());
    }

    @Test
    @DisplayName("Test readBytesWireFormat handles large buffer offset correctly")
    void testReadBytesWireFormatLargeBufferOffset() throws Exception {
        response = new Smb2QueryInfoResponse(mockConfig, 
            Smb2Constants.SMB2_0_INFO_FILE, 
            FileInformation.FILE_INTERNAL_INFO);
        
        byte[] buffer = new byte[2048];
        int bufferIndex = 100;
        
        // Set structure size to 9
        SMBUtil.writeInt2(9, buffer, bufferIndex);
        // Set large buffer offset
        SMBUtil.writeInt2(1000, buffer, bufferIndex + 2);
        // Set buffer length
        SMBUtil.writeInt4(8, buffer, bufferIndex + 4);
        
        response = spy(response);
        when(response.getHeaderStart()).thenReturn(0);
        
        // Write FileInternalInfo data at the large offset
        SMBUtil.writeInt8(0x123456789ABCDEFL, buffer, 1000);
        
        int result = response.readBytesWireFormat(buffer, bufferIndex);
        
        // Should return at least to the end of the data
        assertTrue(result >= 900); // 1000 + 8 - 100
        assertNotNull(response.getInfo());
    }

    @Test
    @DisplayName("Test readBytesWireFormat with zero buffer length")
    void testReadBytesWireFormatZeroBufferLength() throws Exception {
        response = new Smb2QueryInfoResponse(mockConfig, 
            Smb2Constants.SMB2_0_INFO_FILE, 
            FileInformation.FILE_INTERNAL_INFO);
        
        byte[] buffer = new byte[1024];
        int bufferIndex = 0;
        
        // Set structure size to 9
        SMBUtil.writeInt2(9, buffer, bufferIndex);
        // Set buffer offset
        SMBUtil.writeInt2(20, buffer, bufferIndex + 2);
        // Set buffer length to 0
        SMBUtil.writeInt4(0, buffer, bufferIndex + 4);
        
        response = spy(response);
        when(response.getHeaderStart()).thenReturn(0);
        
        int result = response.readBytesWireFormat(buffer, bufferIndex);
        
        assertTrue(result >= 8);
        assertNotNull(response.getInfo());
    }

    @Test
    @DisplayName("Test inheritance from ServerMessageBlock2Response")
    void testInheritance() {
        response = new Smb2QueryInfoResponse(mockConfig, (byte)1, (byte)2);
        assertTrue(response instanceof ServerMessageBlock2Response);
        assertTrue(response instanceof ServerMessageBlock2);
    }

    @Test
    @DisplayName("Test OVERHEAD constant value")
    void testOverheadConstant() {
        assertEquals(72, Smb2QueryInfoResponse.OVERHEAD);
        assertEquals(Smb2Constants.SMB2_HEADER_LENGTH + 8, Smb2QueryInfoResponse.OVERHEAD);
    }

    @ParameterizedTest
    @CsvSource({
        "1, 6",  // SMB2_0_INFO_FILE, FILE_INTERNAL_INFO
        "2, 3",  // SMB2_0_INFO_FILESYSTEM, FS_SIZE_INFO
        "2, 7",  // SMB2_0_INFO_FILESYSTEM, FS_FULL_SIZE_INFO
        "3, 0"   // SMB2_0_INFO_SECURITY, any class
    })
    @DisplayName("Test createInformation with various valid info type and class combinations")
    void testCreateInformationValidCombinations(byte infoType, byte infoClass) throws Exception {
        // Use reflection to test private method
        Method createInfoMethod = Smb2QueryInfoResponse.class.getDeclaredMethod(
            "createInformation", byte.class, byte.class);
        createInfoMethod.setAccessible(true);
        
        Decodable result = (Decodable) createInfoMethod.invoke(null, infoType, infoClass);
        
        assertNotNull(result, 
            String.format("Should create information for type %d, class %d", infoType, infoClass));
    }

    @Test
    @DisplayName("Test readBytesWireFormat preserves buffer content")
    void testReadBytesWireFormatPreservesBuffer() throws Exception {
        response = new Smb2QueryInfoResponse(mockConfig, 
            Smb2Constants.SMB2_0_INFO_FILE, 
            FileInformation.FILE_INTERNAL_INFO);
        
        byte[] buffer = new byte[1024];
        int bufferIndex = 0;
        
        // Fill buffer with test data
        for (int i = 0; i < buffer.length; i++) {
            buffer[i] = (byte)(i % 256);
        }
        
        // Set structure size to 9
        SMBUtil.writeInt2(9, buffer, bufferIndex);
        // Set buffer offset
        SMBUtil.writeInt2(100, buffer, bufferIndex + 2);
        // Set buffer length
        SMBUtil.writeInt4(8, buffer, bufferIndex + 4);
        
        response = spy(response);
        when(response.getHeaderStart()).thenReturn(0);
        
        // Make a copy of the buffer
        byte[] bufferCopy = buffer.clone();
        
        // Call readBytesWireFormat
        response.readBytesWireFormat(buffer, bufferIndex);
        
        // Verify buffer wasn't modified except for the decode operations
        assertArrayEquals(bufferCopy, buffer, "Buffer content should not be modified");
    }

    @Test
    @DisplayName("Test readBytesWireFormat with offset calculation")
    void testReadBytesWireFormatOffsetCalculation() throws Exception {
        response = new Smb2QueryInfoResponse(mockConfig, 
            Smb2Constants.SMB2_0_INFO_FILE, 
            FileInformation.FILE_INTERNAL_INFO);
        
        byte[] buffer = new byte[1024];
        int bufferIndex = 200;
        int headerStart = 50;
        
        // Set structure size to 9
        SMBUtil.writeInt2(9, buffer, bufferIndex);
        // Set buffer offset (relative to header start)
        SMBUtil.writeInt2(300, buffer, bufferIndex + 2);
        // Set buffer length
        SMBUtil.writeInt4(8, buffer, bufferIndex + 4);
        
        response = spy(response);
        when(response.getHeaderStart()).thenReturn(headerStart);
        
        // Write FileInternalInfo data at calculated offset (headerStart + bufferOffset)
        SMBUtil.writeInt8(0xFEDCBA9876543210L, buffer, headerStart + 300);
        
        int result = response.readBytesWireFormat(buffer, bufferIndex);
        
        // Should return at least to the end of the data
        assertTrue(result >= 158); // (50 + 300 + 8) - 200
        assertNotNull(response.getInfo());
        assertTrue(response.getInfo() instanceof FileInternalInfo);
    }

    @Test
    @DisplayName("Test multiple calls to getInfo return same instance")
    void testMultipleGetInfoCalls() throws Exception {
        response = new Smb2QueryInfoResponse(mockConfig, (byte)1, (byte)2);
        
        // Use reflection to set the info field
        var infoField = Smb2QueryInfoResponse.class.getDeclaredField("info");
        infoField.setAccessible(true);
        infoField.set(response, mockDecodable);
        
        Decodable first = response.getInfo();
        Decodable second = response.getInfo();
        
        assertSame(first, second, "Multiple calls should return the same instance");
    }

    @Test
    @DisplayName("Test getInfo with null info returns null")
    void testGetInfoWithNullInfo() {
        response = new Smb2QueryInfoResponse(mockConfig, (byte)1, (byte)2);
        
        assertNull(response.getInfo());
    }

    @Test
    @DisplayName("Test getInfo with class when info is null throws NullPointerException")
    void testGetInfoWithClassWhenInfoIsNull() {
        response = new Smb2QueryInfoResponse(mockConfig, (byte)1, (byte)2);
        
        assertThrows(
            NullPointerException.class,
            () -> response.getInfo(FileInternalInfo.class),
            "Should throw NullPointerException when info is null"
        );
    }

    @Test
    @DisplayName("Test writeBytesWireFormat with null buffer")
    void testWriteBytesWireFormatWithNullBuffer() {
        response = new Smb2QueryInfoResponse(mockConfig, (byte)1, (byte)2);
        
        assertDoesNotThrow(() -> {
            int result = response.writeBytesWireFormat(null, 0);
            assertEquals(0, result);
        });
    }

    @Test
    @DisplayName("Test readBytesWireFormat correctly updates info field")
    void testReadBytesWireFormatUpdatesInfoField() throws Exception {
        response = new Smb2QueryInfoResponse(mockConfig, 
            Smb2Constants.SMB2_0_INFO_FILE, 
            FileInformation.FILE_INTERNAL_INFO);
        
        byte[] buffer = new byte[1024];
        int bufferIndex = 0;
        
        // Verify info is initially null
        assertNull(response.getInfo());
        
        // Set structure size to 9
        SMBUtil.writeInt2(9, buffer, bufferIndex);
        // Set buffer offset
        SMBUtil.writeInt2(20, buffer, bufferIndex + 2);
        // Set buffer length
        SMBUtil.writeInt4(8, buffer, bufferIndex + 4);
        
        response = spy(response);
        when(response.getHeaderStart()).thenReturn(0);
        
        // Write FileInternalInfo data
        SMBUtil.writeInt8(0x1234567890ABCDEFL, buffer, 20);
        
        response.readBytesWireFormat(buffer, bufferIndex);
        
        // Verify info is now set
        assertNotNull(response.getInfo());
        assertTrue(response.getInfo() instanceof FileInternalInfo);
    }
}
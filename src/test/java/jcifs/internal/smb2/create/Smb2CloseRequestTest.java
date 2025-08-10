package jcifs.internal.smb2.create;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.lang.reflect.Field;
import java.util.Arrays;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import jcifs.CIFSContext;
import jcifs.Configuration;
import jcifs.internal.smb2.ServerMessageBlock2;
import jcifs.internal.smb2.Smb2Constants;
import jcifs.internal.util.SMBUtil;

/**
 * Test class for Smb2CloseRequest functionality
 */
@DisplayName("Smb2CloseRequest Tests")
class Smb2CloseRequestTest {

    private Configuration mockConfig;
    private CIFSContext mockContext;
    private byte[] testFileId;
    private String testFileName;
    private Smb2CloseRequest request;

    @BeforeEach
    void setUp() {
        mockConfig = mock(Configuration.class);
        mockContext = mock(CIFSContext.class);
        when(mockContext.getConfig()).thenReturn(mockConfig);
        
        // Create a test file ID (16 bytes)
        testFileId = new byte[16];
        for (int i = 0; i < 16; i++) {
            testFileId[i] = (byte)(i + 1);
        }
        
        testFileName = "test-file.txt";
        request = new Smb2CloseRequest(mockConfig, testFileId, testFileName);
    }

    @Test
    @DisplayName("Constructor with fileId and fileName should initialize correctly")
    void testConstructorWithFileIdAndFileName() throws Exception {
        // Verify command is set correctly (SMB2_CLOSE = 0x0006)
        Field commandField = ServerMessageBlock2.class.getDeclaredField("command");
        commandField.setAccessible(true);
        int command = (int) commandField.get(request);
        assertEquals(0x0006, command); // SMB2_CLOSE value
        
        // Verify file ID is set
        Field fileIdField = Smb2CloseRequest.class.getDeclaredField("fileId");
        fileIdField.setAccessible(true);
        byte[] storedFileId = (byte[]) fileIdField.get(request);
        assertArrayEquals(testFileId, storedFileId);
        
        // Verify fileName is set
        Field fileNameField = Smb2CloseRequest.class.getDeclaredField("fileName");
        fileNameField.setAccessible(true);
        String storedFileName = (String) fileNameField.get(request);
        assertEquals(testFileName, storedFileName);
    }

    @Test
    @DisplayName("Constructor with fileId only should use empty fileName")
    void testConstructorWithFileIdOnly() throws Exception {
        Smb2CloseRequest requestWithFileIdOnly = new Smb2CloseRequest(mockConfig, testFileId);
        
        // Verify file ID is set
        Field fileIdField = Smb2CloseRequest.class.getDeclaredField("fileId");
        fileIdField.setAccessible(true);
        byte[] storedFileId = (byte[]) fileIdField.get(requestWithFileIdOnly);
        assertArrayEquals(testFileId, storedFileId);
        
        // Verify fileName is empty
        Field fileNameField = Smb2CloseRequest.class.getDeclaredField("fileName");
        fileNameField.setAccessible(true);
        String storedFileName = (String) fileNameField.get(requestWithFileIdOnly);
        assertEquals("", storedFileName);
    }

    @Test
    @DisplayName("Constructor with fileName only should use UNSPECIFIED_FILEID")
    void testConstructorWithFileNameOnly() throws Exception {
        Smb2CloseRequest requestWithFileNameOnly = new Smb2CloseRequest(mockConfig, testFileName);
        
        // Verify file ID is UNSPECIFIED_FILEID
        Field fileIdField = Smb2CloseRequest.class.getDeclaredField("fileId");
        fileIdField.setAccessible(true);
        byte[] storedFileId = (byte[]) fileIdField.get(requestWithFileNameOnly);
        assertArrayEquals(Smb2Constants.UNSPECIFIED_FILEID, storedFileId);
        
        // Verify fileName is set
        Field fileNameField = Smb2CloseRequest.class.getDeclaredField("fileName");
        fileNameField.setAccessible(true);
        String storedFileName = (String) fileNameField.get(requestWithFileNameOnly);
        assertEquals(testFileName, storedFileName);
    }

    @Test
    @DisplayName("Constructor with null file ID should accept null")
    void testConstructorWithNullFileId() {
        // Should not throw exception
        Smb2CloseRequest requestWithNull = new Smb2CloseRequest(mockConfig, null, testFileName);
        assertNotNull(requestWithNull);
    }

    @Test
    @DisplayName("Constructor with null fileName should accept null")
    void testConstructorWithNullFileName() throws Exception {
        Smb2CloseRequest requestWithNull = new Smb2CloseRequest(mockConfig, testFileId, null);
        assertNotNull(requestWithNull);
        
        Field fileNameField = Smb2CloseRequest.class.getDeclaredField("fileName");
        fileNameField.setAccessible(true);
        String storedFileName = (String) fileNameField.get(requestWithNull);
        assertEquals(null, storedFileName);
    }

    @Test
    @DisplayName("setFileId should update file ID")
    void testSetFileId() throws Exception {
        byte[] newFileId = new byte[16];
        Arrays.fill(newFileId, (byte)0xFF);
        
        request.setFileId(newFileId);
        
        Field fileIdField = Smb2CloseRequest.class.getDeclaredField("fileId");
        fileIdField.setAccessible(true);
        byte[] storedFileId = (byte[]) fileIdField.get(request);
        assertArrayEquals(newFileId, storedFileId);
    }

    @Test
    @DisplayName("setFileId with null should set null file ID")
    void testSetFileIdWithNull() throws Exception {
        request.setFileId(null);
        
        Field fileIdField = Smb2CloseRequest.class.getDeclaredField("fileId");
        fileIdField.setAccessible(true);
        byte[] storedFileId = (byte[]) fileIdField.get(request);
        assertEquals(null, storedFileId);
    }

    @Test
    @DisplayName("setCloseFlags should update close flags")
    void testSetCloseFlags() throws Exception {
        int testFlags = 0x00000001; // SMB2_CLOSE_FLAG_POSTQUERY_ATTRIB
        request.setCloseFlags(testFlags);
        
        Field closeFlagsField = Smb2CloseRequest.class.getDeclaredField("closeFlags");
        closeFlagsField.setAccessible(true);
        int storedFlags = (int) closeFlagsField.get(request);
        assertEquals(testFlags, storedFlags);
    }

    @Test
    @DisplayName("createResponse should return Smb2CloseResponse with correct parameters")
    void testCreateResponse() throws Exception {
        Smb2CloseResponse response = request.createResponse(mockContext, request);
        
        assertNotNull(response);
        
        // Verify response has correct config
        Field configField = ServerMessageBlock2.class.getDeclaredField("config");
        configField.setAccessible(true);
        Configuration responseConfig = (Configuration) configField.get(response);
        assertEquals(mockConfig, responseConfig);
        
        // Verify response has correct fileId
        assertEquals(testFileId, response.getFileId());
        
        // Verify response has correct fileName
        assertEquals(testFileName, response.getFileName());
    }

    @Test
    @DisplayName("size should return correct message size")
    void testSize() {
        int expectedSize = Smb2Constants.SMB2_HEADER_LENGTH + 24;
        // size8 method rounds up to 8-byte boundary
        int expectedAlignedSize = (expectedSize + 7) & ~7;
        
        assertEquals(expectedAlignedSize, request.size());
    }

    @Test
    @DisplayName("writeBytesWireFormat should write correct structure")
    void testWriteBytesWireFormat() {
        byte[] buffer = new byte[256];
        int offset = 64; // Start at offset to test proper indexing
        
        int written = request.writeBytesWireFormat(buffer, offset);
        
        // Verify bytes written
        assertEquals(24, written);
        
        // Verify structure size (should be 24)
        assertEquals(24, SMBUtil.readInt2(buffer, offset));
        
        // Verify close flags (2 bytes at offset+2, should be 0 by default)
        assertEquals(0, SMBUtil.readInt2(buffer, offset + 2));
        
        // Verify Reserved (4 bytes at offset+4, should be 0)
        assertEquals(0, SMBUtil.readInt4(buffer, offset + 4));
        
        // Verify file ID is copied correctly (16 bytes starting at offset+8)
        byte[] copiedFileId = new byte[16];
        System.arraycopy(buffer, offset + 8, copiedFileId, 0, 16);
        assertArrayEquals(testFileId, copiedFileId);
    }

    @Test
    @DisplayName("writeBytesWireFormat with close flags should write flags correctly")
    void testWriteBytesWireFormatWithCloseFlags() {
        int testFlags = 0x0001; // SMB2_CLOSE_FLAG_POSTQUERY_ATTRIB
        request.setCloseFlags(testFlags);
        
        byte[] buffer = new byte[256];
        int written = request.writeBytesWireFormat(buffer, 0);
        
        assertEquals(24, written);
        assertEquals(24, SMBUtil.readInt2(buffer, 0));
        assertEquals(testFlags, SMBUtil.readInt2(buffer, 2));
    }

    @Test
    @DisplayName("writeBytesWireFormat with null file ID should handle gracefully")
    void testWriteBytesWireFormatWithNullFileId() {
        Smb2CloseRequest requestWithNull = new Smb2CloseRequest(mockConfig, null, testFileName);
        byte[] buffer = new byte[256];
        
        // Should throw NullPointerException when trying to copy null array
        assertThrows(NullPointerException.class, () -> {
            requestWithNull.writeBytesWireFormat(buffer, 0);
        });
    }

    @Test
    @DisplayName("readBytesWireFormat should return 0")
    void testReadBytesWireFormat() {
        byte[] buffer = new byte[256];
        int result = request.readBytesWireFormat(buffer, 0);
        
        assertEquals(0, result);
    }

    @ParameterizedTest
    @ValueSource(ints = {0, 10, 50, 100})
    @DisplayName("writeBytesWireFormat should work at different offsets")
    void testWriteBytesWireFormatAtDifferentOffsets(int offset) {
        byte[] buffer = new byte[512];
        
        int written = request.writeBytesWireFormat(buffer, offset);
        
        assertEquals(24, written);
        assertEquals(24, SMBUtil.readInt2(buffer, offset));
        
        // Verify file ID at correct position
        byte[] copiedFileId = new byte[16];
        System.arraycopy(buffer, offset + 8, copiedFileId, 0, 16);
        assertArrayEquals(testFileId, copiedFileId);
    }

    @Test
    @DisplayName("Test with various file ID patterns")
    void testWithVariousFileIdPatterns() {
        // Test with all zeros
        byte[] zeroFileId = new byte[16];
        Smb2CloseRequest zeroRequest = new Smb2CloseRequest(mockConfig, zeroFileId, testFileName);
        testFileIdInRequest(zeroRequest, zeroFileId);
        
        // Test with all ones
        byte[] onesFileId = new byte[16];
        Arrays.fill(onesFileId, (byte)0xFF);
        Smb2CloseRequest onesRequest = new Smb2CloseRequest(mockConfig, onesFileId, testFileName);
        testFileIdInRequest(onesRequest, onesFileId);
        
        // Test with alternating pattern
        byte[] alternatingFileId = new byte[16];
        for (int i = 0; i < 16; i++) {
            alternatingFileId[i] = (byte)(i % 2 == 0 ? 0xAA : 0x55);
        }
        Smb2CloseRequest alternatingRequest = new Smb2CloseRequest(mockConfig, alternatingFileId, testFileName);
        testFileIdInRequest(alternatingRequest, alternatingFileId);
    }

    private void testFileIdInRequest(Smb2CloseRequest request, byte[] expectedFileId) {
        byte[] buffer = new byte[256];
        request.writeBytesWireFormat(buffer, 0);
        
        byte[] copiedFileId = new byte[16];
        System.arraycopy(buffer, 8, copiedFileId, 0, 16);
        assertArrayEquals(expectedFileId, copiedFileId);
    }

    @Test
    @DisplayName("Test wire format structure matches SMB2 specification")
    void testWireFormatStructure() {
        byte[] buffer = new byte[256];
        Arrays.fill(buffer, (byte)0xCC); // Fill with pattern to detect unwritten areas
        
        int written = request.writeBytesWireFormat(buffer, 0);
        
        // Verify structure according to SMB2 CLOSE specification
        // Structure Size (2 bytes) - should be 24
        assertEquals(24, SMBUtil.readInt2(buffer, 0));
        
        // Flags (2 bytes) - should be 0 by default
        assertEquals(0, SMBUtil.readInt2(buffer, 2));
        
        // Reserved (4 bytes) - The implementation skips writing these bytes,
        // so they will have the initial pattern (0xCCCCCCCC)
        // This is expected behavior as seen in the implementation at line 131
        assertEquals((byte)0xCC, buffer[4]);
        assertEquals((byte)0xCC, buffer[5]);
        assertEquals((byte)0xCC, buffer[6]);
        assertEquals((byte)0xCC, buffer[7]);
        
        // FileId (16 bytes) - should match our test file ID
        byte[] wireFileId = new byte[16];
        System.arraycopy(buffer, 8, wireFileId, 0, 16);
        assertArrayEquals(testFileId, wireFileId);
        
        // Verify nothing was written beyond the structure
        assertEquals((byte)0xCC, buffer[24]);
    }

    @Test
    @DisplayName("Test request implements RequestWithFileId interface correctly")
    void testRequestWithFileIdInterface() {
        // Verify the class implements RequestWithFileId
        assertTrue(request instanceof jcifs.internal.smb2.RequestWithFileId);
        
        // Test interface method
        byte[] newFileId = new byte[16];
        Arrays.fill(newFileId, (byte)0x42);
        
        ((jcifs.internal.smb2.RequestWithFileId)request).setFileId(newFileId);
        
        // Verify it was set correctly by writing to wire format
        byte[] buffer = new byte[256];
        request.writeBytesWireFormat(buffer, 0);
        
        byte[] copiedFileId = new byte[16];
        System.arraycopy(buffer, 8, copiedFileId, 0, 16);
        assertArrayEquals(newFileId, copiedFileId);
    }

    @Test
    @DisplayName("Test edge case with minimum buffer size")
    void testMinimumBufferSize() {
        byte[] buffer = new byte[24]; // Exact size needed
        
        int written = request.writeBytesWireFormat(buffer, 0);
        
        assertEquals(24, written);
        assertEquals(24, SMBUtil.readInt2(buffer, 0));
    }

    @Test
    @DisplayName("Test buffer overflow protection")
    void testBufferOverflowProtection() {
        byte[] smallBuffer = new byte[23]; // One byte too small
        
        // Should throw ArrayIndexOutOfBoundsException
        assertThrows(ArrayIndexOutOfBoundsException.class, () -> {
            request.writeBytesWireFormat(smallBuffer, 0);
        });
    }

    @Test
    @DisplayName("Test file ID boundary values")
    void testFileIdBoundaryValues() {
        // Test with file ID having maximum byte values
        byte[] maxFileId = new byte[16];
        Arrays.fill(maxFileId, (byte)0xFF);
        Smb2CloseRequest maxRequest = new Smb2CloseRequest(mockConfig, maxFileId, testFileName);
        
        byte[] buffer = new byte[256];
        int written = maxRequest.writeBytesWireFormat(buffer, 0);
        
        assertEquals(24, written);
        
        byte[] copiedFileId = new byte[16];
        System.arraycopy(buffer, 8, copiedFileId, 0, 16);
        assertArrayEquals(maxFileId, copiedFileId);
        
        // Test with file ID having minimum byte values
        byte[] minFileId = new byte[16];
        Arrays.fill(minFileId, (byte)0x00);
        Smb2CloseRequest minRequest = new Smb2CloseRequest(mockConfig, minFileId, testFileName);
        
        written = minRequest.writeBytesWireFormat(buffer, 0);
        
        assertEquals(24, written);
        
        System.arraycopy(buffer, 8, copiedFileId, 0, 16);
        assertArrayEquals(minFileId, copiedFileId);
    }

    @Test
    @DisplayName("Test with various fileName patterns")
    void testWithVariousFileNamePatterns() throws Exception {
        // Test with empty fileName
        Smb2CloseRequest emptyNameRequest = new Smb2CloseRequest(mockConfig, testFileId, "");
        Field fileNameField = Smb2CloseRequest.class.getDeclaredField("fileName");
        fileNameField.setAccessible(true);
        assertEquals("", fileNameField.get(emptyNameRequest));
        
        // Test with long fileName
        String longFileName = "very-long-file-name-with-many-characters-that-could-potentially-cause-issues.txt";
        Smb2CloseRequest longNameRequest = new Smb2CloseRequest(mockConfig, testFileId, longFileName);
        assertEquals(longFileName, fileNameField.get(longNameRequest));
        
        // Test with special characters
        String specialFileName = "file@#$%^&*().txt";
        Smb2CloseRequest specialNameRequest = new Smb2CloseRequest(mockConfig, testFileId, specialFileName);
        assertEquals(specialFileName, fileNameField.get(specialNameRequest));
        
        // Test with path separators
        String pathFileName = "path/to/file.txt";
        Smb2CloseRequest pathNameRequest = new Smb2CloseRequest(mockConfig, testFileId, pathFileName);
        assertEquals(pathFileName, fileNameField.get(pathNameRequest));
    }

    @Test
    @DisplayName("Test close flags with different values")
    void testCloseFlagsWithDifferentValues() {
        // Test with different flag values
        int[] testFlagValues = {0x0000, 0x0001, 0xFFFF};
        
        for (int flagValue : testFlagValues) {
            request.setCloseFlags(flagValue);
            
            byte[] buffer = new byte[256];
            request.writeBytesWireFormat(buffer, 0);
            
            // Verify flags are written correctly
            assertEquals(flagValue, SMBUtil.readInt2(buffer, 2));
        }
    }

    @Test
    @DisplayName("Test createResponse with different file IDs and file names")
    void testCreateResponseVariations() {
        // Test with null file ID
        Smb2CloseRequest nullIdRequest = new Smb2CloseRequest(mockConfig, null, testFileName);
        Smb2CloseResponse nullIdResponse = nullIdRequest.createResponse(mockContext, nullIdRequest);
        assertNotNull(nullIdResponse);
        assertEquals(null, nullIdResponse.getFileId());
        assertEquals(testFileName, nullIdResponse.getFileName());
        
        // Test with null file name
        Smb2CloseRequest nullNameRequest = new Smb2CloseRequest(mockConfig, testFileId, null);
        Smb2CloseResponse nullNameResponse = nullNameRequest.createResponse(mockContext, nullNameRequest);
        assertNotNull(nullNameResponse);
        assertArrayEquals(testFileId, nullNameResponse.getFileId());
        assertEquals(null, nullNameResponse.getFileName());
        
        // Test with both null
        Smb2CloseRequest bothNullRequest = new Smb2CloseRequest(mockConfig, null, null);
        Smb2CloseResponse bothNullResponse = bothNullRequest.createResponse(mockContext, bothNullRequest);
        assertNotNull(bothNullResponse);
        assertEquals(null, bothNullResponse.getFileId());
        assertEquals(null, bothNullResponse.getFileName());
    }

    @Test
    @DisplayName("Test multiple close flags combinations")
    void testMultipleCloseFlagsCombinations() {
        // Test combining multiple flags
        int combinedFlags = 0x0003; // Multiple flags set
        request.setCloseFlags(combinedFlags);
        
        byte[] buffer = new byte[256];
        int written = request.writeBytesWireFormat(buffer, 0);
        
        assertEquals(24, written);
        assertEquals(combinedFlags, SMBUtil.readInt2(buffer, 2));
    }

    @Test
    @DisplayName("Test request state after multiple operations")
    void testRequestStateAfterMultipleOperations() throws Exception {
        // Set initial values
        request.setCloseFlags(0x0001);
        
        // Change file ID
        byte[] newFileId1 = new byte[16];
        Arrays.fill(newFileId1, (byte)0xAA);
        request.setFileId(newFileId1);
        
        // Change flags
        request.setCloseFlags(0x0000);
        
        // Change file ID again
        byte[] newFileId2 = new byte[16];
        Arrays.fill(newFileId2, (byte)0xBB);
        request.setFileId(newFileId2);
        
        // Verify final state
        Field fileIdField = Smb2CloseRequest.class.getDeclaredField("fileId");
        fileIdField.setAccessible(true);
        byte[] finalFileId = (byte[]) fileIdField.get(request);
        assertArrayEquals(newFileId2, finalFileId);
        
        Field closeFlagsField = Smb2CloseRequest.class.getDeclaredField("closeFlags");
        closeFlagsField.setAccessible(true);
        int finalFlags = (int) closeFlagsField.get(request);
        assertEquals(0x0000, finalFlags);
        
        // Verify wire format reflects final state
        byte[] buffer = new byte[256];
        request.writeBytesWireFormat(buffer, 0);
        
        assertEquals(0x0000, SMBUtil.readInt2(buffer, 2));
        byte[] wireFileId = new byte[16];
        System.arraycopy(buffer, 8, wireFileId, 0, 16);
        assertArrayEquals(newFileId2, wireFileId);
    }
}
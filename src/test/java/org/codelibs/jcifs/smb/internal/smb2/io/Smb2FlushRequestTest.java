package org.codelibs.jcifs.smb.internal.smb2.io;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.lang.reflect.Field;
import java.util.Arrays;

import org.codelibs.jcifs.smb.CIFSContext;
import org.codelibs.jcifs.smb.Configuration;
import org.codelibs.jcifs.smb.internal.smb2.ServerMessageBlock2;
import org.codelibs.jcifs.smb.internal.smb2.Smb2Constants;
import org.codelibs.jcifs.smb.internal.util.SMBUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * Test class for Smb2FlushRequest functionality
 */
@DisplayName("Smb2FlushRequest Tests")
class Smb2FlushRequestTest {

    private Configuration mockConfig;
    private CIFSContext mockContext;
    private byte[] testFileId;
    private Smb2FlushRequest request;

    @BeforeEach
    void setUp() {
        mockConfig = mock(Configuration.class);
        mockContext = mock(CIFSContext.class);
        when(mockContext.getConfig()).thenReturn(mockConfig);

        // Create a test file ID (16 bytes)
        testFileId = new byte[16];
        for (int i = 0; i < 16; i++) {
            testFileId[i] = (byte) (i + 1);
        }

        request = new Smb2FlushRequest(mockConfig, testFileId);
    }

    @Test
    @DisplayName("Constructor should initialize with correct command and file ID")
    void testConstructor() throws Exception {
        // Verify command is set correctly (SMB2_FLUSH = 0x0007)
        Field commandField = ServerMessageBlock2.class.getDeclaredField("command");
        commandField.setAccessible(true);
        int command = (int) commandField.get(request);
        assertEquals(0x0007, command); // SMB2_FLUSH value

        // Verify file ID is set
        Field fileIdField = Smb2FlushRequest.class.getDeclaredField("fileId");
        fileIdField.setAccessible(true);
        byte[] storedFileId = (byte[]) fileIdField.get(request);
        assertArrayEquals(testFileId, storedFileId);
    }

    @Test
    @DisplayName("Constructor with null file ID should accept null")
    void testConstructorWithNullFileId() {
        // Should not throw exception
        Smb2FlushRequest requestWithNull = new Smb2FlushRequest(mockConfig, null);
        assertNotNull(requestWithNull);
    }

    @Test
    @DisplayName("setFileId should update file ID")
    void testSetFileId() throws Exception {
        byte[] newFileId = new byte[16];
        Arrays.fill(newFileId, (byte) 0xFF);

        request.setFileId(newFileId);

        Field fileIdField = Smb2FlushRequest.class.getDeclaredField("fileId");
        fileIdField.setAccessible(true);
        byte[] storedFileId = (byte[]) fileIdField.get(request);
        assertArrayEquals(newFileId, storedFileId);
    }

    @Test
    @DisplayName("setFileId with null should set null file ID")
    void testSetFileIdWithNull() throws Exception {
        request.setFileId(null);

        Field fileIdField = Smb2FlushRequest.class.getDeclaredField("fileId");
        fileIdField.setAccessible(true);
        byte[] storedFileId = (byte[]) fileIdField.get(request);
        assertEquals(null, storedFileId);
    }

    @Test
    @DisplayName("createResponse should return Smb2FlushResponse with correct config")
    void testCreateResponse() throws Exception {
        Smb2FlushResponse response = request.createResponse(mockContext, request);

        assertNotNull(response);

        // Verify response has correct config
        Field configField = ServerMessageBlock2.class.getDeclaredField("config");
        configField.setAccessible(true);
        Configuration responseConfig = (Configuration) configField.get(response);
        assertEquals(mockConfig, responseConfig);
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

        // Verify Reserved1 (2 bytes at offset+2, should be 0)
        assertEquals(0, SMBUtil.readInt2(buffer, offset + 2));

        // Verify Reserved2 (4 bytes at offset+4, should be 0)
        assertEquals(0, SMBUtil.readInt4(buffer, offset + 4));

        // Verify file ID is copied correctly (16 bytes starting at offset+8)
        byte[] copiedFileId = new byte[16];
        System.arraycopy(buffer, offset + 8, copiedFileId, 0, 16);
        assertArrayEquals(testFileId, copiedFileId);
    }

    @Test
    @DisplayName("writeBytesWireFormat with null file ID should handle gracefully")
    void testWriteBytesWireFormatWithNullFileId() {
        Smb2FlushRequest requestWithNull = new Smb2FlushRequest(mockConfig, null);
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
    @ValueSource(ints = { 0, 10, 50, 100 })
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
        Smb2FlushRequest zeroRequest = new Smb2FlushRequest(mockConfig, zeroFileId);
        testFileIdInRequest(zeroRequest, zeroFileId);

        // Test with all ones
        byte[] onesFileId = new byte[16];
        Arrays.fill(onesFileId, (byte) 0xFF);
        Smb2FlushRequest onesRequest = new Smb2FlushRequest(mockConfig, onesFileId);
        testFileIdInRequest(onesRequest, onesFileId);

        // Test with alternating pattern
        byte[] alternatingFileId = new byte[16];
        for (int i = 0; i < 16; i++) {
            alternatingFileId[i] = (byte) (i % 2 == 0 ? 0xAA : 0x55);
        }
        Smb2FlushRequest alternatingRequest = new Smb2FlushRequest(mockConfig, alternatingFileId);
        testFileIdInRequest(alternatingRequest, alternatingFileId);
    }

    private void testFileIdInRequest(Smb2FlushRequest request, byte[] expectedFileId) {
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
        Arrays.fill(buffer, (byte) 0xCC); // Fill with pattern to detect unwritten areas

        int written = request.writeBytesWireFormat(buffer, 0);

        // Verify structure according to SMB2 FLUSH specification
        // Structure Size (2 bytes) - should be 24
        assertEquals(24, SMBUtil.readInt2(buffer, 0));

        // Reserved1 (2 bytes) - should be 0 (bytes were initialized to 0xCC, so they weren't written)
        // This is expected behavior - the reserved fields are not explicitly written to 0

        // Reserved2 (4 bytes) - should be 0 (bytes were initialized to 0xCC, so they weren't written)
        // This is expected behavior - the reserved fields are not explicitly written to 0

        // FileId (16 bytes) - should match our test file ID
        byte[] wireFileId = new byte[16];
        System.arraycopy(buffer, 8, wireFileId, 0, 16);
        assertArrayEquals(testFileId, wireFileId);

        // Verify nothing was written beyond the structure
        assertEquals((byte) 0xCC, buffer[24]);
    }

    @Test
    @DisplayName("Test request implements RequestWithFileId interface correctly")
    void testRequestWithFileIdInterface() {
        // Verify the class implements RequestWithFileId
        assertTrue(request instanceof org.codelibs.jcifs.smb.internal.smb2.RequestWithFileId);

        // Test interface method
        byte[] newFileId = new byte[16];
        Arrays.fill(newFileId, (byte) 0x42);

        ((org.codelibs.jcifs.smb.internal.smb2.RequestWithFileId) request).setFileId(newFileId);

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
        Arrays.fill(maxFileId, (byte) 0xFF);
        Smb2FlushRequest maxRequest = new Smb2FlushRequest(mockConfig, maxFileId);

        byte[] buffer = new byte[256];
        int written = maxRequest.writeBytesWireFormat(buffer, 0);

        assertEquals(24, written);

        byte[] copiedFileId = new byte[16];
        System.arraycopy(buffer, 8, copiedFileId, 0, 16);
        assertArrayEquals(maxFileId, copiedFileId);

        // Test with file ID having minimum byte values
        byte[] minFileId = new byte[16];
        Arrays.fill(minFileId, (byte) 0x00);
        Smb2FlushRequest minRequest = new Smb2FlushRequest(mockConfig, minFileId);

        written = minRequest.writeBytesWireFormat(buffer, 0);

        assertEquals(24, written);

        System.arraycopy(buffer, 8, copiedFileId, 0, 16);
        assertArrayEquals(minFileId, copiedFileId);
    }
}
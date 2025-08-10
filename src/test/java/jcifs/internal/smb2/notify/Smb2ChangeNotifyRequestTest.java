package jcifs.internal.smb2.notify;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.lenient;

import java.lang.reflect.Field;
import java.util.Arrays;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.junit.jupiter.MockitoExtension;

import jcifs.CIFSContext;
import jcifs.Configuration;
import jcifs.internal.smb2.ServerMessageBlock2;
import jcifs.internal.smb2.ServerMessageBlock2Request;
import jcifs.internal.smb2.Smb2Constants;
import jcifs.internal.util.SMBUtil;

/**
 * Test class for Smb2ChangeNotifyRequest functionality
 */
@DisplayName("Smb2ChangeNotifyRequest Tests")
@ExtendWith(MockitoExtension.class)
class Smb2ChangeNotifyRequestTest {

    private Configuration mockConfig;
    private CIFSContext mockContext;
    private byte[] testFileId;
    private Smb2ChangeNotifyRequest request;

    @BeforeEach
    void setUp() {
        mockConfig = mock(Configuration.class);
        mockContext = mock(CIFSContext.class);
        testFileId = new byte[16];
        Arrays.fill(testFileId, (byte) 0xAB);
        
        // Use lenient stubbing for default configuration values
        lenient().when(mockConfig.getNotifyBufferSize()).thenReturn(8192);
        lenient().when(mockContext.getConfig()).thenReturn(mockConfig);
        
        request = new Smb2ChangeNotifyRequest(mockConfig, testFileId);
    }

    @Test
    @DisplayName("Should create request with configuration and file ID")
    void testConstructor() {
        // Given
        Configuration config = mock(Configuration.class);
        when(config.getNotifyBufferSize()).thenReturn(8192);
        
        // When
        Smb2ChangeNotifyRequest req = new Smb2ChangeNotifyRequest(config, testFileId);

        // Then
        assertNotNull(req);
        assertTrue(req instanceof ServerMessageBlock2Request);
        assertTrue(req instanceof ServerMessageBlock2);
    }

    @Test
    @DisplayName("Should set notify flags correctly")
    void testSetNotifyFlags() throws Exception {
        // Given
        int flags = Smb2ChangeNotifyRequest.SMB2_WATCH_TREE;

        // When
        request.setNotifyFlags(flags);

        // Then
        Field notifyFlagsField = Smb2ChangeNotifyRequest.class.getDeclaredField("notifyFlags");
        notifyFlagsField.setAccessible(true);
        assertEquals(flags, notifyFlagsField.getInt(request));
    }

    @Test
    @DisplayName("Should set completion filter correctly")
    void testSetCompletionFilter() throws Exception {
        // Given
        int filter = Smb2ChangeNotifyRequest.FILE_NOTIFY_CHANGE_FILE_NAME | 
                    Smb2ChangeNotifyRequest.FILE_NOTIFY_CHANGE_DIR_NAME |
                    Smb2ChangeNotifyRequest.FILE_NOTIFY_CHANGE_ATTRIBUTES;

        // When
        request.setCompletionFilter(filter);

        // Then
        Field completionFilterField = Smb2ChangeNotifyRequest.class.getDeclaredField("completionFilter");
        completionFilterField.setAccessible(true);
        assertEquals(filter, completionFilterField.getInt(request));
    }

    @Test
    @DisplayName("Should create correct response")
    void testCreateResponse() {
        // When
        Smb2ChangeNotifyResponse response = request.createResponse(mockContext, request);

        // Then
        assertNotNull(response);
        assertTrue(response instanceof Smb2ChangeNotifyResponse);
    }

    @Test
    @DisplayName("Should calculate correct size")
    void testSize() {
        // When
        int size = request.size();

        // Then
        // Size should be aligned to 8 bytes: SMB2_HEADER_LENGTH + 32
        int expectedSize = Smb2Constants.SMB2_HEADER_LENGTH + 32;
        // The size8 method aligns to 8-byte boundary
        int alignedSize = (expectedSize + 7) & ~7;
        assertEquals(alignedSize, size);
    }

    @Test
    @DisplayName("Should write correct bytes to wire format")
    void testWriteBytesWireFormat() {
        // Given
        byte[] buffer = new byte[512];
        int offset = 100;
        request.setNotifyFlags(Smb2ChangeNotifyRequest.SMB2_WATCH_TREE);
        request.setCompletionFilter(Smb2ChangeNotifyRequest.FILE_NOTIFY_CHANGE_FILE_NAME);

        // When
        int bytesWritten = request.writeBytesWireFormat(buffer, offset);

        // Then
        assertEquals(32, bytesWritten);
        
        // Verify structure size (32)
        assertEquals(32, SMBUtil.readInt2(buffer, offset));
        
        // Verify notify flags
        assertEquals(Smb2ChangeNotifyRequest.SMB2_WATCH_TREE, SMBUtil.readInt2(buffer, offset + 2));
        
        // Verify output buffer length
        assertEquals(8192, SMBUtil.readInt4(buffer, offset + 4));
        
        // Verify file ID
        byte[] readFileId = new byte[16];
        System.arraycopy(buffer, offset + 8, readFileId, 0, 16);
        assertArrayEquals(testFileId, readFileId);
        
        // Verify completion filter
        assertEquals(Smb2ChangeNotifyRequest.FILE_NOTIFY_CHANGE_FILE_NAME, 
                    SMBUtil.readInt4(buffer, offset + 24));
        
        // Verify reserved field is zero
        assertEquals(0, SMBUtil.readInt4(buffer, offset + 28));
    }

    @Test
    @DisplayName("Should read empty bytes from wire format")
    void testReadBytesWireFormat() {
        // Given
        byte[] buffer = new byte[256];
        int offset = 10;

        // When
        int bytesRead = request.readBytesWireFormat(buffer, offset);

        // Then
        assertEquals(0, bytesRead);
    }

    @DisplayName("Should handle different completion filter combinations")
    @ParameterizedTest
    @CsvSource({
        "1, FILE_NOTIFY_CHANGE_FILE_NAME",
        "2, FILE_NOTIFY_CHANGE_DIR_NAME",
        "4, FILE_NOTIFY_CHANGE_ATTRIBUTES",
        "8, FILE_NOTIFY_CHANGE_SIZE",
        "16, FILE_NOTIFY_CHANGE_LAST_WRITE",
        "32, FILE_NOTIFY_CHANGE_LAST_ACCESS",
        "64, FILE_NOTIFY_CHANGE_CREATION",
        "128, FILE_NOTIFY_CHANGE_EA",
        "256, FILE_NOTIFY_CHANGE_SECURITY",
        "512, FILE_NOTIFY_CHANGE_STREAM_NAME",
        "1024, FILE_NOTIFY_CHANGE_STREAM_SIZE",
        "2048, FILE_NOTIFY_CHANGE_STREAM_WRITE"
    })
    void testCompletionFilterConstants(int value, String description) {
        // Given & When
        request.setCompletionFilter(value);
        byte[] buffer = new byte[512];
        request.writeBytesWireFormat(buffer, 0);

        // Then
        int readFilter = SMBUtil.readInt4(buffer, 24);
        assertEquals(value, readFilter);
    }

    @Test
    @DisplayName("Should handle combined completion filters")
    void testCombinedCompletionFilters() {
        // Given
        int combinedFilter = 
            Smb2ChangeNotifyRequest.FILE_NOTIFY_CHANGE_FILE_NAME |
            Smb2ChangeNotifyRequest.FILE_NOTIFY_CHANGE_DIR_NAME |
            Smb2ChangeNotifyRequest.FILE_NOTIFY_CHANGE_ATTRIBUTES |
            Smb2ChangeNotifyRequest.FILE_NOTIFY_CHANGE_SIZE |
            Smb2ChangeNotifyRequest.FILE_NOTIFY_CHANGE_LAST_WRITE;

        // When
        request.setCompletionFilter(combinedFilter);
        byte[] buffer = new byte[512];
        request.writeBytesWireFormat(buffer, 0);

        // Then
        int readFilter = SMBUtil.readInt4(buffer, 24);
        assertEquals(combinedFilter, readFilter);
        assertEquals(0x1F, readFilter); // 1 + 2 + 4 + 8 + 16 = 31 = 0x1F
    }

    @Test
    @DisplayName("Should handle all file change notifications")
    void testAllFileChangeNotifications() {
        // Given - all possible filters
        int allFilters = 
            Smb2ChangeNotifyRequest.FILE_NOTIFY_CHANGE_FILE_NAME |
            Smb2ChangeNotifyRequest.FILE_NOTIFY_CHANGE_DIR_NAME |
            Smb2ChangeNotifyRequest.FILE_NOTIFY_CHANGE_ATTRIBUTES |
            Smb2ChangeNotifyRequest.FILE_NOTIFY_CHANGE_SIZE |
            Smb2ChangeNotifyRequest.FILE_NOTIFY_CHANGE_LAST_WRITE |
            Smb2ChangeNotifyRequest.FILE_NOTIFY_CHANGE_LAST_ACCESS |
            Smb2ChangeNotifyRequest.FILE_NOTIFY_CHANGE_CREATION |
            Smb2ChangeNotifyRequest.FILE_NOTIFY_CHANGE_EA |
            Smb2ChangeNotifyRequest.FILE_NOTIFY_CHANGE_SECURITY |
            Smb2ChangeNotifyRequest.FILE_NOTIFY_CHANGE_STREAM_NAME |
            Smb2ChangeNotifyRequest.FILE_NOTIFY_CHANGE_STREAM_SIZE |
            Smb2ChangeNotifyRequest.FILE_NOTIFY_CHANGE_STREAM_WRITE;

        // When
        request.setCompletionFilter(allFilters);
        byte[] buffer = new byte[512];
        request.writeBytesWireFormat(buffer, 0);

        // Then
        int readFilter = SMBUtil.readInt4(buffer, 24);
        assertEquals(allFilters, readFilter);
        assertEquals(0xFFF, readFilter); // All 12 bits set
    }

    @Test
    @DisplayName("Should handle different buffer sizes from configuration")
    void testDifferentBufferSizes() {
        // Given
        Configuration config = mock(Configuration.class);
        when(config.getNotifyBufferSize()).thenReturn(16384);
        Smb2ChangeNotifyRequest req = new Smb2ChangeNotifyRequest(config, testFileId);

        // When
        byte[] buffer = new byte[512];
        req.writeBytesWireFormat(buffer, 0);

        // Then
        int readBufferSize = SMBUtil.readInt4(buffer, 4);
        assertEquals(16384, readBufferSize);
    }

    @Test
    @DisplayName("Should handle zero notify flags")
    void testZeroNotifyFlags() {
        // Given
        request.setNotifyFlags(0);

        // When
        byte[] buffer = new byte[512];
        request.writeBytesWireFormat(buffer, 0);

        // Then
        int readFlags = SMBUtil.readInt2(buffer, 2);
        assertEquals(0, readFlags);
    }

    @Test
    @DisplayName("Should handle zero completion filter")
    void testZeroCompletionFilter() {
        // Given
        request.setCompletionFilter(0);

        // When
        byte[] buffer = new byte[512];
        request.writeBytesWireFormat(buffer, 0);

        // Then
        int readFilter = SMBUtil.readInt4(buffer, 24);
        assertEquals(0, readFilter);
    }

    @Test
    @DisplayName("Should handle different file IDs")
    void testDifferentFileIds() {
        // Given
        byte[] fileId1 = new byte[16];
        Arrays.fill(fileId1, (byte) 0x11);
        
        byte[] fileId2 = new byte[16];
        Arrays.fill(fileId2, (byte) 0xFF);
        
        byte[] fileId3 = new byte[16];
        for (int i = 0; i < 16; i++) {
            fileId3[i] = (byte) i;
        }

        // When & Then for each file ID
        testFileIdWriting(fileId1);
        testFileIdWriting(fileId2);
        testFileIdWriting(fileId3);
    }

    private void testFileIdWriting(byte[] fileId) {
        Configuration config = mock(Configuration.class);
        when(config.getNotifyBufferSize()).thenReturn(8192);
        Smb2ChangeNotifyRequest req = new Smb2ChangeNotifyRequest(config, fileId);
        byte[] buffer = new byte[512];
        req.writeBytesWireFormat(buffer, 0);
        
        byte[] readFileId = new byte[16];
        System.arraycopy(buffer, 8, readFileId, 0, 16);
        assertArrayEquals(fileId, readFileId);
    }

    @Test
    @DisplayName("Should maintain correct wire format structure")
    void testWireFormatStructure() {
        // Given
        request.setNotifyFlags(0x0001);
        request.setCompletionFilter(0x00000FFF);

        // When
        byte[] buffer = new byte[512];
        int written = request.writeBytesWireFormat(buffer, 0);

        // Then
        assertEquals(32, written);
        
        // Verify complete structure
        assertEquals(32, SMBUtil.readInt2(buffer, 0));      // StructureSize
        assertEquals(0x0001, SMBUtil.readInt2(buffer, 2));  // Flags
        assertEquals(8192, SMBUtil.readInt4(buffer, 4));    // OutputBufferLength
        // FileId at offset 8-23
        assertEquals(0x00000FFF, SMBUtil.readInt4(buffer, 24)); // CompletionFilter
        assertEquals(0, SMBUtil.readInt4(buffer, 28));      // Reserved
    }

    @Test
    @DisplayName("Should handle notify flags with watch tree")
    void testNotifyFlagsWatchTree() {
        // Given
        request.setNotifyFlags(Smb2ChangeNotifyRequest.SMB2_WATCH_TREE);

        // When
        byte[] buffer = new byte[512];
        request.writeBytesWireFormat(buffer, 0);

        // Then
        int readFlags = SMBUtil.readInt2(buffer, 2);
        assertEquals(Smb2ChangeNotifyRequest.SMB2_WATCH_TREE, readFlags);
        assertEquals(0x0001, readFlags);
    }

    @Test
    @DisplayName("Should verify command constant in constructor")
    void testCommandConstant() throws Exception {
        // When
        Field commandField = ServerMessageBlock2.class.getDeclaredField("command");
        commandField.setAccessible(true);
        int command = commandField.getInt(request);

        // Then
        assertEquals(0x000F, command); // SMB2_CHANGE_NOTIFY
    }

    @Test
    @DisplayName("Should handle maximum buffer size")
    void testMaximumBufferSize() {
        // Given
        Configuration config = mock(Configuration.class);
        when(config.getNotifyBufferSize()).thenReturn(Integer.MAX_VALUE);
        Smb2ChangeNotifyRequest req = new Smb2ChangeNotifyRequest(config, testFileId);

        // When
        byte[] buffer = new byte[512];
        req.writeBytesWireFormat(buffer, 0);

        // Then
        int readBufferSize = SMBUtil.readInt4(buffer, 4);
        assertEquals(Integer.MAX_VALUE, readBufferSize);
    }

    @Test
    @DisplayName("Should handle minimum buffer size")
    void testMinimumBufferSize() {
        // Given
        Configuration config = mock(Configuration.class);
        when(config.getNotifyBufferSize()).thenReturn(0);
        Smb2ChangeNotifyRequest req = new Smb2ChangeNotifyRequest(config, testFileId);

        // When
        byte[] buffer = new byte[512];
        req.writeBytesWireFormat(buffer, 0);

        // Then
        int readBufferSize = SMBUtil.readInt4(buffer, 4);
        assertEquals(0, readBufferSize);
    }

    @Test
    @DisplayName("Should write to buffer with offset")
    void testWriteWithOffset() {
        // Given
        int offset = 200;
        byte[] buffer = new byte[512];
        request.setNotifyFlags(0x0001);
        request.setCompletionFilter(0x000000FF);

        // When
        int written = request.writeBytesWireFormat(buffer, offset);

        // Then
        assertEquals(32, written);
        assertEquals(32, SMBUtil.readInt2(buffer, offset));
        assertEquals(0x0001, SMBUtil.readInt2(buffer, offset + 2));
        assertEquals(8192, SMBUtil.readInt4(buffer, offset + 4));
        assertEquals(0x000000FF, SMBUtil.readInt4(buffer, offset + 24));
    }

    @Test
    @DisplayName("Should verify all constant values")
    void testAllConstants() {
        // Verify notify flags
        assertEquals(0x1, Smb2ChangeNotifyRequest.SMB2_WATCH_TREE);
        
        // Verify completion filter constants
        assertEquals(0x1, Smb2ChangeNotifyRequest.FILE_NOTIFY_CHANGE_FILE_NAME);
        assertEquals(0x2, Smb2ChangeNotifyRequest.FILE_NOTIFY_CHANGE_DIR_NAME);
        assertEquals(0x4, Smb2ChangeNotifyRequest.FILE_NOTIFY_CHANGE_ATTRIBUTES);
        assertEquals(0x8, Smb2ChangeNotifyRequest.FILE_NOTIFY_CHANGE_SIZE);
        assertEquals(0x10, Smb2ChangeNotifyRequest.FILE_NOTIFY_CHANGE_LAST_WRITE);
        assertEquals(0x20, Smb2ChangeNotifyRequest.FILE_NOTIFY_CHANGE_LAST_ACCESS);
        assertEquals(0x40, Smb2ChangeNotifyRequest.FILE_NOTIFY_CHANGE_CREATION);
        assertEquals(0x80, Smb2ChangeNotifyRequest.FILE_NOTIFY_CHANGE_EA);
        assertEquals(0x100, Smb2ChangeNotifyRequest.FILE_NOTIFY_CHANGE_SECURITY);
        assertEquals(0x200, Smb2ChangeNotifyRequest.FILE_NOTIFY_CHANGE_STREAM_NAME);
        assertEquals(0x400, Smb2ChangeNotifyRequest.FILE_NOTIFY_CHANGE_STREAM_SIZE);
        assertEquals(0x800, Smb2ChangeNotifyRequest.FILE_NOTIFY_CHANGE_STREAM_WRITE);
    }

    @Test
    @DisplayName("Should handle null file ID gracefully")
    void testNullFileId() {
        // Given
        byte[] nullFileId = new byte[16]; // All zeros
        Configuration config = mock(Configuration.class);
        when(config.getNotifyBufferSize()).thenReturn(8192);

        // When
        Smb2ChangeNotifyRequest req = new Smb2ChangeNotifyRequest(config, nullFileId);
        byte[] buffer = new byte[512];
        req.writeBytesWireFormat(buffer, 0);

        // Then
        byte[] readFileId = new byte[16];
        System.arraycopy(buffer, 8, readFileId, 0, 16);
        assertArrayEquals(nullFileId, readFileId);
    }

    @Test
    @DisplayName("Should handle sequential operations")
    void testSequentialOperations() {
        // Given
        request.setNotifyFlags(0);
        request.setCompletionFilter(0);

        // When - first write
        byte[] buffer1 = new byte[512];
        request.writeBytesWireFormat(buffer1, 0);

        // Update values
        request.setNotifyFlags(Smb2ChangeNotifyRequest.SMB2_WATCH_TREE);
        request.setCompletionFilter(0xFFF);

        // Second write
        byte[] buffer2 = new byte[512];
        request.writeBytesWireFormat(buffer2, 0);

        // Then
        assertEquals(0, SMBUtil.readInt2(buffer1, 2));
        assertEquals(0, SMBUtil.readInt4(buffer1, 24));
        assertEquals(0x0001, SMBUtil.readInt2(buffer2, 2));
        assertEquals(0xFFF, SMBUtil.readInt4(buffer2, 24));
    }
}
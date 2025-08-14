package jcifs.internal.smb2.notify;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

import jcifs.BaseTest;
import jcifs.Configuration;
import jcifs.FileNotifyInformation;
import jcifs.internal.NotifyResponse;
import jcifs.internal.SMBProtocolDecodingException;
import jcifs.internal.smb2.ServerMessageBlock2;
import jcifs.internal.smb2.ServerMessageBlock2Response;
import jcifs.internal.util.SMBUtil;
import jcifs.smb.NtStatus;

/**
 * Test class for Smb2ChangeNotifyResponse functionality
 */
@DisplayName("Smb2ChangeNotifyResponse Tests")
class Smb2ChangeNotifyResponseTest extends BaseTest {

    private Configuration mockConfig;
    private Smb2ChangeNotifyResponse response;

    @BeforeEach
    void setUp() {
        mockConfig = mock(Configuration.class);
        response = new Smb2ChangeNotifyResponse(mockConfig);
    }

    @Test
    @DisplayName("Should create response with configuration")
    void testConstructorWithConfiguration() {
        // Given & When
        Smb2ChangeNotifyResponse resp = new Smb2ChangeNotifyResponse(mockConfig);

        // Then
        assertNotNull(resp);
        assertTrue(resp instanceof ServerMessageBlock2Response);
        assertTrue(resp instanceof ServerMessageBlock2);
        assertTrue(resp instanceof NotifyResponse);
        assertNotNull(resp.getNotifyInformation());
        assertEquals(0, resp.getNotifyInformation().size());
    }

    @Test
    @DisplayName("Should write empty bytes to wire format")
    void testWriteBytesWireFormat() {
        // Given
        byte[] buffer = new byte[256];
        int offset = 10;

        // When
        int bytesWritten = response.writeBytesWireFormat(buffer, offset);

        // Then
        assertEquals(0, bytesWritten);
    }

    @Test
    @DisplayName("Should read valid single notification from wire format")
    void testReadSingleNotification() throws Exception {
        // Given
        byte[] buffer = new byte[512];
        int offset = 0;

        // Set header start position for the response
        setHeaderStart(response, 64);

        // Write structure header (9 bytes)
        SMBUtil.writeInt2(9, buffer, offset); // Structure size
        SMBUtil.writeInt2(80 - 64, buffer, offset + 2); // Buffer offset (relative to header)
        SMBUtil.writeInt4(50, buffer, offset + 4); // Total length of notification data

        // Write notification data at buffer offset 80
        int notifyOffset = 80;
        SMBUtil.writeInt4(0, buffer, notifyOffset); // NextEntryOffset (0 = last entry)
        SMBUtil.writeInt4(1, buffer, notifyOffset + 4); // Action (FILE_ACTION_ADDED)
        // Write filename in Unicode
        String fileName = "test.txt";
        byte[] fileNameBytes = fileName.getBytes("UnicodeLittleUnmarked");
        SMBUtil.writeInt4(fileNameBytes.length, buffer, notifyOffset + 8); // FileNameLength
        System.arraycopy(fileNameBytes, 0, buffer, notifyOffset + 12, fileNameBytes.length);

        // When
        int bytesRead = response.readBytesWireFormat(buffer, offset);

        // Then
        assertTrue(bytesRead > 0);
        List<FileNotifyInformation> notifications = response.getNotifyInformation();
        assertEquals(1, notifications.size());

        FileNotifyInformation info = notifications.get(0);
        assertEquals(1, info.getAction());
        assertEquals("test.txt", info.getFileName());
    }

    @Test
    @DisplayName("Should read multiple notifications from wire format")
    void testReadMultipleNotifications() throws Exception {
        // Given
        byte[] buffer = new byte[1024];
        int offset = 0;

        // Set header start position
        setHeaderStart(response, 64);

        // Write structure header
        SMBUtil.writeInt2(9, buffer, offset);
        SMBUtil.writeInt2(80 - 64, buffer, offset + 2);
        SMBUtil.writeInt4(200, buffer, offset + 4); // Total length

        // First notification at offset 80
        int notifyOffset = 80;
        SMBUtil.writeInt4(40, buffer, notifyOffset); // NextEntryOffset
        SMBUtil.writeInt4(1, buffer, notifyOffset + 4); // Action (ADDED)
        SMBUtil.writeInt4(10, buffer, notifyOffset + 8); // FileNameLength
        System.arraycopy("file1".getBytes("UnicodeLittleUnmarked"), 0, buffer, notifyOffset + 12, 10);

        // Second notification at offset 120 (80 + 40)
        notifyOffset = 120;
        SMBUtil.writeInt4(44, buffer, notifyOffset); // NextEntryOffset
        SMBUtil.writeInt4(2, buffer, notifyOffset + 4); // Action (REMOVED)
        SMBUtil.writeInt4(10, buffer, notifyOffset + 8);
        System.arraycopy("file2".getBytes("UnicodeLittleUnmarked"), 0, buffer, notifyOffset + 12, 10);

        // Third notification at offset 164 (120 + 44)
        notifyOffset = 164;
        SMBUtil.writeInt4(0, buffer, notifyOffset); // NextEntryOffset (last)
        SMBUtil.writeInt4(3, buffer, notifyOffset + 4); // Action (MODIFIED)
        SMBUtil.writeInt4(10, buffer, notifyOffset + 8);
        System.arraycopy("file3".getBytes("UnicodeLittleUnmarked"), 0, buffer, notifyOffset + 12, 10);

        // When
        int bytesRead = response.readBytesWireFormat(buffer, offset);

        // Then
        assertTrue(bytesRead > 0);
        List<FileNotifyInformation> notifications = response.getNotifyInformation();
        assertEquals(3, notifications.size());

        assertEquals(1, notifications.get(0).getAction());
        assertEquals("file1", notifications.get(0).getFileName());

        assertEquals(2, notifications.get(1).getAction());
        assertEquals("file2", notifications.get(1).getFileName());

        assertEquals(3, notifications.get(2).getAction());
        assertEquals("file3", notifications.get(2).getFileName());
    }

    @DisplayName("Should throw exception for invalid structure size")
    @ParameterizedTest
    @ValueSource(ints = { 0, 1, 2, 4, 8, 10, 16, 32, 255 })
    void testInvalidStructureSize(int structureSize) {
        // Given
        byte[] buffer = new byte[256];
        SMBUtil.writeInt2(structureSize, buffer, 0);

        // When & Then
        SMBProtocolDecodingException exception =
                assertThrows(SMBProtocolDecodingException.class, () -> response.readBytesWireFormat(buffer, 0));
        assertEquals("Expected structureSize = 9", exception.getMessage());
    }

    @Test
    @DisplayName("Should handle empty notification list")
    void testEmptyNotificationList() throws Exception {
        // Given
        byte[] buffer = new byte[256];
        int offset = 0;

        setHeaderStart(response, 64);

        // Write structure with zero length
        SMBUtil.writeInt2(9, buffer, offset);
        SMBUtil.writeInt2(80 - 64, buffer, offset + 2);
        SMBUtil.writeInt4(0, buffer, offset + 4); // Zero length

        // When
        int bytesRead = response.readBytesWireFormat(buffer, offset);

        // Then
        assertTrue(bytesRead > 0);
        List<FileNotifyInformation> notifications = response.getNotifyInformation();
        assertEquals(1, notifications.size()); // One empty notification is created
    }

    @Test
    @DisplayName("Should handle notification with long filename")
    void testLongFilename() throws Exception {
        // Given
        byte[] buffer = new byte[2048];
        int offset = 0;

        setHeaderStart(response, 64);

        // Create a long filename
        StringBuilder longName = new StringBuilder();
        for (int i = 0; i < 100; i++) {
            longName.append("test");
        }
        String fileName = longName.toString();
        byte[] fileNameBytes = fileName.getBytes("UnicodeLittleUnmarked");

        // Write structure header
        SMBUtil.writeInt2(9, buffer, offset);
        SMBUtil.writeInt2(80 - 64, buffer, offset + 2);
        SMBUtil.writeInt4(12 + fileNameBytes.length, buffer, offset + 4);

        // Write notification
        int notifyOffset = 80;
        SMBUtil.writeInt4(0, buffer, notifyOffset);
        SMBUtil.writeInt4(1, buffer, notifyOffset + 4);
        SMBUtil.writeInt4(fileNameBytes.length, buffer, notifyOffset + 8);
        System.arraycopy(fileNameBytes, 0, buffer, notifyOffset + 12, fileNameBytes.length);

        // When
        int bytesRead = response.readBytesWireFormat(buffer, offset);

        // Then
        assertTrue(bytesRead > 0);
        List<FileNotifyInformation> notifications = response.getNotifyInformation();
        assertEquals(1, notifications.size());
        assertEquals(fileName, notifications.get(0).getFileName());
    }

    @Test
    @DisplayName("Should test isErrorResponseStatus with various status codes")
    void testIsErrorResponseStatus() throws Exception {
        // Test with NT_STATUS_NOTIFY_ENUM_DIR - should not be error
        setStatus(response, NtStatus.NT_STATUS_NOTIFY_ENUM_DIR);
        assertFalse(response.isErrorResponseStatus());

        // Test with success status
        setStatus(response, NtStatus.NT_STATUS_OK);
        assertFalse(response.isErrorResponseStatus());

        // Test with error status
        setStatus(response, NtStatus.NT_STATUS_ACCESS_DENIED);
        assertTrue(response.isErrorResponseStatus());

        // Test with another error status
        setStatus(response, NtStatus.NT_STATUS_INVALID_PARAMETER);
        assertTrue(response.isErrorResponseStatus());
    }

    @DisplayName("Should handle various file actions")
    @ParameterizedTest
    @CsvSource({ "1, FILE_ACTION_ADDED", "2, FILE_ACTION_REMOVED", "3, FILE_ACTION_MODIFIED", "4, FILE_ACTION_RENAMED_OLD_NAME",
            "5, FILE_ACTION_RENAMED_NEW_NAME", "6, FILE_ACTION_ADDED_STREAM", "7, FILE_ACTION_REMOVED_STREAM",
            "8, FILE_ACTION_MODIFIED_STREAM" })
    void testDifferentFileActions(int action, String description) throws Exception {
        // Given
        byte[] buffer = new byte[512];
        int offset = 0;

        setHeaderStart(response, 64);

        // Write structure
        SMBUtil.writeInt2(9, buffer, offset);
        SMBUtil.writeInt2(80 - 64, buffer, offset + 2);
        SMBUtil.writeInt4(50, buffer, offset + 4);

        // Write notification with specific action
        int notifyOffset = 80;
        SMBUtil.writeInt4(0, buffer, notifyOffset);
        SMBUtil.writeInt4(action, buffer, notifyOffset + 4);
        SMBUtil.writeInt4(8, buffer, notifyOffset + 8);
        System.arraycopy("test".getBytes("UnicodeLittleUnmarked"), 0, buffer, notifyOffset + 12, 8);

        // When
        response.readBytesWireFormat(buffer, offset);

        // Then
        List<FileNotifyInformation> notifications = response.getNotifyInformation();
        assertEquals(1, notifications.size());
        assertEquals(action, notifications.get(0).getAction());
    }

    @Test
    @DisplayName("Should handle notification chain with alignment")
    void testNotificationChainAlignment() throws Exception {
        // Given - notifications must be 4-byte aligned
        byte[] buffer = new byte[1024];
        int offset = 0;

        setHeaderStart(response, 64);

        // Write structure header
        SMBUtil.writeInt2(9, buffer, offset);
        SMBUtil.writeInt2(80 - 64, buffer, offset + 2);
        SMBUtil.writeInt4(300, buffer, offset + 4);

        // First notification with unaligned filename length
        int notifyOffset = 80;
        SMBUtil.writeInt4(28, buffer, notifyOffset); // NextEntryOffset (aligned)
        SMBUtil.writeInt4(1, buffer, notifyOffset + 4);
        SMBUtil.writeInt4(6, buffer, notifyOffset + 8); // 6 bytes filename
        System.arraycopy("abc".getBytes("UnicodeLittleUnmarked"), 0, buffer, notifyOffset + 12, 6);

        // Second notification starts at aligned offset
        notifyOffset = 108; // 80 + 28
        SMBUtil.writeInt4(0, buffer, notifyOffset);
        SMBUtil.writeInt4(2, buffer, notifyOffset + 4);
        SMBUtil.writeInt4(8, buffer, notifyOffset + 8);
        System.arraycopy("test".getBytes("UnicodeLittleUnmarked"), 0, buffer, notifyOffset + 12, 8);

        // When
        response.readBytesWireFormat(buffer, offset);

        // Then
        List<FileNotifyInformation> notifications = response.getNotifyInformation();
        assertEquals(2, notifications.size());
        assertEquals("abc", notifications.get(0).getFileName());
        assertEquals("test", notifications.get(1).getFileName());
    }

    @Test
    @DisplayName("Should handle buffer boundary conditions")
    void testBufferBoundaryConditions() throws Exception {
        // Given - notification exactly at buffer end
        byte[] buffer = new byte[104]; // Exact size needed
        int offset = 0;

        setHeaderStart(response, 64);

        // Write structure
        SMBUtil.writeInt2(9, buffer, offset);
        SMBUtil.writeInt2(80 - 64, buffer, offset + 2);
        SMBUtil.writeInt4(24, buffer, offset + 4); // Exact notification size

        // Write notification
        int notifyOffset = 80;
        SMBUtil.writeInt4(0, buffer, notifyOffset);
        SMBUtil.writeInt4(1, buffer, notifyOffset + 4);
        SMBUtil.writeInt4(8, buffer, notifyOffset + 8);
        System.arraycopy("test".getBytes("UnicodeLittleUnmarked"), 0, buffer, notifyOffset + 12, 8);

        // When
        response.readBytesWireFormat(buffer, offset);

        // Then
        List<FileNotifyInformation> notifications = response.getNotifyInformation();
        assertEquals(1, notifications.size());
    }

    @Test
    @DisplayName("Should handle notification with Unicode characters")
    void testUnicodeFilenames() throws Exception {
        // Given
        byte[] buffer = new byte[512];
        int offset = 0;

        setHeaderStart(response, 64);

        String unicodeName = "文件名.txt"; // Chinese characters
        byte[] fileNameBytes = unicodeName.getBytes("UnicodeLittleUnmarked");

        // Write structure
        SMBUtil.writeInt2(9, buffer, offset);
        SMBUtil.writeInt2(80 - 64, buffer, offset + 2);
        SMBUtil.writeInt4(12 + fileNameBytes.length, buffer, offset + 4);

        // Write notification
        int notifyOffset = 80;
        SMBUtil.writeInt4(0, buffer, notifyOffset);
        SMBUtil.writeInt4(1, buffer, notifyOffset + 4);
        SMBUtil.writeInt4(fileNameBytes.length, buffer, notifyOffset + 8);
        System.arraycopy(fileNameBytes, 0, buffer, notifyOffset + 12, fileNameBytes.length);

        // When
        response.readBytesWireFormat(buffer, offset);

        // Then
        List<FileNotifyInformation> notifications = response.getNotifyInformation();
        assertEquals(1, notifications.size());
        assertEquals(unicodeName, notifications.get(0).getFileName());
    }

    @Test
    @DisplayName("Should handle malformed next entry offset")
    void testMalformedNextEntryOffset() throws Exception {
        // Given - notification with invalid next entry offset
        byte[] buffer = new byte[512];
        int offset = 0;

        setHeaderStart(response, 64);

        // Write structure
        SMBUtil.writeInt2(9, buffer, offset);
        SMBUtil.writeInt2(80 - 64, buffer, offset + 2);
        SMBUtil.writeInt4(100, buffer, offset + 4);

        // Write notification with next offset beyond buffer
        int notifyOffset = 80;
        SMBUtil.writeInt4(500, buffer, notifyOffset); // Invalid - too large
        SMBUtil.writeInt4(1, buffer, notifyOffset + 4);
        SMBUtil.writeInt4(8, buffer, notifyOffset + 8);
        System.arraycopy("test".getBytes("UnicodeLittleUnmarked"), 0, buffer, notifyOffset + 12, 8);

        // When & Then - should handle gracefully
        assertThrows(Exception.class, () -> {
            response.readBytesWireFormat(buffer, offset);
        });
    }

    @Test
    @DisplayName("Should verify NotifyResponse interface implementation")
    void testNotifyResponseInterface() {
        // Then
        assertTrue(response instanceof NotifyResponse);
        assertNotNull(response.getNotifyInformation());
        assertTrue(response.getNotifyInformation().isEmpty());
    }

    @Test
    @DisplayName("Should handle maximum buffer size")
    void testMaximumBufferSize() throws Exception {
        // Given - large buffer with many notifications
        byte[] buffer = new byte[65536];
        int offset = 0;

        setHeaderStart(response, 64);

        // Calculate space for notifications
        int notificationSize = 32; // Each notification
        int notificationCount = 100;
        int totalSize = notificationSize * notificationCount;

        // Write structure
        SMBUtil.writeInt2(9, buffer, offset);
        SMBUtil.writeInt2(80 - 64, buffer, offset + 2);
        SMBUtil.writeInt4(totalSize, buffer, offset + 4);

        // Write many notifications
        int notifyOffset = 80;
        for (int i = 0; i < notificationCount; i++) {
            int nextOffset = (i < notificationCount - 1) ? notificationSize : 0;
            SMBUtil.writeInt4(nextOffset, buffer, notifyOffset);
            SMBUtil.writeInt4(1, buffer, notifyOffset + 4);
            SMBUtil.writeInt4(8, buffer, notifyOffset + 8);
            System.arraycopy("file".getBytes("UnicodeLittleUnmarked"), 0, buffer, notifyOffset + 12, 8);
            notifyOffset += notificationSize;
        }

        // When
        response.readBytesWireFormat(buffer, offset);

        // Then
        List<FileNotifyInformation> notifications = response.getNotifyInformation();
        assertEquals(notificationCount, notifications.size());
    }

    @Test
    @DisplayName("Should handle null configuration")
    void testNullConfiguration() {
        // When
        Smb2ChangeNotifyResponse responseWithNull = new Smb2ChangeNotifyResponse(null);

        // Then
        assertNotNull(responseWithNull);
        assertNotNull(responseWithNull.getNotifyInformation());
    }

    /**
     * Helper method to set header start using reflection
     */
    private void setHeaderStart(Smb2ChangeNotifyResponse response, int headerStart) throws Exception {
        Method method = ServerMessageBlock2.class.getDeclaredMethod("getHeaderStart");
        method.setAccessible(true);

        Field field = ServerMessageBlock2.class.getDeclaredField("headerStart");
        field.setAccessible(true);
        field.setInt(response, headerStart);
    }

    /**
     * Helper method to set status using reflection
     */
    private void setStatus(Smb2ChangeNotifyResponse response, int status) throws Exception {
        Field statusField = ServerMessageBlock2.class.getDeclaredField("status");
        statusField.setAccessible(true);
        statusField.setInt(response, status);
    }
}
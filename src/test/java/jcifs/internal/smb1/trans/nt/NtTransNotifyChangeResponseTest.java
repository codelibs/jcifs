package jcifs.internal.smb1.trans.nt;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import java.lang.reflect.Field;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import jcifs.Configuration;
import jcifs.FileNotifyInformation;
import jcifs.internal.SMBProtocolDecodingException;
import jcifs.internal.util.SMBUtil;
import jcifs.util.Strings;

/**
 * Unit tests for NtTransNotifyChangeResponse class
 */
class NtTransNotifyChangeResponseTest {

    @Mock
    private Configuration mockConfig;

    private NtTransNotifyChangeResponse response;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        response = new NtTransNotifyChangeResponse(mockConfig);
    }

    @Test
    @DisplayName("Test constructor creates instance with empty notification list")
    void testConstructor() {
        assertNotNull(response);
        assertNotNull(response.getNotifyInformation());
        assertTrue(response.getNotifyInformation().isEmpty());
    }

    @Test
    @DisplayName("Test writeSetupWireFormat returns 0")
    void testWriteSetupWireFormat() {
        byte[] buffer = new byte[100];
        int result = response.writeSetupWireFormat(buffer, 0);
        
        assertEquals(0, result);
    }

    @Test
    @DisplayName("Test writeParametersWireFormat returns 0")
    void testWriteParametersWireFormat() {
        byte[] buffer = new byte[100];
        int result = response.writeParametersWireFormat(buffer, 0);
        
        assertEquals(0, result);
    }

    @Test
    @DisplayName("Test writeDataWireFormat returns 0")
    void testWriteDataWireFormat() {
        byte[] buffer = new byte[100];
        int result = response.writeDataWireFormat(buffer, 0);
        
        assertEquals(0, result);
    }

    @Test
    @DisplayName("Test readSetupWireFormat returns 0")
    void testReadSetupWireFormat() {
        byte[] buffer = new byte[100];
        int result = response.readSetupWireFormat(buffer, 0, buffer.length);
        
        assertEquals(0, result);
    }

    @Test
    @DisplayName("Test readDataWireFormat returns 0")
    void testReadDataWireFormat() {
        byte[] buffer = new byte[100];
        int result = response.readDataWireFormat(buffer, 0, buffer.length);
        
        assertEquals(0, result);
    }

    @Test
    @DisplayName("Test readParametersWireFormat with single notification")
    void testReadParametersWireFormatSingleNotification() throws Exception {
        byte[] buffer = createSingleNotificationBuffer("test.txt", FileNotifyInformation.FILE_ACTION_ADDED);
        
        int result = response.readParametersWireFormat(buffer, 0, buffer.length);
        
        assertTrue(result > 0);
        List<FileNotifyInformation> notifications = response.getNotifyInformation();
        assertEquals(1, notifications.size());
        
        FileNotifyInformation info = notifications.get(0);
        assertEquals("test.txt", info.getFileName());
        assertEquals(FileNotifyInformation.FILE_ACTION_ADDED, info.getAction());
    }

    @Test
    @DisplayName("Test readParametersWireFormat with multiple notifications")
    void testReadParametersWireFormatMultipleNotifications() throws Exception {
        byte[] buffer = createMultipleNotificationsBuffer();
        
        int result = response.readParametersWireFormat(buffer, 0, buffer.length);
        
        assertTrue(result > 0);
        List<FileNotifyInformation> notifications = response.getNotifyInformation();
        assertEquals(3, notifications.size());
        
        // Verify first notification
        assertEquals("file1.txt", notifications.get(0).getFileName());
        assertEquals(FileNotifyInformation.FILE_ACTION_ADDED, notifications.get(0).getAction());
        
        // Verify second notification
        assertEquals("file2.txt", notifications.get(1).getFileName());
        assertEquals(FileNotifyInformation.FILE_ACTION_REMOVED, notifications.get(1).getAction());
        
        // Verify third notification
        assertEquals("file3.txt", notifications.get(2).getFileName());
        assertEquals(FileNotifyInformation.FILE_ACTION_MODIFIED, notifications.get(2).getAction());
    }

    @Test
    @DisplayName("Test readParametersWireFormat with empty buffer")
    void testReadParametersWireFormatEmptyBuffer() throws Exception {
        byte[] buffer = new byte[0];
        
        assertThrows(Exception.class, () -> {
            response.readParametersWireFormat(buffer, 0, 0);
        });
    }

    @Test
    @DisplayName("Test readParametersWireFormat with various file actions")
    @ParameterizedTest
    @ValueSource(ints = {
        FileNotifyInformation.FILE_ACTION_ADDED,
        FileNotifyInformation.FILE_ACTION_REMOVED,
        FileNotifyInformation.FILE_ACTION_MODIFIED,
        FileNotifyInformation.FILE_ACTION_RENAMED_OLD_NAME,
        FileNotifyInformation.FILE_ACTION_RENAMED_NEW_NAME,
        FileNotifyInformation.FILE_ACTION_ADDED_STREAM,
        FileNotifyInformation.FILE_ACTION_REMOVED_STREAM,
        FileNotifyInformation.FILE_ACTION_MODIFIED_STREAM
    })
    void testReadParametersWireFormatWithVariousActions(int action) throws Exception {
        byte[] buffer = createSingleNotificationBuffer("testfile.dat", action);
        
        int result = response.readParametersWireFormat(buffer, 0, buffer.length);
        
        assertTrue(result > 0);
        List<FileNotifyInformation> notifications = response.getNotifyInformation();
        assertEquals(1, notifications.size());
        assertEquals(action, notifications.get(0).getAction());
    }

    @Test
    @DisplayName("Test readParametersWireFormat with long filename")
    void testReadParametersWireFormatLongFilename() throws Exception {
        String longFileName = "very_long_file_name_with_many_characters_to_test_buffer_handling_in_the_implementation.txt";
        byte[] buffer = createSingleNotificationBuffer(longFileName, FileNotifyInformation.FILE_ACTION_MODIFIED);
        
        int result = response.readParametersWireFormat(buffer, 0, buffer.length);
        
        assertTrue(result > 0);
        List<FileNotifyInformation> notifications = response.getNotifyInformation();
        assertEquals(1, notifications.size());
        assertEquals(longFileName, notifications.get(0).getFileName());
    }

    @Test
    @DisplayName("Test readParametersWireFormat with Unicode filename")
    void testReadParametersWireFormatUnicodeFilename() throws Exception {
        String unicodeFileName = "файл_测试_テスト.txt";
        byte[] buffer = createSingleNotificationBuffer(unicodeFileName, FileNotifyInformation.FILE_ACTION_ADDED);
        
        int result = response.readParametersWireFormat(buffer, 0, buffer.length);
        
        assertTrue(result > 0);
        List<FileNotifyInformation> notifications = response.getNotifyInformation();
        assertEquals(1, notifications.size());
        assertEquals(unicodeFileName, notifications.get(0).getFileName());
    }

    @Test
    @DisplayName("Test readParametersWireFormat with non-aligned nextEntryOffset throws exception")
    void testReadParametersWireFormatNonAlignedOffset() throws Exception {
        ByteBuffer buffer = ByteBuffer.allocate(100);
        buffer.order(ByteOrder.LITTLE_ENDIAN);
        
        // Create notification with non-aligned nextEntryOffset
        buffer.putInt(3);  // Non-aligned nextEntryOffset (not divisible by 4)
        buffer.putInt(FileNotifyInformation.FILE_ACTION_ADDED);
        buffer.putInt(8);  // File name length
        buffer.put("test.txt".getBytes("UTF-16LE"));
        
        assertThrows(SMBProtocolDecodingException.class, () -> {
            response.readParametersWireFormat(buffer.array(), 0, buffer.array().length);
        });
    }

    @Test
    @DisplayName("Test readParametersWireFormat with buffer offset")
    void testReadParametersWireFormatWithBufferOffset() throws Exception {
        int offset = 20;
        byte[] notificationData = createSingleNotificationBuffer("offset_test.txt", FileNotifyInformation.FILE_ACTION_MODIFIED);
        byte[] buffer = new byte[offset + notificationData.length];
        System.arraycopy(notificationData, 0, buffer, offset, notificationData.length);
        
        int result = response.readParametersWireFormat(buffer, offset, notificationData.length);
        
        assertTrue(result > 0);
        List<FileNotifyInformation> notifications = response.getNotifyInformation();
        assertEquals(1, notifications.size());
        assertEquals("offset_test.txt", notifications.get(0).getFileName());
    }

    @Test
    @DisplayName("Test getNotifyInformation returns same list instance")
    void testGetNotifyInformationReturnsSameInstance() {
        List<FileNotifyInformation> list1 = response.getNotifyInformation();
        List<FileNotifyInformation> list2 = response.getNotifyInformation();
        
        assertNotNull(list1);
        assertNotNull(list2);
        assertSame(list1, list2);
    }

    @Test
    @DisplayName("Test toString returns expected format")
    void testToString() {
        String result = response.toString();
        
        assertNotNull(result);
        assertTrue(result.startsWith("NtTransQuerySecurityResponse["));
        assertTrue(result.endsWith("]"));
    }

    @Test
    @DisplayName("Test readParametersWireFormat with zero nextEntryOffset stops iteration")
    void testReadParametersWireFormatZeroNextEntryOffset() throws Exception {
        ByteBuffer buffer = ByteBuffer.allocate(200);
        buffer.order(ByteOrder.LITTLE_ENDIAN);
        
        // First notification with nextEntryOffset pointing to second
        int secondOffset = 48;
        buffer.putInt(secondOffset);  // nextEntryOffset to second entry
        buffer.putInt(FileNotifyInformation.FILE_ACTION_ADDED);
        String fileName1 = "first.txt";
        byte[] fileNameBytes1 = fileName1.getBytes("UTF-16LE");
        buffer.putInt(fileNameBytes1.length);
        buffer.put(fileNameBytes1);
        
        // Align to secondOffset
        buffer.position(secondOffset);
        
        // Second notification with zero nextEntryOffset (last entry)
        buffer.putInt(0);  // nextEntryOffset = 0 (last entry)
        buffer.putInt(FileNotifyInformation.FILE_ACTION_REMOVED);
        String fileName2 = "second.txt";
        byte[] fileNameBytes2 = fileName2.getBytes("UTF-16LE");
        buffer.putInt(fileNameBytes2.length);
        buffer.put(fileNameBytes2);
        
        int result = response.readParametersWireFormat(buffer.array(), 0, buffer.array().length);
        
        assertTrue(result > 0);
        List<FileNotifyInformation> notifications = response.getNotifyInformation();
        assertEquals(2, notifications.size());
        assertEquals("first.txt", notifications.get(0).getFileName());
        assertEquals("second.txt", notifications.get(1).getFileName());
    }

    @Test
    @DisplayName("Test readParametersWireFormat handles empty filename")
    void testReadParametersWireFormatEmptyFilename() throws Exception {
        byte[] buffer = createSingleNotificationBuffer("", FileNotifyInformation.FILE_ACTION_ADDED);
        
        int result = response.readParametersWireFormat(buffer, 0, buffer.length);
        
        assertTrue(result > 0);
        List<FileNotifyInformation> notifications = response.getNotifyInformation();
        assertEquals(1, notifications.size());
        assertEquals("", notifications.get(0).getFileName());
    }

    /**
     * Helper method to create a buffer with a single notification
     */
    private byte[] createSingleNotificationBuffer(String fileName, int action) throws Exception {
        ByteBuffer buffer = ByteBuffer.allocate(1024);
        buffer.order(ByteOrder.LITTLE_ENDIAN);
        
        byte[] fileNameBytes = fileName.getBytes("UTF-16LE");
        
        buffer.putInt(0);  // nextEntryOffset (0 = last entry)
        buffer.putInt(action);
        buffer.putInt(fileNameBytes.length);
        buffer.put(fileNameBytes);
        
        // Return only the used portion of the buffer
        byte[] result = new byte[buffer.position()];
        buffer.rewind();
        buffer.get(result);
        return result;
    }

    /**
     * Helper method to create a buffer with multiple notifications
     */
    private byte[] createMultipleNotificationsBuffer() throws Exception {
        ByteBuffer buffer = ByteBuffer.allocate(1024);
        buffer.order(ByteOrder.LITTLE_ENDIAN);
        
        // Calculate offsets (must be 4-byte aligned)
        String fileName1 = "file1.txt";
        String fileName2 = "file2.txt";
        String fileName3 = "file3.txt";
        
        byte[] fileNameBytes1 = fileName1.getBytes("UTF-16LE");
        byte[] fileNameBytes2 = fileName2.getBytes("UTF-16LE");
        byte[] fileNameBytes3 = fileName3.getBytes("UTF-16LE");
        
        // First entry size: 4 (nextOffset) + 4 (action) + 4 (nameLength) + nameBytes
        int entry1Size = 12 + fileNameBytes1.length;
        int entry1AlignedSize = ((entry1Size + 3) / 4) * 4;  // Align to 4 bytes
        
        int entry2Size = 12 + fileNameBytes2.length;
        int entry2AlignedSize = ((entry2Size + 3) / 4) * 4;  // Align to 4 bytes
        
        // First notification
        buffer.putInt(entry1AlignedSize);  // nextEntryOffset
        buffer.putInt(FileNotifyInformation.FILE_ACTION_ADDED);
        buffer.putInt(fileNameBytes1.length);
        buffer.put(fileNameBytes1);
        
        // Pad to aligned size
        while (buffer.position() < entry1AlignedSize) {
            buffer.put((byte) 0);
        }
        
        // Second notification
        buffer.putInt(entry2AlignedSize);  // nextEntryOffset
        buffer.putInt(FileNotifyInformation.FILE_ACTION_REMOVED);
        buffer.putInt(fileNameBytes2.length);
        buffer.put(fileNameBytes2);
        
        // Pad to aligned size
        int secondEntryEnd = entry1AlignedSize + entry2AlignedSize;
        while (buffer.position() < secondEntryEnd) {
            buffer.put((byte) 0);
        }
        
        // Third notification (last entry)
        buffer.putInt(0);  // nextEntryOffset (0 = last entry)
        buffer.putInt(FileNotifyInformation.FILE_ACTION_MODIFIED);
        buffer.putInt(fileNameBytes3.length);
        buffer.put(fileNameBytes3);
        
        // Return only the used portion of the buffer
        byte[] result = new byte[buffer.position()];
        buffer.rewind();
        buffer.get(result);
        return result;
    }
}
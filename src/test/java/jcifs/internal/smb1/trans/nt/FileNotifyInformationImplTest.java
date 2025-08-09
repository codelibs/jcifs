package jcifs.internal.smb1.trans.nt;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.junit.jupiter.params.provider.CsvSource;

import jcifs.FileNotifyInformation;
import jcifs.internal.SMBProtocolDecodingException;
import jcifs.internal.util.SMBUtil;

/**
 * Unit tests for FileNotifyInformationImpl class
 */
class FileNotifyInformationImplTest {

    private FileNotifyInformationImpl notifyInfo;
    
    @BeforeEach
    void setUp() {
        notifyInfo = new FileNotifyInformationImpl();
    }

    @Test
    @DisplayName("Test default constructor creates instance with null values")
    void testDefaultConstructor() {
        assertNotNull(notifyInfo);
        assertEquals(0, notifyInfo.getAction());
        assertNull(notifyInfo.getFileName());
        assertEquals(0, notifyInfo.getNextEntryOffset());
    }

    @Test
    @DisplayName("Test constructor with buffer decodes correctly")
    void testConstructorWithBuffer() throws IOException {
        // Create test buffer with notification data
        byte[] buffer = createValidNotificationBuffer("testfile.txt", FileNotifyInformation.FILE_ACTION_ADDED);
        
        FileNotifyInformationImpl info = new FileNotifyInformationImpl(buffer, 0, buffer.length);
        
        assertNotNull(info);
        assertEquals(FileNotifyInformation.FILE_ACTION_ADDED, info.getAction());
        assertEquals("testfile.txt", info.getFileName());
    }

    @Test
    @DisplayName("Test decode with valid single entry")
    void testDecodeValidSingleEntry() throws SMBProtocolDecodingException {
        String fileName = "document.pdf";
        int action = FileNotifyInformation.FILE_ACTION_MODIFIED;
        byte[] buffer = createValidNotificationBuffer(fileName, action);
        
        int bytesRead = notifyInfo.decode(buffer, 0, buffer.length);
        
        assertTrue(bytesRead > 0);
        assertEquals(0, notifyInfo.getNextEntryOffset()); // Single entry has 0 offset
        assertEquals(action, notifyInfo.getAction());
        assertEquals(fileName, notifyInfo.getFileName());
    }

    @Test
    @DisplayName("Test decode with multiple entries (non-zero next offset)")
    void testDecodeWithNextEntry() throws SMBProtocolDecodingException {
        String fileName = "test.txt";
        int action = FileNotifyInformation.FILE_ACTION_REMOVED;
        int nextOffset = 64; // Aligned to 4 bytes
        
        byte[] buffer = createNotificationBufferWithNextOffset(fileName, action, nextOffset);
        
        int bytesRead = notifyInfo.decode(buffer, 0, buffer.length);
        
        assertTrue(bytesRead > 0);
        assertEquals(nextOffset, notifyInfo.getNextEntryOffset());
        assertEquals(action, notifyInfo.getAction());
        assertEquals(fileName, notifyInfo.getFileName());
    }

    @Test
    @DisplayName("Test decode with empty buffer returns 0")
    void testDecodeEmptyBuffer() throws SMBProtocolDecodingException {
        byte[] buffer = new byte[0];
        
        int bytesRead = notifyInfo.decode(buffer, 0, 0);
        
        assertEquals(0, bytesRead);
        assertEquals(0, notifyInfo.getAction());
        assertNull(notifyInfo.getFileName());
    }

    @Test
    @DisplayName("Test decode with zero length returns 0")
    void testDecodeZeroLength() throws SMBProtocolDecodingException {
        byte[] buffer = new byte[100];
        
        int bytesRead = notifyInfo.decode(buffer, 0, 0);
        
        assertEquals(0, bytesRead);
    }

    @Test
    @DisplayName("Test decode with non-aligned next entry offset throws exception")
    void testDecodeNonAlignedNextOffset() {
        byte[] buffer = new byte[100];
        // Write non-aligned next entry offset (not divisible by 4)
        SMBUtil.writeInt4(7, buffer, 0); // 7 is not aligned to 4 bytes
        SMBUtil.writeInt4(FileNotifyInformation.FILE_ACTION_ADDED, buffer, 4);
        SMBUtil.writeInt4(8, buffer, 8); // file name length
        
        assertThrows(SMBProtocolDecodingException.class, () -> {
            notifyInfo.decode(buffer, 0, buffer.length);
        }, "Non aligned nextEntryOffset");
    }

    @ParameterizedTest
    @DisplayName("Test decode with various action values")
    @ValueSource(ints = {
        FileNotifyInformation.FILE_ACTION_ADDED,
        FileNotifyInformation.FILE_ACTION_REMOVED,
        FileNotifyInformation.FILE_ACTION_MODIFIED,
        FileNotifyInformation.FILE_ACTION_RENAMED_OLD_NAME,
        FileNotifyInformation.FILE_ACTION_RENAMED_NEW_NAME,
        FileNotifyInformation.FILE_ACTION_ADDED_STREAM,
        FileNotifyInformation.FILE_ACTION_REMOVED_STREAM,
        FileNotifyInformation.FILE_ACTION_MODIFIED_STREAM,
        FileNotifyInformation.FILE_ACTION_REMOVED_BY_DELETE
    })
    void testDecodeWithVariousActions(int action) throws SMBProtocolDecodingException {
        String fileName = "file.dat";
        byte[] buffer = createValidNotificationBuffer(fileName, action);
        
        int bytesRead = notifyInfo.decode(buffer, 0, buffer.length);
        
        assertTrue(bytesRead > 0);
        assertEquals(action, notifyInfo.getAction());
        assertEquals(fileName, notifyInfo.getFileName());
    }

    @ParameterizedTest
    @DisplayName("Test decode with various file names")
    @CsvSource({
        "a.txt",
        "very_long_filename_with_many_characters_to_test_buffer_handling.docx",
        "file with spaces.pdf",
        "文件.txt", // Unicode filename
        "file-with-special-chars!@#$%^&().bin"
    })
    void testDecodeWithVariousFileNames(String fileName) throws SMBProtocolDecodingException {
        byte[] buffer = createValidNotificationBuffer(fileName, FileNotifyInformation.FILE_ACTION_ADDED);
        
        int bytesRead = notifyInfo.decode(buffer, 0, buffer.length);
        
        assertTrue(bytesRead > 0);
        assertEquals(fileName, notifyInfo.getFileName());
    }

    @Test
    @DisplayName("Test decode with buffer offset")
    void testDecodeWithBufferOffset() throws SMBProtocolDecodingException {
        String fileName = "offset_test.txt";
        int action = FileNotifyInformation.FILE_ACTION_MODIFIED;
        int offset = 50;
        
        byte[] smallBuffer = createValidNotificationBuffer(fileName, action);
        byte[] buffer = new byte[smallBuffer.length + offset + 50];
        System.arraycopy(smallBuffer, 0, buffer, offset, smallBuffer.length);
        
        int bytesRead = notifyInfo.decode(buffer, offset, smallBuffer.length);
        
        assertTrue(bytesRead > 0);
        assertEquals(action, notifyInfo.getAction());
        assertEquals(fileName, notifyInfo.getFileName());
    }

    @Test
    @DisplayName("Test decode correctly calculates bytes read")
    void testDecodeBytesReadCalculation() throws SMBProtocolDecodingException {
        String fileName = "test123.doc";
        byte[] buffer = createValidNotificationBuffer(fileName, FileNotifyInformation.FILE_ACTION_ADDED);
        
        int bytesRead = notifyInfo.decode(buffer, 0, buffer.length);
        
        // Should be: 4 (nextOffset) + 4 (action) + 4 (nameLength) + fileName bytes
        int expectedBytes = 12 + (fileName.length() * 2); // Unicode is 2 bytes per char
        assertEquals(expectedBytes, bytesRead);
    }

    @Test
    @DisplayName("Test getAction returns correct value")
    void testGetAction() throws SMBProtocolDecodingException {
        int expectedAction = FileNotifyInformation.FILE_ACTION_RENAMED_NEW_NAME;
        byte[] buffer = createValidNotificationBuffer("renamed.txt", expectedAction);
        
        notifyInfo.decode(buffer, 0, buffer.length);
        
        assertEquals(expectedAction, notifyInfo.getAction());
    }

    @Test
    @DisplayName("Test getFileName returns correct value")
    void testGetFileName() throws SMBProtocolDecodingException {
        String expectedFileName = "important_document.xlsx";
        byte[] buffer = createValidNotificationBuffer(expectedFileName, FileNotifyInformation.FILE_ACTION_ADDED);
        
        notifyInfo.decode(buffer, 0, buffer.length);
        
        assertEquals(expectedFileName, notifyInfo.getFileName());
    }

    @Test
    @DisplayName("Test getNextEntryOffset returns correct value")
    void testGetNextEntryOffset() throws SMBProtocolDecodingException {
        int expectedOffset = 128;
        byte[] buffer = createNotificationBufferWithNextOffset("file.txt", 
            FileNotifyInformation.FILE_ACTION_ADDED, expectedOffset);
        
        notifyInfo.decode(buffer, 0, buffer.length);
        
        assertEquals(expectedOffset, notifyInfo.getNextEntryOffset());
    }

    @Test
    @DisplayName("Test toString contains expected information")
    void testToString() throws SMBProtocolDecodingException {
        String fileName = "log.txt";
        int action = FileNotifyInformation.FILE_ACTION_MODIFIED;
        byte[] buffer = createValidNotificationBuffer(fileName, action);
        
        notifyInfo.decode(buffer, 0, buffer.length);
        String result = notifyInfo.toString();
        
        assertNotNull(result);
        assertTrue(result.contains("FileNotifyInformation"));
        assertTrue(result.contains("nextEntry="));
        assertTrue(result.contains("action="));
        assertTrue(result.contains("file=" + fileName));
        // Hexdump.toHexString produces 4-character padded uppercase hex
        String expectedHex = String.format("%04X", action);
        assertTrue(result.contains("0x" + expectedHex));
    }

    @Test
    @DisplayName("Test toString with empty object")
    void testToStringEmpty() {
        String result = notifyInfo.toString();
        
        assertNotNull(result);
        assertTrue(result.contains("FileNotifyInformation"));
        assertTrue(result.contains("nextEntry=0"));
        assertTrue(result.contains("action=0x0000")); // Hexdump.toHexString produces 4-char padded hex
        assertTrue(result.contains("file=null"));
    }

    @ParameterizedTest
    @DisplayName("Test decode with aligned next entry offsets")
    @ValueSource(ints = {0, 4, 8, 16, 32, 64, 128, 256, 1024})
    void testDecodeWithAlignedOffsets(int nextOffset) throws SMBProtocolDecodingException {
        byte[] buffer = createNotificationBufferWithNextOffset("aligned.txt", 
            FileNotifyInformation.FILE_ACTION_ADDED, nextOffset);
        
        int bytesRead = notifyInfo.decode(buffer, 0, buffer.length);
        
        assertTrue(bytesRead > 0);
        assertEquals(nextOffset, notifyInfo.getNextEntryOffset());
    }

    @ParameterizedTest
    @DisplayName("Test decode with non-aligned offsets throws exception")
    @ValueSource(ints = {1, 2, 3, 5, 6, 7, 9, 15, 17, 31, 33})
    void testDecodeWithNonAlignedOffsetsThrows(int nextOffset) {
        byte[] buffer = createNotificationBufferWithNextOffset("nonaligned.txt", 
            FileNotifyInformation.FILE_ACTION_ADDED, nextOffset);
        
        assertThrows(SMBProtocolDecodingException.class, () -> {
            notifyInfo.decode(buffer, 0, buffer.length);
        });
    }

    @Test
    @DisplayName("Test decode with maximum file name length")
    void testDecodeMaxFileNameLength() throws SMBProtocolDecodingException {
        // Create a very long filename (but within reasonable bounds)
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 255; i++) {
            sb.append('A');
        }
        String longFileName = sb.toString();
        
        byte[] buffer = createValidNotificationBuffer(longFileName, FileNotifyInformation.FILE_ACTION_ADDED);
        
        int bytesRead = notifyInfo.decode(buffer, 0, buffer.length);
        
        assertTrue(bytesRead > 0);
        assertEquals(longFileName, notifyInfo.getFileName());
    }

    @Test
    @DisplayName("Test decode with empty file name")
    void testDecodeEmptyFileName() throws SMBProtocolDecodingException {
        byte[] buffer = createValidNotificationBuffer("", FileNotifyInformation.FILE_ACTION_ADDED);
        
        int bytesRead = notifyInfo.decode(buffer, 0, buffer.length);
        
        assertTrue(bytesRead >= 12); // At least the header bytes
        assertEquals("", notifyInfo.getFileName());
    }

    /**
     * Helper method to create a valid notification buffer
     */
    private byte[] createValidNotificationBuffer(String fileName, int action) {
        return createNotificationBufferWithNextOffset(fileName, action, 0);
    }

    /**
     * Helper method to create a notification buffer with specified next offset
     */
    private byte[] createNotificationBufferWithNextOffset(String fileName, int action, int nextOffset) {
        byte[] fileNameBytes = fileName.getBytes(StandardCharsets.UTF_16LE);
        int totalSize = 12 + fileNameBytes.length + 50; // Extra space for safety
        byte[] buffer = new byte[totalSize];
        
        // Write next entry offset (4 bytes)
        SMBUtil.writeInt4(nextOffset, buffer, 0);
        
        // Write action (4 bytes)
        SMBUtil.writeInt4(action, buffer, 4);
        
        // Write file name length (4 bytes)
        SMBUtil.writeInt4(fileNameBytes.length, buffer, 8);
        
        // Write file name
        System.arraycopy(fileNameBytes, 0, buffer, 12, fileNameBytes.length);
        
        return buffer;
    }
}
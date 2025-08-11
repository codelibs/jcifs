package jcifs.internal.fscc;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import java.util.Date;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import jcifs.Configuration;
import jcifs.SmbConstants;
import jcifs.internal.SMBProtocolDecodingException;
import jcifs.internal.util.SMBUtil;
import jcifs.util.Strings;

/**
 * Test class for FileBothDirectoryInfo
 */
class FileBothDirectoryInfoTest {

    @Mock
    private Configuration mockConfig;
    
    private FileBothDirectoryInfo fileBothDirectoryInfo;
    private FileBothDirectoryInfo fileBothDirectoryInfoNonUnicode;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        // Mock the OEM encoding for non-Unicode tests
        when(mockConfig.getOemEncoding()).thenReturn("Cp850");
        fileBothDirectoryInfo = new FileBothDirectoryInfo(mockConfig, true);
        fileBothDirectoryInfoNonUnicode = new FileBothDirectoryInfo(mockConfig, false);
    }

    @Test
    @DisplayName("Test constructor initializes fields correctly")
    void testConstructor() {
        assertNotNull(fileBothDirectoryInfo);
        assertNotNull(fileBothDirectoryInfoNonUnicode);
    }

    @Test
    @DisplayName("Test getName returns filename")
    void testGetName() throws SMBProtocolDecodingException {
        // Prepare test data
        byte[] buffer = createValidBuffer("testfile.txt", "TEST~1.TXT", true);
        
        // Decode
        fileBothDirectoryInfo.decode(buffer, 0, buffer.length);
        
        // Verify
        assertEquals("testfile.txt", fileBothDirectoryInfo.getName());
    }

    @Test
    @DisplayName("Test getType returns TYPE_FILESYSTEM")
    void testGetType() {
        assertEquals(SmbConstants.TYPE_FILESYSTEM, fileBothDirectoryInfo.getType());
    }

    @Test
    @DisplayName("Test getFileIndex returns correct value")
    void testGetFileIndex() throws SMBProtocolDecodingException {
        // Prepare test data
        byte[] buffer = createValidBuffer("file.txt", "FILE~1.TXT", true);
        int expectedFileIndex = 0x12345678;
        SMBUtil.writeInt4(expectedFileIndex, buffer, 4);
        
        // Decode
        fileBothDirectoryInfo.decode(buffer, 0, buffer.length);
        
        // Verify
        assertEquals(expectedFileIndex, fileBothDirectoryInfo.getFileIndex());
    }

    @Test
    @DisplayName("Test getFilename returns correct filename")
    void testGetFilename() throws SMBProtocolDecodingException {
        // Prepare test data
        String expectedFilename = "longfilename.docx";
        byte[] buffer = createValidBuffer(expectedFilename, "LONGFI~1.DOC", true);
        
        // Decode
        fileBothDirectoryInfo.decode(buffer, 0, buffer.length);
        
        // Verify
        assertEquals(expectedFilename, fileBothDirectoryInfo.getFilename());
    }

    @Test
    @DisplayName("Test getAttributes returns correct attributes")
    void testGetAttributes() throws SMBProtocolDecodingException {
        // Prepare test data
        byte[] buffer = createValidBuffer("file.txt", "FILE~1.TXT", true);
        int expectedAttributes = 0x00000021; // FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_ARCHIVE
        SMBUtil.writeInt4(expectedAttributes, buffer, 56);
        
        // Decode
        fileBothDirectoryInfo.decode(buffer, 0, buffer.length);
        
        // Verify
        assertEquals(expectedAttributes, fileBothDirectoryInfo.getAttributes());
    }

    @Test
    @DisplayName("Test createTime returns correct creation time")
    void testCreateTime() throws SMBProtocolDecodingException {
        // Prepare test data
        byte[] buffer = createValidBuffer("file.txt", "FILE~1.TXT", true);
        long expectedCreationTime = System.currentTimeMillis();
        SMBUtil.writeTime(expectedCreationTime, buffer, 8);
        
        // Decode
        fileBothDirectoryInfo.decode(buffer, 0, buffer.length);
        
        // Verify
        assertEquals(expectedCreationTime, fileBothDirectoryInfo.createTime());
    }

    @Test
    @DisplayName("Test lastModified returns correct last write time")
    void testLastModified() throws SMBProtocolDecodingException {
        // Prepare test data
        byte[] buffer = createValidBuffer("file.txt", "FILE~1.TXT", true);
        long expectedLastWriteTime = System.currentTimeMillis();
        SMBUtil.writeTime(expectedLastWriteTime, buffer, 24);
        
        // Decode
        fileBothDirectoryInfo.decode(buffer, 0, buffer.length);
        
        // Verify
        assertEquals(expectedLastWriteTime, fileBothDirectoryInfo.lastModified());
    }

    @Test
    @DisplayName("Test lastAccess returns correct last access time")
    void testLastAccess() throws SMBProtocolDecodingException {
        // Prepare test data
        byte[] buffer = createValidBuffer("file.txt", "FILE~1.TXT", true);
        long expectedLastAccessTime = System.currentTimeMillis();
        SMBUtil.writeTime(expectedLastAccessTime, buffer, 16);
        
        // Decode
        fileBothDirectoryInfo.decode(buffer, 0, buffer.length);
        
        // Verify
        assertEquals(expectedLastAccessTime, fileBothDirectoryInfo.lastAccess());
    }

    @Test
    @DisplayName("Test length returns correct end of file size")
    void testLength() throws SMBProtocolDecodingException {
        // Prepare test data
        byte[] buffer = createValidBuffer("file.txt", "FILE~1.TXT", true);
        long expectedEndOfFile = 1024L * 1024L; // 1MB
        SMBUtil.writeInt8(expectedEndOfFile, buffer, 40);
        
        // Decode
        fileBothDirectoryInfo.decode(buffer, 0, buffer.length);
        
        // Verify
        assertEquals(expectedEndOfFile, fileBothDirectoryInfo.length());
    }

    @Test
    @DisplayName("Test getNextEntryOffset returns correct value")
    void testGetNextEntryOffset() throws SMBProtocolDecodingException {
        // Prepare test data
        byte[] buffer = createValidBuffer("file.txt", "FILE~1.TXT", true);
        int expectedNextEntryOffset = 256;
        SMBUtil.writeInt4(expectedNextEntryOffset, buffer, 0);
        
        // Decode
        fileBothDirectoryInfo.decode(buffer, 0, buffer.length);
        
        // Verify
        assertEquals(expectedNextEntryOffset, fileBothDirectoryInfo.getNextEntryOffset());
    }

    @Test
    @DisplayName("Test decode with Unicode filename")
    void testDecodeWithUnicodeFilename() throws SMBProtocolDecodingException {
        // Prepare test data with Unicode filename
        String expectedFilename = "日本語ファイル.txt";
        byte[] buffer = createValidBuffer(expectedFilename, "~1.TXT", true);
        
        // Decode
        fileBothDirectoryInfo.decode(buffer, 0, buffer.length);
        
        // Verify
        assertEquals(expectedFilename, fileBothDirectoryInfo.getFilename());
    }

    @Test
    @DisplayName("Test decode with non-Unicode filename")
    void testDecodeWithNonUnicodeFilename() throws SMBProtocolDecodingException {
        // Prepare test data with non-Unicode filename
        String expectedFilename = "asciifile.txt";
        byte[] buffer = createValidBufferNonUnicode(expectedFilename, "ASCII~1.TXT");
        
        // Decode
        fileBothDirectoryInfoNonUnicode.decode(buffer, 0, buffer.length);
        
        // Verify
        assertEquals(expectedFilename, fileBothDirectoryInfoNonUnicode.getFilename());
    }

    @Test
    @DisplayName("Test decode with null-terminated Unicode filename")
    void testDecodeWithNullTerminatedUnicodeFilename() throws SMBProtocolDecodingException {
        // Prepare test data with null-terminated filename
        String expectedFilename = "nullterm.txt";
        byte[] buffer = createValidBufferWithNullTermination(expectedFilename, "NULLTE~1.TXT", true);
        
        // Decode
        fileBothDirectoryInfo.decode(buffer, 0, buffer.length);
        
        // Verify - the decode method strips null termination, so filename should match
        assertEquals(expectedFilename, fileBothDirectoryInfo.getFilename());
    }

    @Test
    @DisplayName("Test decode with null-terminated non-Unicode filename")
    void testDecodeWithNullTerminatedNonUnicodeFilename() throws SMBProtocolDecodingException {
        // Prepare test data with null-terminated filename
        String expectedFilename = "nullterm.txt";
        byte[] buffer = createValidBufferWithNullTerminationNonUnicode(expectedFilename, "NULLTE~1.TXT");
        
        // Decode
        fileBothDirectoryInfoNonUnicode.decode(buffer, 0, buffer.length);
        
        // Verify
        assertEquals(expectedFilename, fileBothDirectoryInfoNonUnicode.getFilename());
    }

    @Test
    @DisplayName("Test decode with buffer offset")
    void testDecodeWithBufferOffset() throws SMBProtocolDecodingException {
        // Prepare test data with offset
        int offset = 10;
        String expectedFilename = "offsetfile.txt";
        byte[] buffer = new byte[200 + offset];
        byte[] dataBuffer = createValidBuffer(expectedFilename, "OFFSET~1.TXT", true);
        System.arraycopy(dataBuffer, 0, buffer, offset, dataBuffer.length);
        
        // Decode from offset
        fileBothDirectoryInfo.decode(buffer, offset, dataBuffer.length);
        
        // Verify
        assertEquals(expectedFilename, fileBothDirectoryInfo.getFilename());
    }

    @Test
    @DisplayName("Test decode returns correct bytes consumed")
    void testDecodeBytesConsumed() throws SMBProtocolDecodingException {
        // Prepare test data
        String filename = "testfile.txt";
        byte[] buffer = createValidBuffer(filename, "TESTFI~1.TXT", true);
        
        // Decode and check return value
        int bytesConsumed = fileBothDirectoryInfo.decode(buffer, 0, buffer.length);
        
        // Verify bytes consumed matches the actual data size
        assertTrue(bytesConsumed < 0); // Return value is negative (start - bufferIndex)
        assertEquals(-94 - filename.length() * 2, bytesConsumed); // Base structure + filename length
    }

    @Test
    @DisplayName("Test decode with maximum field values")
    void testDecodeWithMaximumValues() throws SMBProtocolDecodingException {
        // Prepare test data with maximum values
        byte[] buffer = createValidBuffer("maxfile.txt", "MAXFIL~1.TXT", true);
        
        // Set maximum values
        SMBUtil.writeInt4(Integer.MAX_VALUE, buffer, 0); // nextEntryOffset
        SMBUtil.writeInt4(Integer.MAX_VALUE, buffer, 4); // fileIndex
        // For time values, use a reasonable max time that won't overflow
        long maxTime = System.currentTimeMillis() + 1000000000000L;
        SMBUtil.writeTime(maxTime, buffer, 8); // creationTime
        SMBUtil.writeTime(maxTime, buffer, 16); // lastAccessTime
        SMBUtil.writeTime(maxTime, buffer, 24); // lastWriteTime
        SMBUtil.writeTime(maxTime, buffer, 32); // changeTime
        SMBUtil.writeInt8(Long.MAX_VALUE, buffer, 40); // endOfFile
        SMBUtil.writeInt8(Long.MAX_VALUE, buffer, 48); // allocationSize
        SMBUtil.writeInt4(Integer.MAX_VALUE, buffer, 56); // extFileAttributes
        SMBUtil.writeInt4(Integer.MAX_VALUE, buffer, 64); // eaSize
        
        // Decode
        fileBothDirectoryInfo.decode(buffer, 0, buffer.length);
        
        // Verify
        assertEquals(Integer.MAX_VALUE, fileBothDirectoryInfo.getNextEntryOffset());
        assertEquals(Integer.MAX_VALUE, fileBothDirectoryInfo.getFileIndex());
        assertEquals(maxTime, fileBothDirectoryInfo.createTime());
        assertEquals(maxTime, fileBothDirectoryInfo.lastAccess());
        assertEquals(maxTime, fileBothDirectoryInfo.lastModified());
        assertEquals(Long.MAX_VALUE, fileBothDirectoryInfo.length());
        assertEquals(Integer.MAX_VALUE, fileBothDirectoryInfo.getAttributes());
    }

    @Test
    @DisplayName("Test decode with zero values")
    void testDecodeWithZeroValues() throws SMBProtocolDecodingException {
        // Prepare test data with zero values
        byte[] buffer = createValidBuffer("zerofile.txt", "ZEROFI~1.TXT", true);
        
        // Set zero values - for SMB times, 0 in wire format represents 0 in Java time
        SMBUtil.writeInt4(0, buffer, 0); // nextEntryOffset
        SMBUtil.writeInt4(0, buffer, 4); // fileIndex
        SMBUtil.writeInt8(0, buffer, 8); // creationTime - raw 0 in wire format
        SMBUtil.writeInt8(0, buffer, 16); // lastAccessTime - raw 0 in wire format
        SMBUtil.writeInt8(0, buffer, 24); // lastWriteTime - raw 0 in wire format
        SMBUtil.writeInt8(0, buffer, 32); // changeTime - raw 0 in wire format
        SMBUtil.writeInt8(0, buffer, 40); // endOfFile
        SMBUtil.writeInt8(0, buffer, 48); // allocationSize
        SMBUtil.writeInt4(0, buffer, 56); // extFileAttributes
        SMBUtil.writeInt4(0, buffer, 64); // eaSize
        
        // Decode
        fileBothDirectoryInfo.decode(buffer, 0, buffer.length);
        
        // Verify - when wire format is 0, readTime returns a negative value due to the 1601-1970 conversion
        assertEquals(0, fileBothDirectoryInfo.getNextEntryOffset());
        assertEquals(0, fileBothDirectoryInfo.getFileIndex());
        // For time fields, 0 in the wire format means Jan 1, 1601, which is negative in Unix epoch
        assertTrue(fileBothDirectoryInfo.createTime() < 0);
        assertTrue(fileBothDirectoryInfo.lastAccess() < 0);
        assertTrue(fileBothDirectoryInfo.lastModified() < 0);
        assertEquals(0, fileBothDirectoryInfo.length());
        assertEquals(0, fileBothDirectoryInfo.getAttributes());
    }

    @Test
    @DisplayName("Test toString method contains all fields")
    void testToString() throws SMBProtocolDecodingException {
        // Prepare test data
        byte[] buffer = createValidBuffer("tostring.txt", "TOSTRI~1.TXT", true);
        long testTime = System.currentTimeMillis();
        
        // Set specific values
        SMBUtil.writeInt4(100, buffer, 0); // nextEntryOffset
        SMBUtil.writeInt4(200, buffer, 4); // fileIndex
        SMBUtil.writeTime(testTime, buffer, 8); // creationTime
        SMBUtil.writeTime(testTime, buffer, 16); // lastAccessTime
        SMBUtil.writeTime(testTime, buffer, 24); // lastWriteTime
        SMBUtil.writeTime(testTime, buffer, 32); // changeTime
        SMBUtil.writeInt8(1024L, buffer, 40); // endOfFile
        SMBUtil.writeInt8(2048L, buffer, 48); // allocationSize
        SMBUtil.writeInt4(0x20, buffer, 56); // extFileAttributes
        SMBUtil.writeInt4(512, buffer, 64); // eaSize
        
        // Decode
        fileBothDirectoryInfo.decode(buffer, 0, buffer.length);
        
        // Get toString result
        String result = fileBothDirectoryInfo.toString();
        
        // Verify string contains all important fields
        assertTrue(result.contains("SmbFindFileBothDirectoryInfo"));
        assertTrue(result.contains("nextEntryOffset=100"));
        assertTrue(result.contains("fileIndex=200"));
        assertTrue(result.contains("creationTime="));
        assertTrue(result.contains("lastAccessTime="));
        assertTrue(result.contains("lastWriteTime="));
        assertTrue(result.contains("changeTime="));
        assertTrue(result.contains("endOfFile=1024"));
        assertTrue(result.contains("allocationSize=2048"));
        assertTrue(result.contains("extFileAttributes=32"));
        assertTrue(result.contains("eaSize=512"));
        assertTrue(result.contains("shortName=TOSTRI~1.TXT"));
        assertTrue(result.contains("filename=tostring.txt"));
    }

    @Test
    @DisplayName("Test decode with empty filename")
    void testDecodeWithEmptyFilename() throws SMBProtocolDecodingException {
        // Prepare test data with empty filename
        byte[] buffer = createValidBuffer("", "", true);
        
        // Decode
        fileBothDirectoryInfo.decode(buffer, 0, buffer.length);
        
        // Verify
        assertEquals("", fileBothDirectoryInfo.getFilename());
    }

    @Test
    @DisplayName("Test decode with very long filename")
    void testDecodeWithLongFilename() throws SMBProtocolDecodingException {
        // Prepare test data with long filename (255 characters)
        StringBuilder longName = new StringBuilder();
        for (int i = 0; i < 255; i++) {
            longName.append((char)('a' + (i % 26)));
        }
        String expectedFilename = longName.toString();
        byte[] buffer = createValidBuffer(expectedFilename, "LONGNA~1.TXT", true);
        
        // Decode
        fileBothDirectoryInfo.decode(buffer, 0, buffer.length);
        
        // Verify
        assertEquals(expectedFilename, fileBothDirectoryInfo.getFilename());
    }

    @Test
    @DisplayName("Test decode with special characters in filename")
    void testDecodeWithSpecialCharactersInFilename() throws SMBProtocolDecodingException {
        // Prepare test data with special characters
        String expectedFilename = "file-name_2024#version@1.0.txt";
        byte[] buffer = createValidBuffer(expectedFilename, "FILE-N~1.TXT", true);
        
        // Decode
        fileBothDirectoryInfo.decode(buffer, 0, buffer.length);
        
        // Verify
        assertEquals(expectedFilename, fileBothDirectoryInfo.getFilename());
    }

    // Helper methods to create valid buffer data
    private byte[] createValidBuffer(String filename, String shortName, boolean unicode) {
        int filenameLength = unicode ? filename.length() * 2 : filename.length();
        byte[] buffer = new byte[94 + filenameLength];
        
        // Set default values
        SMBUtil.writeInt4(0, buffer, 0); // nextEntryOffset
        SMBUtil.writeInt4(1, buffer, 4); // fileIndex
        SMBUtil.writeTime(System.currentTimeMillis(), buffer, 8); // creationTime
        SMBUtil.writeTime(System.currentTimeMillis(), buffer, 16); // lastAccessTime
        SMBUtil.writeTime(System.currentTimeMillis(), buffer, 24); // lastWriteTime
        SMBUtil.writeTime(System.currentTimeMillis(), buffer, 32); // changeTime
        SMBUtil.writeInt8(1024L, buffer, 40); // endOfFile
        SMBUtil.writeInt8(2048L, buffer, 48); // allocationSize
        SMBUtil.writeInt4(0x20, buffer, 56); // extFileAttributes
        SMBUtil.writeInt4(filenameLength, buffer, 60); // fileNameLength
        SMBUtil.writeInt4(0, buffer, 64); // eaSize
        
        // Write short name length and short name
        byte[] shortNameBytes = Strings.getUNIBytes(shortName);
        buffer[68] = (byte) shortNameBytes.length; // shortNameLength
        System.arraycopy(shortNameBytes, 0, buffer, 70, Math.min(shortNameBytes.length, 24));
        
        // Write filename
        if (unicode) {
            byte[] filenameBytes = Strings.getUNIBytes(filename);
            System.arraycopy(filenameBytes, 0, buffer, 94, filenameBytes.length);
        } else {
            byte[] filenameBytes = Strings.getOEMBytes(filename, mockConfig);
            System.arraycopy(filenameBytes, 0, buffer, 94, filenameBytes.length);
        }
        
        return buffer;
    }

    private byte[] createValidBufferNonUnicode(String filename, String shortName) {
        return createValidBuffer(filename, shortName, false);
    }

    private byte[] createValidBufferWithNullTermination(String filename, String shortName, boolean unicode) {
        // Create buffer with extra space for null termination
        int filenameLength = unicode ? (filename.length() * 2) + 2 : filename.length() + 1;
        byte[] buffer = new byte[94 + filenameLength];
        
        // Set default values
        SMBUtil.writeInt4(0, buffer, 0); // nextEntryOffset
        SMBUtil.writeInt4(1, buffer, 4); // fileIndex
        SMBUtil.writeTime(System.currentTimeMillis(), buffer, 8); // creationTime
        SMBUtil.writeTime(System.currentTimeMillis(), buffer, 16); // lastAccessTime
        SMBUtil.writeTime(System.currentTimeMillis(), buffer, 24); // lastWriteTime
        SMBUtil.writeTime(System.currentTimeMillis(), buffer, 32); // changeTime
        SMBUtil.writeInt8(1024L, buffer, 40); // endOfFile
        SMBUtil.writeInt8(2048L, buffer, 48); // allocationSize
        SMBUtil.writeInt4(0x20, buffer, 56); // extFileAttributes
        SMBUtil.writeInt4(filenameLength, buffer, 60); // fileNameLength - includes null termination
        SMBUtil.writeInt4(0, buffer, 64); // eaSize
        
        // Write short name length and short name
        byte[] shortNameBytes = Strings.getUNIBytes(shortName);
        buffer[68] = (byte) shortNameBytes.length; // shortNameLength
        System.arraycopy(shortNameBytes, 0, buffer, 70, Math.min(shortNameBytes.length, 24));
        
        // Write filename with null termination
        if (unicode) {
            byte[] filenameBytes = Strings.getUNIBytes(filename);
            System.arraycopy(filenameBytes, 0, buffer, 94, filenameBytes.length);
            // Add null termination
            buffer[94 + filenameBytes.length] = 0;
            buffer[94 + filenameBytes.length + 1] = 0;
        } else {
            byte[] filenameBytes = Strings.getOEMBytes(filename, mockConfig);
            System.arraycopy(filenameBytes, 0, buffer, 94, filenameBytes.length);
            // Add null termination
            buffer[94 + filenameBytes.length] = 0;
        }
        
        return buffer;
    }

    private byte[] createValidBufferWithNullTerminationNonUnicode(String filename, String shortName) {
        return createValidBufferWithNullTermination(filename, shortName, false);
    }
}

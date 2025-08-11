package jcifs.internal.fscc;

import static org.junit.jupiter.api.Assertions.*;

import java.util.Date;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import jcifs.internal.SMBProtocolDecodingException;
import jcifs.internal.util.SMBUtil;

/**
 * Test class for FileBasicInfo
 */
class FileBasicInfoTest {

    private FileBasicInfo fileBasicInfo;
    // Use realistic time values in milliseconds since 1970 (Unix epoch)
    private static final long TEST_CREATE_TIME = System.currentTimeMillis() - 86400000L; // 1 day ago
    private static final long TEST_LAST_ACCESS_TIME = System.currentTimeMillis() - 43200000L; // 12 hours ago
    private static final long TEST_LAST_WRITE_TIME = System.currentTimeMillis() - 3600000L; // 1 hour ago
    private static final long TEST_CHANGE_TIME = System.currentTimeMillis(); // now
    private static final int TEST_ATTRIBUTES = 0x00000020; // FILE_ATTRIBUTE_ARCHIVE

    @BeforeEach
    void setUp() {
        fileBasicInfo = new FileBasicInfo();
    }

    @Test
    @DisplayName("Test default constructor")
    void testDefaultConstructor() {
        // Verify default values
        assertEquals(0L, fileBasicInfo.getCreateTime());
        assertEquals(0L, fileBasicInfo.getLastAccessTime());
        assertEquals(0L, fileBasicInfo.getLastWriteTime());
        assertEquals(0, fileBasicInfo.getAttributes());
    }

    @Test
    @DisplayName("Test parameterized constructor")
    void testParameterizedConstructor() {
        // Create instance with test values
        FileBasicInfo info = new FileBasicInfo(
            TEST_CREATE_TIME,
            TEST_LAST_ACCESS_TIME,
            TEST_LAST_WRITE_TIME,
            TEST_CHANGE_TIME,
            TEST_ATTRIBUTES
        );

        // Verify all values are set correctly
        assertEquals(TEST_CREATE_TIME, info.getCreateTime());
        assertEquals(TEST_LAST_ACCESS_TIME, info.getLastAccessTime());
        assertEquals(TEST_LAST_WRITE_TIME, info.getLastWriteTime());
        assertEquals(TEST_ATTRIBUTES, info.getAttributes());
    }

    @Test
    @DisplayName("Test getFileInformationLevel returns correct value")
    void testGetFileInformationLevel() {
        assertEquals(FileInformation.FILE_BASIC_INFO, fileBasicInfo.getFileInformationLevel());
    }

    @Test
    @DisplayName("Test getSize always returns 0")
    void testGetSize() {
        // Default instance
        assertEquals(0L, fileBasicInfo.getSize());
        
        // Instance with values
        FileBasicInfo info = new FileBasicInfo(
            TEST_CREATE_TIME,
            TEST_LAST_ACCESS_TIME,
            TEST_LAST_WRITE_TIME,
            TEST_CHANGE_TIME,
            TEST_ATTRIBUTES
        );
        assertEquals(0L, info.getSize());
    }

    @Test
    @DisplayName("Test size method returns correct buffer size")
    void testSize() {
        assertEquals(40, fileBasicInfo.size());
    }

    @Test
    @DisplayName("Test encode method")
    void testEncode() throws SMBProtocolDecodingException {
        // Create instance with test values
        FileBasicInfo info = new FileBasicInfo(
            TEST_CREATE_TIME,
            TEST_LAST_ACCESS_TIME,
            TEST_LAST_WRITE_TIME,
            TEST_CHANGE_TIME,
            TEST_ATTRIBUTES
        );

        // Prepare buffer
        byte[] buffer = new byte[100];
        int startIndex = 10;

        // Encode
        int bytesWritten = info.encode(buffer, startIndex);

        // Verify bytes written (encode returns 40, which includes 4 padding bytes)
        assertEquals(40, bytesWritten);

        // Create a new FileBasicInfo and decode to verify encoding
        FileBasicInfo decoded = new FileBasicInfo();
        decoded.decode(buffer, startIndex, 36); // decode only reads 36 bytes
        
        // Verify the values match after round-trip
        assertEquals(TEST_CREATE_TIME, decoded.getCreateTime());
        assertEquals(TEST_LAST_ACCESS_TIME, decoded.getLastAccessTime());
        assertEquals(TEST_LAST_WRITE_TIME, decoded.getLastWriteTime());
        assertEquals(TEST_ATTRIBUTES, decoded.getAttributes());
    }

    @Test
    @DisplayName("Test decode method")
    void testDecode() throws SMBProtocolDecodingException {
        // First encode using a known FileBasicInfo
        FileBasicInfo original = new FileBasicInfo(
            TEST_CREATE_TIME,
            TEST_LAST_ACCESS_TIME,
            TEST_LAST_WRITE_TIME,
            TEST_CHANGE_TIME,
            TEST_ATTRIBUTES
        );
        
        byte[] buffer = new byte[100];
        int startIndex = 5;
        original.encode(buffer, startIndex);

        // Now decode into a new instance
        int bytesRead = fileBasicInfo.decode(buffer, startIndex, 36);

        // Verify bytes read
        assertEquals(36, bytesRead);

        // Verify decoded values match original
        assertEquals(TEST_CREATE_TIME, fileBasicInfo.getCreateTime());
        assertEquals(TEST_LAST_ACCESS_TIME, fileBasicInfo.getLastAccessTime());
        assertEquals(TEST_LAST_WRITE_TIME, fileBasicInfo.getLastWriteTime());
        assertEquals(TEST_ATTRIBUTES, fileBasicInfo.getAttributes());
    }

    @Test
    @DisplayName("Test encode and decode roundtrip")
    void testEncodeDecodeRoundtrip() throws SMBProtocolDecodingException {
        // Create original instance
        FileBasicInfo original = new FileBasicInfo(
            TEST_CREATE_TIME,
            TEST_LAST_ACCESS_TIME,
            TEST_LAST_WRITE_TIME,
            TEST_CHANGE_TIME,
            TEST_ATTRIBUTES
        );

        // Encode to buffer
        byte[] buffer = new byte[50];
        int encodedBytes = original.encode(buffer, 0);

        // Decode to new instance (decode reads 36 bytes, encode writes 40)
        FileBasicInfo decoded = new FileBasicInfo();
        int decodedBytes = decoded.decode(buffer, 0, 36);

        // Verify encoding/decoding
        assertEquals(40, encodedBytes); // encode writes 40 bytes (includes padding)
        assertEquals(36, decodedBytes); // decode reads 36 bytes (no padding)
        assertEquals(original.getCreateTime(), decoded.getCreateTime());
        assertEquals(original.getLastAccessTime(), decoded.getLastAccessTime());
        assertEquals(original.getLastWriteTime(), decoded.getLastWriteTime());
        assertEquals(original.getAttributes(), decoded.getAttributes());
    }

    @Test
    @DisplayName("Test toString method")
    void testToString() {
        FileBasicInfo info = new FileBasicInfo(
            TEST_CREATE_TIME,
            TEST_LAST_ACCESS_TIME,
            TEST_LAST_WRITE_TIME,
            TEST_CHANGE_TIME,
            TEST_ATTRIBUTES
        );

        String str = info.toString();

        // Verify string contains expected elements
        assertNotNull(str);
        assertTrue(str.startsWith("SmbQueryFileBasicInfo["));
        assertTrue(str.contains("createTime="));
        assertTrue(str.contains("lastAccessTime="));
        assertTrue(str.contains("lastWriteTime="));
        assertTrue(str.contains("changeTime="));
        assertTrue(str.contains("attributes=0x"));
        assertTrue(str.endsWith("]"));
    }

    @Test
    @DisplayName("Test decode with minimum buffer size")
    void testDecodeMinimumBuffer() throws SMBProtocolDecodingException {
        // First create and encode
        FileBasicInfo original = new FileBasicInfo(
            TEST_CREATE_TIME,
            TEST_LAST_ACCESS_TIME,
            TEST_LAST_WRITE_TIME,
            TEST_CHANGE_TIME,
            TEST_ATTRIBUTES
        );
        
        // Create buffer with exact decode size
        byte[] tempBuffer = new byte[50];
        original.encode(tempBuffer, 0);
        
        // Copy only the first 36 bytes (what decode reads)
        byte[] buffer = new byte[36];
        System.arraycopy(tempBuffer, 0, buffer, 0, 36);

        // Decode
        int bytesRead = fileBasicInfo.decode(buffer, 0, 36);

        // Verify
        assertEquals(36, bytesRead);
        assertEquals(TEST_CREATE_TIME, fileBasicInfo.getCreateTime());
        assertEquals(TEST_LAST_ACCESS_TIME, fileBasicInfo.getLastAccessTime());
        assertEquals(TEST_LAST_WRITE_TIME, fileBasicInfo.getLastWriteTime());
        assertEquals(TEST_ATTRIBUTES, fileBasicInfo.getAttributes());
    }

    @Test
    @DisplayName("Test encode with offset")
    void testEncodeWithOffset() throws SMBProtocolDecodingException {
        FileBasicInfo info = new FileBasicInfo(
            TEST_CREATE_TIME,
            TEST_LAST_ACCESS_TIME,
            TEST_LAST_WRITE_TIME,
            TEST_CHANGE_TIME,
            TEST_ATTRIBUTES
        );

        byte[] buffer = new byte[100];
        int offset = 25;
        
        // Encode with offset
        int bytesWritten = info.encode(buffer, offset);

        // Verify bytes written
        assertEquals(40, bytesWritten);
        
        // Decode to verify encoding
        FileBasicInfo decoded = new FileBasicInfo();
        decoded.decode(buffer, offset, 36);
        
        assertEquals(TEST_CREATE_TIME, decoded.getCreateTime());
        assertEquals(TEST_LAST_ACCESS_TIME, decoded.getLastAccessTime());
        assertEquals(TEST_LAST_WRITE_TIME, decoded.getLastWriteTime());
        assertEquals(TEST_ATTRIBUTES, decoded.getAttributes());
    }

    @Test
    @DisplayName("Test with zero times and attributes")
    void testWithZeroValues() throws SMBProtocolDecodingException {
        FileBasicInfo info = new FileBasicInfo(0L, 0L, 0L, 0L, 0);

        // Encode
        byte[] buffer = new byte[50];
        int encodedBytes = info.encode(buffer, 0);

        // Decode
        FileBasicInfo decoded = new FileBasicInfo();
        decoded.decode(buffer, 0, 36); // decode reads 36 bytes

        // Note: When encoding time 0, SMBUtil.writeTime writes 0 directly,
        // but SMBUtil.readTime interprets 0 as Jan 1, 1601 in Unix time (-11644473600000)
        // This is the expected behavior for Windows FILETIME
        long expectedTime = -11644473600000L; // Jan 1, 1601 in Unix time
        assertEquals(expectedTime, decoded.getCreateTime());
        assertEquals(expectedTime, decoded.getLastAccessTime());
        assertEquals(expectedTime, decoded.getLastWriteTime());
        assertEquals(0, decoded.getAttributes());
    }

    @Test
    @DisplayName("Test with large time values")
    void testWithLargeTimeValues() throws SMBProtocolDecodingException {
        // Use large but valid time values
        long largeTime = System.currentTimeMillis() + 365L * 24 * 60 * 60 * 1000; // 1 year from now
        int maxAttributes = Integer.MAX_VALUE;
        
        FileBasicInfo info = new FileBasicInfo(
            largeTime,
            largeTime,
            largeTime,
            largeTime,
            maxAttributes
        );

        // Encode and decode
        byte[] buffer = new byte[50];
        info.encode(buffer, 0);
        
        FileBasicInfo decoded = new FileBasicInfo();
        decoded.decode(buffer, 0, 36);

        // Verify
        assertEquals(largeTime, decoded.getCreateTime());
        assertEquals(largeTime, decoded.getLastAccessTime());
        assertEquals(largeTime, decoded.getLastWriteTime());
        assertEquals(maxAttributes, decoded.getAttributes());
    }

    @Test
    @DisplayName("Test with various file attributes")
    void testVariousFileAttributes() {
        // Test common file attribute combinations
        int[] attributes = {
            0x00000001, // FILE_ATTRIBUTE_READONLY
            0x00000002, // FILE_ATTRIBUTE_HIDDEN
            0x00000004, // FILE_ATTRIBUTE_SYSTEM
            0x00000010, // FILE_ATTRIBUTE_DIRECTORY
            0x00000020, // FILE_ATTRIBUTE_ARCHIVE
            0x00000080, // FILE_ATTRIBUTE_NORMAL
            0x00000100, // FILE_ATTRIBUTE_TEMPORARY
            0x00000037  // Combined attributes
        };

        for (int attr : attributes) {
            FileBasicInfo info = new FileBasicInfo(0L, 0L, 0L, 0L, attr);
            assertEquals(attr, info.getAttributes());
            
            // Verify in toString
            String str = info.toString();
            assertTrue(str.contains("attributes=0x"));
        }
    }
}

package org.codelibs.jcifs.smb.internal.fscc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import org.codelibs.jcifs.smb.internal.SMBProtocolDecodingException;
import org.codelibs.jcifs.smb.internal.util.SMBUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Test class for BasicFileInformation interface and its implementations
 */
@ExtendWith(MockitoExtension.class)
class BasicFileInformationTest {

    @Mock
    private BasicFileInformation mockBasicFileInfo;

    private FileBasicInfo fileBasicInfo;

    // Use Unix timestamps (milliseconds since 1970) for test values
    private static final long TEST_CREATE_TIME = System.currentTimeMillis() - 10000;
    private static final long TEST_LAST_ACCESS_TIME = System.currentTimeMillis() - 8000;
    private static final long TEST_LAST_WRITE_TIME = System.currentTimeMillis() - 6000;
    private static final long TEST_CHANGE_TIME = System.currentTimeMillis() - 4000;
    private static final int TEST_ATTRIBUTES = 0x20; // FILE_ATTRIBUTE_ARCHIVE

    @BeforeEach
    void setUp() {
        fileBasicInfo = new FileBasicInfo();
    }

    @Test
    @DisplayName("Test interface mock behavior")
    void testInterfaceMock() {
        // Given
        when(mockBasicFileInfo.getAttributes()).thenReturn(TEST_ATTRIBUTES);
        when(mockBasicFileInfo.getCreateTime()).thenReturn(TEST_CREATE_TIME);
        when(mockBasicFileInfo.getLastWriteTime()).thenReturn(TEST_LAST_WRITE_TIME);
        when(mockBasicFileInfo.getLastAccessTime()).thenReturn(TEST_LAST_ACCESS_TIME);
        when(mockBasicFileInfo.getSize()).thenReturn(1024L);
        when(mockBasicFileInfo.getFileInformationLevel()).thenReturn(FileInformation.FILE_BASIC_INFO);

        // When & Then
        assertEquals(TEST_ATTRIBUTES, mockBasicFileInfo.getAttributes());
        assertEquals(TEST_CREATE_TIME, mockBasicFileInfo.getCreateTime());
        assertEquals(TEST_LAST_WRITE_TIME, mockBasicFileInfo.getLastWriteTime());
        assertEquals(TEST_LAST_ACCESS_TIME, mockBasicFileInfo.getLastAccessTime());
        assertEquals(1024L, mockBasicFileInfo.getSize());
        assertEquals(FileInformation.FILE_BASIC_INFO, mockBasicFileInfo.getFileInformationLevel());

        // Verify all methods were called
        verify(mockBasicFileInfo).getAttributes();
        verify(mockBasicFileInfo).getCreateTime();
        verify(mockBasicFileInfo).getLastWriteTime();
        verify(mockBasicFileInfo).getLastAccessTime();
        verify(mockBasicFileInfo).getSize();
        verify(mockBasicFileInfo).getFileInformationLevel();
    }

    @Test
    @DisplayName("Test FileBasicInfo default constructor")
    void testFileBasicInfoDefaultConstructor() {
        // Given
        FileBasicInfo info = new FileBasicInfo();

        // When & Then
        assertEquals(0, info.getAttributes());
        assertEquals(0L, info.getCreateTime());
        assertEquals(0L, info.getLastWriteTime());
        assertEquals(0L, info.getLastAccessTime());
        assertEquals(0L, info.getSize());
        assertEquals(FileInformation.FILE_BASIC_INFO, info.getFileInformationLevel());
    }

    @Test
    @DisplayName("Test FileBasicInfo parameterized constructor")
    void testFileBasicInfoParameterizedConstructor() {
        // Given & When
        FileBasicInfo info =
                new FileBasicInfo(TEST_CREATE_TIME, TEST_LAST_ACCESS_TIME, TEST_LAST_WRITE_TIME, TEST_CHANGE_TIME, TEST_ATTRIBUTES);

        // Then
        assertEquals(TEST_ATTRIBUTES, info.getAttributes());
        assertEquals(TEST_CREATE_TIME, info.getCreateTime());
        assertEquals(TEST_LAST_WRITE_TIME, info.getLastWriteTime());
        assertEquals(TEST_LAST_ACCESS_TIME, info.getLastAccessTime());
        assertEquals(0L, info.getSize()); // FileBasicInfo always returns 0 for size
        assertEquals(FileInformation.FILE_BASIC_INFO, info.getFileInformationLevel());
    }

    @Test
    @DisplayName("Test FileBasicInfo decode method")
    void testFileBasicInfoDecode() throws SMBProtocolDecodingException {
        // Given
        byte[] buffer = new byte[64];
        int bufferIndex = 8;

        // Prepare test data in buffer (40 bytes of data)
        // Use SMBUtil to properly encode times in Windows FILETIME format
        SMBUtil.writeTime(TEST_CREATE_TIME, buffer, bufferIndex);
        SMBUtil.writeTime(TEST_LAST_ACCESS_TIME, buffer, bufferIndex + 8);
        SMBUtil.writeTime(TEST_LAST_WRITE_TIME, buffer, bufferIndex + 16);
        SMBUtil.writeTime(TEST_CHANGE_TIME, buffer, bufferIndex + 24);
        SMBUtil.writeInt4(TEST_ATTRIBUTES, buffer, bufferIndex + 32);

        // When
        int bytesDecoded = fileBasicInfo.decode(buffer, bufferIndex, 40);

        // Then
        assertEquals(36, bytesDecoded); // Should decode 36 bytes
        assertEquals(TEST_CREATE_TIME, fileBasicInfo.getCreateTime());
        assertEquals(TEST_LAST_ACCESS_TIME, fileBasicInfo.getLastAccessTime());
        assertEquals(TEST_LAST_WRITE_TIME, fileBasicInfo.getLastWriteTime());
        assertEquals(TEST_ATTRIBUTES, fileBasicInfo.getAttributes());
    }

    @Test
    @DisplayName("Test FileBasicInfo encode method")
    void testFileBasicInfoEncode() {
        // Given
        FileBasicInfo info =
                new FileBasicInfo(TEST_CREATE_TIME, TEST_LAST_ACCESS_TIME, TEST_LAST_WRITE_TIME, TEST_CHANGE_TIME, TEST_ATTRIBUTES);
        byte[] buffer = new byte[64];
        int dstIndex = 8;

        // When
        int bytesEncoded = info.encode(buffer, dstIndex);

        // Then
        assertEquals(40, bytesEncoded); // Should encode 40 bytes
        // Use SMBUtil to read times back properly
        assertEquals(TEST_CREATE_TIME, SMBUtil.readTime(buffer, dstIndex));
        assertEquals(TEST_LAST_ACCESS_TIME, SMBUtil.readTime(buffer, dstIndex + 8));
        assertEquals(TEST_LAST_WRITE_TIME, SMBUtil.readTime(buffer, dstIndex + 16));
        assertEquals(TEST_CHANGE_TIME, SMBUtil.readTime(buffer, dstIndex + 24));
        assertEquals(TEST_ATTRIBUTES, SMBUtil.readInt4(buffer, dstIndex + 32));
    }

    @Test
    @DisplayName("Test FileBasicInfo size method")
    void testFileBasicInfoSize() {
        // Given
        FileBasicInfo info = new FileBasicInfo();

        // When & Then
        assertEquals(40, info.size());
    }

    @Test
    @DisplayName("Test FileBasicInfo toString method")
    void testFileBasicInfoToString() {
        // Given
        FileBasicInfo info =
                new FileBasicInfo(TEST_CREATE_TIME, TEST_LAST_ACCESS_TIME, TEST_LAST_WRITE_TIME, TEST_CHANGE_TIME, TEST_ATTRIBUTES);

        // When
        String result = info.toString();

        // Then
        assertNotNull(result);
        assertTrue(result.contains("SmbQueryFileBasicInfo"));
        assertTrue(result.contains("createTime="));
        assertTrue(result.contains("lastAccessTime="));
        assertTrue(result.contains("lastWriteTime="));
        assertTrue(result.contains("changeTime="));
        assertTrue(result.contains("attributes=0x"));
    }

    @Test
    @DisplayName("Test decode with minimum buffer size")
    void testDecodeWithMinimumBufferSize() throws SMBProtocolDecodingException {
        // Given
        byte[] buffer = new byte[36]; // Minimum required size
        int bufferIndex = 0;

        // Fill with test data using SMBUtil
        SMBUtil.writeTime(TEST_CREATE_TIME, buffer, bufferIndex);
        SMBUtil.writeTime(TEST_LAST_ACCESS_TIME, buffer, bufferIndex + 8);
        SMBUtil.writeTime(TEST_LAST_WRITE_TIME, buffer, bufferIndex + 16);
        SMBUtil.writeTime(TEST_CHANGE_TIME, buffer, bufferIndex + 24);
        SMBUtil.writeInt4(TEST_ATTRIBUTES, buffer, bufferIndex + 32);

        // When
        int bytesDecoded = fileBasicInfo.decode(buffer, bufferIndex, buffer.length);

        // Then
        assertEquals(36, bytesDecoded);
        assertEquals(TEST_CREATE_TIME, fileBasicInfo.getCreateTime());
        assertEquals(TEST_LAST_ACCESS_TIME, fileBasicInfo.getLastAccessTime());
        assertEquals(TEST_LAST_WRITE_TIME, fileBasicInfo.getLastWriteTime());
        assertEquals(TEST_ATTRIBUTES, fileBasicInfo.getAttributes());
    }

    @Test
    @DisplayName("Test encode and decode roundtrip")
    void testEncodeDecodeRoundtrip() throws SMBProtocolDecodingException {
        // Given
        FileBasicInfo originalInfo =
                new FileBasicInfo(TEST_CREATE_TIME, TEST_LAST_ACCESS_TIME, TEST_LAST_WRITE_TIME, TEST_CHANGE_TIME, TEST_ATTRIBUTES);
        byte[] buffer = new byte[64];

        // When - Encode
        int bytesEncoded = originalInfo.encode(buffer, 0);

        // When - Decode
        FileBasicInfo decodedInfo = new FileBasicInfo();
        int bytesDecoded = decodedInfo.decode(buffer, 0, bytesEncoded);

        // Then
        assertEquals(40, bytesEncoded);
        assertEquals(36, bytesDecoded); // decode returns 36, encode returns 40
        assertEquals(originalInfo.getCreateTime(), decodedInfo.getCreateTime());
        assertEquals(originalInfo.getLastAccessTime(), decodedInfo.getLastAccessTime());
        assertEquals(originalInfo.getLastWriteTime(), decodedInfo.getLastWriteTime());
        assertEquals(originalInfo.getAttributes(), decodedInfo.getAttributes());
    }

    @Test
    @DisplayName("Test with various attribute flags")
    void testWithVariousAttributeFlags() {
        // Test common file attribute combinations
        int[] attributeFlags = { 0x01, // FILE_ATTRIBUTE_READONLY
                0x02, // FILE_ATTRIBUTE_HIDDEN
                0x04, // FILE_ATTRIBUTE_SYSTEM
                0x10, // FILE_ATTRIBUTE_DIRECTORY
                0x20, // FILE_ATTRIBUTE_ARCHIVE
                0x80, // FILE_ATTRIBUTE_NORMAL
                0x100, // FILE_ATTRIBUTE_TEMPORARY
                0x21, // Combination: ARCHIVE | READONLY
                0x06 // Combination: HIDDEN | SYSTEM
        };

        for (int attributes : attributeFlags) {
            // Given
            FileBasicInfo info =
                    new FileBasicInfo(TEST_CREATE_TIME, TEST_LAST_ACCESS_TIME, TEST_LAST_WRITE_TIME, TEST_CHANGE_TIME, attributes);

            // When & Then
            assertEquals(attributes, info.getAttributes());
        }
    }

    @Test
    @DisplayName("Test with edge case time values")
    void testWithEdgeCaseTimeValues() {
        // Test with various time values including edge cases
        long[][] timeValues = { { 0L, 0L, 0L, 0L }, // All zeros
                { Long.MAX_VALUE, Long.MAX_VALUE, Long.MAX_VALUE, Long.MAX_VALUE }, // Max values
                { 1L, 2L, 3L, 4L }, // Small values
                { -1L, -2L, -3L, -4L } // Negative values (though unusual for file times)
        };

        for (long[] times : timeValues) {
            // Given
            FileBasicInfo info = new FileBasicInfo(times[0], // create time
                    times[1], // last access time
                    times[2], // last write time
                    times[3], // change time
                    TEST_ATTRIBUTES);

            // When & Then
            assertEquals(times[0], info.getCreateTime());
            assertEquals(times[1], info.getLastAccessTime());
            assertEquals(times[2], info.getLastWriteTime());
        }
    }

    @Test
    @DisplayName("Test custom implementation of BasicFileInformation")
    void testCustomImplementation() {
        // Given - Create a custom implementation
        BasicFileInformation customImpl = new BasicFileInformation() {
            @Override
            public int getAttributes() {
                return 0x123;
            }

            @Override
            public long getCreateTime() {
                return 999L;
            }

            @Override
            public long getLastWriteTime() {
                return 888L;
            }

            @Override
            public long getLastAccessTime() {
                return 777L;
            }

            @Override
            public long getSize() {
                return 666L;
            }

            @Override
            public byte getFileInformationLevel() {
                return FileInformation.FILE_STANDARD_INFO;
            }

            @Override
            public int decode(byte[] buffer, int bufferIndex, int len) {
                return 0;
            }

            @Override
            public int size() {
                return 100;
            }

            @Override
            public int encode(byte[] dst, int dstIndex) {
                return 0;
            }
        };

        // When & Then
        assertEquals(0x123, customImpl.getAttributes());
        assertEquals(999L, customImpl.getCreateTime());
        assertEquals(888L, customImpl.getLastWriteTime());
        assertEquals(777L, customImpl.getLastAccessTime());
        assertEquals(666L, customImpl.getSize());
        assertEquals(FileInformation.FILE_STANDARD_INFO, customImpl.getFileInformationLevel());
        assertEquals(100, customImpl.size());
    }

}

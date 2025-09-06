package org.codelibs.jcifs.smb.internal.fscc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.codelibs.jcifs.smb.internal.SMBProtocolDecodingException;
import org.codelibs.jcifs.smb.internal.util.SMBUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Test class for FileStandardInfo
 */
class FileStandardInfoTest {

    private FileStandardInfo fileStandardInfo;

    @BeforeEach
    void setUp() {
        fileStandardInfo = new FileStandardInfo();
    }

    @Test
    @DisplayName("Test getFileInformationLevel returns FILE_STANDARD_INFO")
    void testGetFileInformationLevel() {
        assertEquals(BasicFileInformation.FILE_STANDARD_INFO, fileStandardInfo.getFileInformationLevel());
    }

    @Test
    @DisplayName("Test getAttributes returns 0")
    void testGetAttributes() {
        assertEquals(0, fileStandardInfo.getAttributes());
    }

    @Test
    @DisplayName("Test getCreateTime returns 0")
    void testGetCreateTime() {
        assertEquals(0L, fileStandardInfo.getCreateTime());
    }

    @Test
    @DisplayName("Test getLastWriteTime returns 0")
    void testGetLastWriteTime() {
        assertEquals(0L, fileStandardInfo.getLastWriteTime());
    }

    @Test
    @DisplayName("Test getLastAccessTime returns 0")
    void testGetLastAccessTime() {
        assertEquals(0L, fileStandardInfo.getLastAccessTime());
    }

    @Test
    @DisplayName("Test getSize returns endOfFile value")
    void testGetSize() throws SMBProtocolDecodingException {
        // Prepare test data
        byte[] buffer = new byte[22];
        long expectedAllocationSize = 1024L;
        long expectedEndOfFile = 512L;
        int expectedNumberOfLinks = 3;
        boolean expectedDeletePending = true;
        boolean expectedDirectory = false;

        // Encode test data
        int offset = 0;
        SMBUtil.writeInt8(expectedAllocationSize, buffer, offset);
        offset += 8;
        SMBUtil.writeInt8(expectedEndOfFile, buffer, offset);
        offset += 8;
        SMBUtil.writeInt4(expectedNumberOfLinks, buffer, offset);
        offset += 4;
        buffer[offset++] = (byte) (expectedDeletePending ? 1 : 0);
        buffer[offset++] = (byte) (expectedDirectory ? 1 : 0);

        // Decode and verify
        fileStandardInfo.decode(buffer, 0, buffer.length);
        assertEquals(expectedEndOfFile, fileStandardInfo.getSize());
    }

    @Test
    @DisplayName("Test size method returns 22")
    void testSize() {
        assertEquals(22, fileStandardInfo.size());
    }

    @Test
    @DisplayName("Test decode with valid data")
    void testDecodeWithValidData() throws SMBProtocolDecodingException {
        // Prepare test data
        byte[] buffer = new byte[30]; // Extra space to test offset
        int bufferIndex = 5; // Start at offset 5
        long expectedAllocationSize = 2048L;
        long expectedEndOfFile = 1536L;
        int expectedNumberOfLinks = 5;
        boolean expectedDeletePending = true;
        boolean expectedDirectory = true;

        // Encode test data at offset
        int offset = bufferIndex;
        SMBUtil.writeInt8(expectedAllocationSize, buffer, offset);
        offset += 8;
        SMBUtil.writeInt8(expectedEndOfFile, buffer, offset);
        offset += 8;
        SMBUtil.writeInt4(expectedNumberOfLinks, buffer, offset);
        offset += 4;
        buffer[offset++] = (byte) 1; // deletePending = true
        buffer[offset++] = (byte) 1; // directory = true

        // Decode
        int bytesDecoded = fileStandardInfo.decode(buffer, bufferIndex, 22);

        // Verify
        assertEquals(22, bytesDecoded);
        assertEquals(expectedEndOfFile, fileStandardInfo.getSize());
    }

    @Test
    @DisplayName("Test decode with delete pending false and directory false")
    void testDecodeWithFalseFlags() throws SMBProtocolDecodingException {
        // Prepare test data
        byte[] buffer = new byte[22];
        long expectedAllocationSize = 4096L;
        long expectedEndOfFile = 3072L;
        int expectedNumberOfLinks = 1;
        boolean expectedDeletePending = false;
        boolean expectedDirectory = false;

        // Encode test data
        int offset = 0;
        SMBUtil.writeInt8(expectedAllocationSize, buffer, offset);
        offset += 8;
        SMBUtil.writeInt8(expectedEndOfFile, buffer, offset);
        offset += 8;
        SMBUtil.writeInt4(expectedNumberOfLinks, buffer, offset);
        offset += 4;
        buffer[offset++] = (byte) 0; // deletePending = false
        buffer[offset++] = (byte) 0; // directory = false

        // Decode
        int bytesDecoded = fileStandardInfo.decode(buffer, 0, buffer.length);

        // Verify
        assertEquals(22, bytesDecoded);
        assertEquals(expectedEndOfFile, fileStandardInfo.getSize());
    }

    @Test
    @DisplayName("Test decode with non-zero byte values for boolean flags")
    void testDecodeWithNonZeroByteValues() throws SMBProtocolDecodingException {
        // Prepare test data
        byte[] buffer = new byte[22];
        long expectedAllocationSize = 8192L;
        long expectedEndOfFile = 6144L;
        int expectedNumberOfLinks = 2;

        // Encode test data
        int offset = 0;
        SMBUtil.writeInt8(expectedAllocationSize, buffer, offset);
        offset += 8;
        SMBUtil.writeInt8(expectedEndOfFile, buffer, offset);
        offset += 8;
        SMBUtil.writeInt4(expectedNumberOfLinks, buffer, offset);
        offset += 4;
        buffer[offset++] = (byte) 0xFF; // Non-zero value for deletePending
        buffer[offset++] = (byte) 0x80; // Non-zero value for directory

        // Decode
        int bytesDecoded = fileStandardInfo.decode(buffer, 0, buffer.length);

        // Verify - non-zero values should be treated as true
        assertEquals(22, bytesDecoded);
        assertEquals(expectedEndOfFile, fileStandardInfo.getSize());
    }

    @Test
    @DisplayName("Test encode with various values")
    void testEncode() throws SMBProtocolDecodingException {
        // First decode to set internal state
        byte[] sourceBuffer = new byte[22];
        long expectedAllocationSize = 16384L;
        long expectedEndOfFile = 12288L;
        int expectedNumberOfLinks = 7;
        boolean expectedDeletePending = true;
        boolean expectedDirectory = false;

        // Encode source data
        int offset = 0;
        SMBUtil.writeInt8(expectedAllocationSize, sourceBuffer, offset);
        offset += 8;
        SMBUtil.writeInt8(expectedEndOfFile, sourceBuffer, offset);
        offset += 8;
        SMBUtil.writeInt4(expectedNumberOfLinks, sourceBuffer, offset);
        offset += 4;
        sourceBuffer[offset++] = (byte) 1; // deletePending = true
        sourceBuffer[offset++] = (byte) 0; // directory = false

        // Decode to set state
        fileStandardInfo.decode(sourceBuffer, 0, sourceBuffer.length);

        // Now test encode
        byte[] destinationBuffer = new byte[30]; // Extra space
        int dstIndex = 3; // Start at offset 3
        int bytesEncoded = fileStandardInfo.encode(destinationBuffer, dstIndex);

        // Verify
        assertEquals(22, bytesEncoded);

        // Verify encoded data
        assertEquals(expectedAllocationSize, SMBUtil.readInt8(destinationBuffer, dstIndex));
        assertEquals(expectedEndOfFile, SMBUtil.readInt8(destinationBuffer, dstIndex + 8));
        assertEquals(expectedNumberOfLinks, SMBUtil.readInt4(destinationBuffer, dstIndex + 16));
        assertEquals(1, destinationBuffer[dstIndex + 20]); // deletePending
        assertEquals(0, destinationBuffer[dstIndex + 21]); // directory
    }

    @Test
    @DisplayName("Test encode and decode roundtrip")
    void testEncodeDecodeRoundtrip() throws SMBProtocolDecodingException {
        // Setup first instance with test data
        byte[] originalBuffer = new byte[22];
        long expectedAllocationSize = 32768L;
        long expectedEndOfFile = 24576L;
        int expectedNumberOfLinks = 10;
        boolean expectedDeletePending = false;
        boolean expectedDirectory = true;

        // Encode original data
        int offset = 0;
        SMBUtil.writeInt8(expectedAllocationSize, originalBuffer, offset);
        offset += 8;
        SMBUtil.writeInt8(expectedEndOfFile, originalBuffer, offset);
        offset += 8;
        SMBUtil.writeInt4(expectedNumberOfLinks, originalBuffer, offset);
        offset += 4;
        originalBuffer[offset++] = (byte) 0; // deletePending = false
        originalBuffer[offset++] = (byte) 1; // directory = true

        // Decode into first instance
        FileStandardInfo firstInstance = new FileStandardInfo();
        firstInstance.decode(originalBuffer, 0, originalBuffer.length);

        // Encode from first instance
        byte[] encodedBuffer = new byte[22];
        firstInstance.encode(encodedBuffer, 0);

        // Decode into second instance
        FileStandardInfo secondInstance = new FileStandardInfo();
        secondInstance.decode(encodedBuffer, 0, encodedBuffer.length);

        // Verify both instances have same values
        assertEquals(firstInstance.getSize(), secondInstance.getSize());
        assertEquals(expectedEndOfFile, secondInstance.getSize());
    }

    @Test
    @DisplayName("Test toString method")
    void testToString() throws SMBProtocolDecodingException {
        // Setup test data
        byte[] buffer = new byte[22];
        long expectedAllocationSize = 65536L;
        long expectedEndOfFile = 49152L;
        int expectedNumberOfLinks = 15;
        boolean expectedDeletePending = true;
        boolean expectedDirectory = true;

        // Encode test data
        int offset = 0;
        SMBUtil.writeInt8(expectedAllocationSize, buffer, offset);
        offset += 8;
        SMBUtil.writeInt8(expectedEndOfFile, buffer, offset);
        offset += 8;
        SMBUtil.writeInt4(expectedNumberOfLinks, buffer, offset);
        offset += 4;
        buffer[offset++] = (byte) 1; // deletePending = true
        buffer[offset++] = (byte) 1; // directory = true

        // Decode
        fileStandardInfo.decode(buffer, 0, buffer.length);

        // Test toString
        String result = fileStandardInfo.toString();

        // Verify string contains expected values
        assertTrue(result.contains("SmbQueryInfoStandard"));
        assertTrue(result.contains("allocationSize=" + expectedAllocationSize));
        assertTrue(result.contains("endOfFile=" + expectedEndOfFile));
        assertTrue(result.contains("numberOfLinks=" + expectedNumberOfLinks));
        assertTrue(result.contains("deletePending=true"));
        assertTrue(result.contains("directory=true"));
    }

    @Test
    @DisplayName("Test decode with maximum values")
    void testDecodeWithMaxValues() throws SMBProtocolDecodingException {
        // Prepare test data with maximum values
        byte[] buffer = new byte[22];
        long maxLong = Long.MAX_VALUE;
        int maxInt = Integer.MAX_VALUE;

        // Encode test data
        int offset = 0;
        SMBUtil.writeInt8(maxLong, buffer, offset);
        offset += 8;
        SMBUtil.writeInt8(maxLong, buffer, offset);
        offset += 8;
        SMBUtil.writeInt4(maxInt, buffer, offset);
        offset += 4;
        buffer[offset++] = (byte) 0xFF;
        buffer[offset++] = (byte) 0xFF;

        // Decode
        int bytesDecoded = fileStandardInfo.decode(buffer, 0, buffer.length);

        // Verify
        assertEquals(22, bytesDecoded);
        assertEquals(maxLong, fileStandardInfo.getSize());
    }

    @Test
    @DisplayName("Test decode with minimum values")
    void testDecodeWithMinValues() throws SMBProtocolDecodingException {
        // Prepare test data with minimum values
        byte[] buffer = new byte[22];
        long minLong = 0L;
        int minInt = 0;

        // Encode test data
        int offset = 0;
        SMBUtil.writeInt8(minLong, buffer, offset);
        offset += 8;
        SMBUtil.writeInt8(minLong, buffer, offset);
        offset += 8;
        SMBUtil.writeInt4(minInt, buffer, offset);
        offset += 4;
        buffer[offset++] = (byte) 0;
        buffer[offset++] = (byte) 0;

        // Decode
        int bytesDecoded = fileStandardInfo.decode(buffer, 0, buffer.length);

        // Verify
        assertEquals(22, bytesDecoded);
        assertEquals(minLong, fileStandardInfo.getSize());
    }

    @Test
    @DisplayName("Test decode with negative values")
    void testDecodeWithNegativeValues() throws SMBProtocolDecodingException {
        // Prepare test data with negative values
        byte[] buffer = new byte[22];
        long negativeLong = -1L;
        int negativeInt = -1;

        // Encode test data
        int offset = 0;
        SMBUtil.writeInt8(negativeLong, buffer, offset);
        offset += 8;
        SMBUtil.writeInt8(negativeLong, buffer, offset);
        offset += 8;
        SMBUtil.writeInt4(negativeInt, buffer, offset);
        offset += 4;
        buffer[offset++] = (byte) 0;
        buffer[offset++] = (byte) 0;

        // Decode
        int bytesDecoded = fileStandardInfo.decode(buffer, 0, buffer.length);

        // Verify - negative values are valid in this context
        assertEquals(22, bytesDecoded);
        assertEquals(negativeLong, fileStandardInfo.getSize());
    }
}

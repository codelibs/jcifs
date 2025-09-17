package org.codelibs.jcifs.smb.internal.fscc;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.codelibs.jcifs.smb.internal.SMBProtocolDecodingException;
import org.codelibs.jcifs.smb.internal.util.SMBUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Test class for FileInternalInfo
 */
class FileInternalInfoTest {

    private FileInternalInfo fileInternalInfo;

    @BeforeEach
    void setUp() {
        fileInternalInfo = new FileInternalInfo();
    }

    @Test
    @DisplayName("Test getFileInformationLevel returns FILE_INTERNAL_INFO")
    void testGetFileInformationLevel() {
        assertEquals(FileInformation.FILE_INTERNAL_INFO, fileInternalInfo.getFileInformationLevel());
    }

    @Test
    @DisplayName("Test initial indexNumber value is 0")
    void testInitialIndexNumber() {
        assertEquals(0L, fileInternalInfo.getIndexNumber());
    }

    @Test
    @DisplayName("Test size method returns 8")
    void testSize() {
        assertEquals(8, fileInternalInfo.size());
    }

    @Test
    @DisplayName("Test decode with valid data")
    void testDecodeWithValidData() throws SMBProtocolDecodingException {
        // Prepare test data
        byte[] buffer = new byte[8];
        long expectedIndexNumber = 0x123456789ABCDEF0L;

        // Encode test data
        SMBUtil.writeInt8(expectedIndexNumber, buffer, 0);

        // Decode
        int bytesDecoded = fileInternalInfo.decode(buffer, 0, buffer.length);

        // Verify
        assertEquals(8, bytesDecoded);
        assertEquals(expectedIndexNumber, fileInternalInfo.getIndexNumber());
    }

    @Test
    @DisplayName("Test decode with buffer offset")
    void testDecodeWithBufferOffset() throws SMBProtocolDecodingException {
        // Prepare test data with offset
        byte[] buffer = new byte[20]; // Extra space to test offset
        int bufferIndex = 7; // Start at offset 7
        long expectedIndexNumber = 0xFEDCBA9876543210L;

        // Encode test data at offset
        SMBUtil.writeInt8(expectedIndexNumber, buffer, bufferIndex);

        // Decode
        int bytesDecoded = fileInternalInfo.decode(buffer, bufferIndex, 8);

        // Verify
        assertEquals(8, bytesDecoded);
        assertEquals(expectedIndexNumber, fileInternalInfo.getIndexNumber());
    }

    @Test
    @DisplayName("Test decode with zero index number")
    void testDecodeWithZeroIndexNumber() throws SMBProtocolDecodingException {
        // Prepare test data
        byte[] buffer = new byte[8];
        long expectedIndexNumber = 0L;

        // Encode test data
        SMBUtil.writeInt8(expectedIndexNumber, buffer, 0);

        // Decode
        int bytesDecoded = fileInternalInfo.decode(buffer, 0, buffer.length);

        // Verify
        assertEquals(8, bytesDecoded);
        assertEquals(expectedIndexNumber, fileInternalInfo.getIndexNumber());
    }

    @Test
    @DisplayName("Test decode with maximum index number")
    void testDecodeWithMaxIndexNumber() throws SMBProtocolDecodingException {
        // Prepare test data
        byte[] buffer = new byte[8];
        long expectedIndexNumber = Long.MAX_VALUE;

        // Encode test data
        SMBUtil.writeInt8(expectedIndexNumber, buffer, 0);

        // Decode
        int bytesDecoded = fileInternalInfo.decode(buffer, 0, buffer.length);

        // Verify
        assertEquals(8, bytesDecoded);
        assertEquals(expectedIndexNumber, fileInternalInfo.getIndexNumber());
    }

    @Test
    @DisplayName("Test decode with minimum index number")
    void testDecodeWithMinIndexNumber() throws SMBProtocolDecodingException {
        // Prepare test data
        byte[] buffer = new byte[8];
        long expectedIndexNumber = Long.MIN_VALUE;

        // Encode test data
        SMBUtil.writeInt8(expectedIndexNumber, buffer, 0);

        // Decode
        int bytesDecoded = fileInternalInfo.decode(buffer, 0, buffer.length);

        // Verify
        assertEquals(8, bytesDecoded);
        assertEquals(expectedIndexNumber, fileInternalInfo.getIndexNumber());
    }

    @Test
    @DisplayName("Test decode with negative index number")
    void testDecodeWithNegativeIndexNumber() throws SMBProtocolDecodingException {
        // Prepare test data
        byte[] buffer = new byte[8];
        long expectedIndexNumber = -1234567890L;

        // Encode test data
        SMBUtil.writeInt8(expectedIndexNumber, buffer, 0);

        // Decode
        int bytesDecoded = fileInternalInfo.decode(buffer, 0, buffer.length);

        // Verify
        assertEquals(8, bytesDecoded);
        assertEquals(expectedIndexNumber, fileInternalInfo.getIndexNumber());
    }

    @Test
    @DisplayName("Test encode with valid data")
    void testEncodeWithValidData() throws SMBProtocolDecodingException {
        // First decode to set internal state
        byte[] sourceBuffer = new byte[8];
        long expectedIndexNumber = 0x0123456789ABCDEFL;
        SMBUtil.writeInt8(expectedIndexNumber, sourceBuffer, 0);
        fileInternalInfo.decode(sourceBuffer, 0, sourceBuffer.length);

        // Now test encode
        byte[] destinationBuffer = new byte[8];
        int bytesEncoded = fileInternalInfo.encode(destinationBuffer, 0);

        // Verify
        assertEquals(8, bytesEncoded);
        assertEquals(expectedIndexNumber, SMBUtil.readInt8(destinationBuffer, 0));
    }

    @Test
    @DisplayName("Test encode with buffer offset")
    void testEncodeWithBufferOffset() throws SMBProtocolDecodingException {
        // First decode to set internal state
        byte[] sourceBuffer = new byte[8];
        long expectedIndexNumber = 0xAABBCCDDEEFF1122L;
        SMBUtil.writeInt8(expectedIndexNumber, sourceBuffer, 0);
        fileInternalInfo.decode(sourceBuffer, 0, sourceBuffer.length);

        // Now test encode with offset
        byte[] destinationBuffer = new byte[20]; // Extra space
        int dstIndex = 5; // Start at offset 5
        int bytesEncoded = fileInternalInfo.encode(destinationBuffer, dstIndex);

        // Verify
        assertEquals(8, bytesEncoded);
        assertEquals(expectedIndexNumber, SMBUtil.readInt8(destinationBuffer, dstIndex));

        // Verify surrounding bytes are untouched
        for (int i = 0; i < dstIndex; i++) {
            assertEquals(0, destinationBuffer[i]);
        }
        for (int i = dstIndex + 8; i < destinationBuffer.length; i++) {
            assertEquals(0, destinationBuffer[i]);
        }
    }

    @Test
    @DisplayName("Test encode and decode roundtrip")
    void testEncodeDecodeRoundtrip() throws SMBProtocolDecodingException {
        // Setup first instance with test data
        long expectedIndexNumber = 0x1122334455667788L;
        byte[] originalBuffer = new byte[8];
        SMBUtil.writeInt8(expectedIndexNumber, originalBuffer, 0);

        // Decode into first instance
        FileInternalInfo firstInstance = new FileInternalInfo();
        firstInstance.decode(originalBuffer, 0, originalBuffer.length);

        // Encode from first instance
        byte[] encodedBuffer = new byte[8];
        firstInstance.encode(encodedBuffer, 0);

        // Decode into second instance
        FileInternalInfo secondInstance = new FileInternalInfo();
        secondInstance.decode(encodedBuffer, 0, encodedBuffer.length);

        // Verify both instances have same values
        assertEquals(firstInstance.getIndexNumber(), secondInstance.getIndexNumber());
        assertEquals(expectedIndexNumber, secondInstance.getIndexNumber());
    }

    @Test
    @DisplayName("Test multiple decode operations")
    void testMultipleDecodeOperations() throws SMBProtocolDecodingException {
        // First decode
        byte[] buffer1 = new byte[8];
        long indexNumber1 = 0x1111111111111111L;
        SMBUtil.writeInt8(indexNumber1, buffer1, 0);
        fileInternalInfo.decode(buffer1, 0, buffer1.length);
        assertEquals(indexNumber1, fileInternalInfo.getIndexNumber());

        // Second decode - should overwrite previous value
        byte[] buffer2 = new byte[8];
        long indexNumber2 = 0x2222222222222222L;
        SMBUtil.writeInt8(indexNumber2, buffer2, 0);
        fileInternalInfo.decode(buffer2, 0, buffer2.length);
        assertEquals(indexNumber2, fileInternalInfo.getIndexNumber());

        // Third decode - should overwrite again
        byte[] buffer3 = new byte[8];
        long indexNumber3 = 0x3333333333333333L;
        SMBUtil.writeInt8(indexNumber3, buffer3, 0);
        fileInternalInfo.decode(buffer3, 0, buffer3.length);
        assertEquals(indexNumber3, fileInternalInfo.getIndexNumber());
    }

    @Test
    @DisplayName("Test toString method")
    void testToString() throws SMBProtocolDecodingException {
        // Setup test data
        byte[] buffer = new byte[8];
        long expectedIndexNumber = 0x9876543210ABCDEFL;
        SMBUtil.writeInt8(expectedIndexNumber, buffer, 0);

        // Decode
        fileInternalInfo.decode(buffer, 0, buffer.length);

        // Test toString
        String result = fileInternalInfo.toString();

        // Verify string contains expected components
        assertNotNull(result);
        assertTrue(result.contains("SmbQueryFileInternalInfo"));
        assertTrue(result.contains("indexNumber="));
        assertTrue(result.contains(String.valueOf(expectedIndexNumber)));
    }

    @Test
    @DisplayName("Test toString with zero index number")
    void testToStringWithZeroIndexNumber() {
        // Initial state should have indexNumber = 0
        String result = fileInternalInfo.toString();

        // Verify string contains expected components
        assertNotNull(result);
        assertTrue(result.contains("SmbQueryFileInternalInfo"));
        assertTrue(result.contains("indexNumber=0"));
    }

    @Test
    @DisplayName("Test toString with negative index number")
    void testToStringWithNegativeIndexNumber() throws SMBProtocolDecodingException {
        // Setup test data with negative value
        byte[] buffer = new byte[8];
        long expectedIndexNumber = -9999999999L;
        SMBUtil.writeInt8(expectedIndexNumber, buffer, 0);

        // Decode
        fileInternalInfo.decode(buffer, 0, buffer.length);

        // Test toString
        String result = fileInternalInfo.toString();

        // Verify string contains expected components
        assertNotNull(result);
        assertTrue(result.contains("SmbQueryFileInternalInfo"));
        assertTrue(result.contains("indexNumber=" + expectedIndexNumber));
    }

    @Test
    @DisplayName("Test decode ignores length parameter")
    void testDecodeIgnoresLengthParameter() throws SMBProtocolDecodingException {
        // The decode method should always read exactly 8 bytes regardless of len parameter
        byte[] buffer = new byte[20];
        long expectedIndexNumber = 0xCAFEBABEDEADBEEFL;
        SMBUtil.writeInt8(expectedIndexNumber, buffer, 0);

        // Decode with different length parameters
        int bytesDecoded1 = fileInternalInfo.decode(buffer, 0, 5); // Less than needed
        assertEquals(8, bytesDecoded1); // Should still return 8
        assertEquals(expectedIndexNumber, fileInternalInfo.getIndexNumber());

        FileInternalInfo info2 = new FileInternalInfo();
        int bytesDecoded2 = info2.decode(buffer, 0, 15); // More than needed
        assertEquals(8, bytesDecoded2); // Should still return 8
        assertEquals(expectedIndexNumber, info2.getIndexNumber());
    }

    @Test
    @DisplayName("Test encode with initial state")
    void testEncodeWithInitialState() {
        // Test encode without prior decode (initial state with indexNumber = 0)
        byte[] destinationBuffer = new byte[8];
        int bytesEncoded = fileInternalInfo.encode(destinationBuffer, 0);

        // Verify
        assertEquals(8, bytesEncoded);
        assertEquals(0L, SMBUtil.readInt8(destinationBuffer, 0));
    }

    @Test
    @DisplayName("Test boundary values for index number")
    void testBoundaryValuesForIndexNumber() throws SMBProtocolDecodingException {
        // Test various boundary values
        long[] testValues = { 0L, // Zero
                1L, // One
                -1L, // Negative one
                0x00000000FFFFFFFFL, // 32-bit max as long
                0xFFFFFFFF00000000L, // High 32 bits set
                0x7FFFFFFFFFFFFFFFL, // Long.MAX_VALUE
                0x8000000000000000L, // Long.MIN_VALUE
                0x0101010101010101L, // Repeating pattern
                0xFEFEFEFEFEFEFEFEL // Another pattern
        };

        for (long testValue : testValues) {
            FileInternalInfo testInfo = new FileInternalInfo();
            byte[] buffer = new byte[8];
            SMBUtil.writeInt8(testValue, buffer, 0);

            int bytesDecoded = testInfo.decode(buffer, 0, buffer.length);
            assertEquals(8, bytesDecoded);
            assertEquals(testValue, testInfo.getIndexNumber());

            // Test encode as well
            byte[] encodedBuffer = new byte[8];
            int bytesEncoded = testInfo.encode(encodedBuffer, 0);
            assertEquals(8, bytesEncoded);
            assertEquals(testValue, SMBUtil.readInt8(encodedBuffer, 0));
        }
    }
}

package jcifs.internal.smb2.ioctl;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import jcifs.internal.SMBProtocolDecodingException;
import jcifs.internal.util.SMBUtil;

/**
 * Test class for SrvPipePeekResponse
 * Tests the decoding of FSCTL_PIPE_PEEK response according to MS-FSCC 2.3.29
 */
class SrvPipePeekResponseTest {

    private SrvPipePeekResponse response;

    @BeforeEach
    void setUp() {
        response = new SrvPipePeekResponse();
    }

    @Test
    @DisplayName("Test successful decode with data")
    void testDecodeWithData() throws SMBProtocolDecodingException {
        // Prepare test data
        byte[] buffer = new byte[24]; // 16 bytes header + 8 bytes data
        int bufferIndex = 0;

        // Set up test values
        int namedPipeState = 0x03; // NP_NOWAIT | NP_READMODE_MESSAGE
        int readDataAvailable = 100;
        int numberOfMessages = 2;
        int messageLength = 50;
        byte[] testData = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };

        // Write values to buffer
        SMBUtil.writeInt4(namedPipeState, buffer, bufferIndex);
        SMBUtil.writeInt4(readDataAvailable, buffer, bufferIndex + 4);
        SMBUtil.writeInt4(numberOfMessages, buffer, bufferIndex + 8);
        SMBUtil.writeInt4(messageLength, buffer, bufferIndex + 12);
        System.arraycopy(testData, 0, buffer, bufferIndex + 16, testData.length);

        // Decode
        int bytesDecoded = response.decode(buffer, bufferIndex, buffer.length);

        // Verify results
        assertEquals(namedPipeState, response.getNamedPipeState());
        assertEquals(readDataAvailable, response.getReadDataAvailable());
        assertEquals(numberOfMessages, response.getNumberOfMessages());
        assertEquals(messageLength, response.getMessageLength());
        assertArrayEquals(testData, response.getData());
        // The decode method returns only the header size (16 bytes)\n        assertEquals(16, bytesDecoded);
    }

    @Test
    @DisplayName("Test decode without data")
    void testDecodeWithoutData() throws SMBProtocolDecodingException {
        // Prepare test data - only header, no data
        byte[] buffer = new byte[16];
        int bufferIndex = 0;

        // Set up test values
        int namedPipeState = 0x01;
        int readDataAvailable = 0;
        int numberOfMessages = 0;
        int messageLength = 0;

        // Write values to buffer
        SMBUtil.writeInt4(namedPipeState, buffer, bufferIndex);
        SMBUtil.writeInt4(readDataAvailable, buffer, bufferIndex + 4);
        SMBUtil.writeInt4(numberOfMessages, buffer, bufferIndex + 8);
        SMBUtil.writeInt4(messageLength, buffer, bufferIndex + 12);

        // Decode
        int bytesDecoded = response.decode(buffer, bufferIndex, buffer.length);

        // Verify results
        assertEquals(namedPipeState, response.getNamedPipeState());
        assertEquals(readDataAvailable, response.getReadDataAvailable());
        assertEquals(numberOfMessages, response.getNumberOfMessages());
        assertEquals(messageLength, response.getMessageLength());
        assertNotNull(response.getData());
        assertEquals(0, response.getData().length);
        // The decode method returns only the header size (16 bytes)\n        assertEquals(16, bytesDecoded);
    }

    @Test
    @DisplayName("Test decode with non-zero buffer index")
    void testDecodeWithNonZeroBufferIndex() throws SMBProtocolDecodingException {
        // Prepare test data with offset
        int offset = 10;
        byte[] buffer = new byte[34]; // 10 offset + 16 header + 8 data
        int bufferIndex = offset;

        // Set up test values
        int namedPipeState = 0x02;
        int readDataAvailable = 256;
        int numberOfMessages = 5;
        int messageLength = 128;
        byte[] testData = { (byte) 0xFF, (byte) 0xEE, (byte) 0xDD, (byte) 0xCC, (byte) 0xBB, (byte) 0xAA, (byte) 0x99, (byte) 0x88 };

        // Write values to buffer at offset
        SMBUtil.writeInt4(namedPipeState, buffer, bufferIndex);
        SMBUtil.writeInt4(readDataAvailable, buffer, bufferIndex + 4);
        SMBUtil.writeInt4(numberOfMessages, buffer, bufferIndex + 8);
        SMBUtil.writeInt4(messageLength, buffer, bufferIndex + 12);
        System.arraycopy(testData, 0, buffer, bufferIndex + 16, testData.length);

        // Decode
        int bytesDecoded = response.decode(buffer, bufferIndex, 24);

        // Verify results
        assertEquals(namedPipeState, response.getNamedPipeState());
        assertEquals(readDataAvailable, response.getReadDataAvailable());
        assertEquals(numberOfMessages, response.getNumberOfMessages());
        assertEquals(messageLength, response.getMessageLength());
        assertArrayEquals(testData, response.getData());
        // The decode method returns only the header size (16 bytes)
        assertEquals(16, bytesDecoded);
    }

    @Test
    @DisplayName("Test decode with maximum values")
    void testDecodeWithMaxValues() throws SMBProtocolDecodingException {
        // Prepare test data with max values
        byte[] buffer = new byte[20]; // 16 header + 4 data
        int bufferIndex = 0;

        // Set up max values
        int namedPipeState = Integer.MAX_VALUE;
        int readDataAvailable = Integer.MAX_VALUE;
        int numberOfMessages = Integer.MAX_VALUE;
        int messageLength = Integer.MAX_VALUE;
        byte[] testData = { 0x7F, 0x7F, 0x7F, 0x7F };

        // Write values to buffer
        SMBUtil.writeInt4(namedPipeState, buffer, bufferIndex);
        SMBUtil.writeInt4(readDataAvailable, buffer, bufferIndex + 4);
        SMBUtil.writeInt4(numberOfMessages, buffer, bufferIndex + 8);
        SMBUtil.writeInt4(messageLength, buffer, bufferIndex + 12);
        System.arraycopy(testData, 0, buffer, bufferIndex + 16, testData.length);

        // Decode
        int bytesDecoded = response.decode(buffer, bufferIndex, buffer.length);

        // Verify results
        assertEquals(namedPipeState, response.getNamedPipeState());
        assertEquals(readDataAvailable, response.getReadDataAvailable());
        assertEquals(numberOfMessages, response.getNumberOfMessages());
        assertEquals(messageLength, response.getMessageLength());
        assertArrayEquals(testData, response.getData());
        // The decode method returns only the header size (16 bytes)\n        assertEquals(16, bytesDecoded);
    }

    @Test
    @DisplayName("Test decode with negative values")
    void testDecodeWithNegativeValues() throws SMBProtocolDecodingException {
        // Prepare test data with negative values (when interpreted as signed)
        byte[] buffer = new byte[16];
        int bufferIndex = 0;

        // Set up negative values
        int namedPipeState = -1;
        int readDataAvailable = -100;
        int numberOfMessages = -200;
        int messageLength = -300;

        // Write values to buffer
        SMBUtil.writeInt4(namedPipeState, buffer, bufferIndex);
        SMBUtil.writeInt4(readDataAvailable, buffer, bufferIndex + 4);
        SMBUtil.writeInt4(numberOfMessages, buffer, bufferIndex + 8);
        SMBUtil.writeInt4(messageLength, buffer, bufferIndex + 12);

        // Decode
        int bytesDecoded = response.decode(buffer, bufferIndex, buffer.length);

        // Verify results - values should be preserved as-is
        assertEquals(namedPipeState, response.getNamedPipeState());
        assertEquals(readDataAvailable, response.getReadDataAvailable());
        assertEquals(numberOfMessages, response.getNumberOfMessages());
        assertEquals(messageLength, response.getMessageLength());
        assertNotNull(response.getData());
        assertEquals(0, response.getData().length);
        // The decode method returns only the header size (16 bytes)\n        assertEquals(16, bytesDecoded);
    }

    @Test
    @DisplayName("Test decode with large data payload")
    void testDecodeWithLargeData() throws SMBProtocolDecodingException {
        // Prepare test data with large data section
        int dataSize = 1024;
        byte[] buffer = new byte[16 + dataSize];
        int bufferIndex = 0;

        // Set up test values
        int namedPipeState = 0x03;
        int readDataAvailable = dataSize;
        int numberOfMessages = 10;
        int messageLength = 100;

        // Create test data pattern
        byte[] testData = new byte[dataSize];
        for (int i = 0; i < dataSize; i++) {
            testData[i] = (byte) (i % 256);
        }

        // Write values to buffer
        SMBUtil.writeInt4(namedPipeState, buffer, bufferIndex);
        SMBUtil.writeInt4(readDataAvailable, buffer, bufferIndex + 4);
        SMBUtil.writeInt4(numberOfMessages, buffer, bufferIndex + 8);
        SMBUtil.writeInt4(messageLength, buffer, bufferIndex + 12);
        System.arraycopy(testData, 0, buffer, bufferIndex + 16, testData.length);

        // Decode
        int bytesDecoded = response.decode(buffer, bufferIndex, buffer.length);

        // Verify results
        assertEquals(namedPipeState, response.getNamedPipeState());
        assertEquals(readDataAvailable, response.getReadDataAvailable());
        assertEquals(numberOfMessages, response.getNumberOfMessages());
        assertEquals(messageLength, response.getMessageLength());
        assertArrayEquals(testData, response.getData());
        // The decode method returns only the header size (16 bytes)\n        assertEquals(16, bytesDecoded);
    }

    @Test
    @DisplayName("Test getters return initial null/zero values")
    void testInitialGetterValues() {
        // Create fresh instance
        SrvPipePeekResponse freshResponse = new SrvPipePeekResponse();

        // Verify initial state
        assertEquals(0, freshResponse.getNamedPipeState());
        assertEquals(0, freshResponse.getReadDataAvailable());
        assertEquals(0, freshResponse.getNumberOfMessages());
        assertEquals(0, freshResponse.getMessageLength());
        assertNull(freshResponse.getData());
    }

    @Test
    @DisplayName("Test decode with exact 16 byte header")
    void testDecodeExact16ByteHeader() throws SMBProtocolDecodingException {
        // Prepare exact 16 byte buffer
        byte[] buffer = new byte[16];

        // Set simple values
        SMBUtil.writeInt4(1, buffer, 0);
        SMBUtil.writeInt4(2, buffer, 4);
        SMBUtil.writeInt4(3, buffer, 8);
        SMBUtil.writeInt4(4, buffer, 12);

        // Decode
        int bytesDecoded = response.decode(buffer, 0, 16);

        // Verify
        assertEquals(1, response.getNamedPipeState());
        assertEquals(2, response.getReadDataAvailable());
        assertEquals(3, response.getNumberOfMessages());
        assertEquals(4, response.getMessageLength());
        assertEquals(0, response.getData().length);
        assertEquals(16, bytesDecoded);
    }

    @Test
    @DisplayName("Test decode preserves data integrity")
    void testDecodeDataIntegrity() throws SMBProtocolDecodingException {
        // Prepare buffer with specific pattern
        byte[] buffer = new byte[32];
        byte[] expectedData = new byte[16];

        // Fill data section with pattern
        for (int i = 0; i < 16; i++) {
            expectedData[i] = (byte) (0xA0 + i);
            buffer[16 + i] = expectedData[i];
        }

        // Set header values
        SMBUtil.writeInt4(0x100, buffer, 0);
        SMBUtil.writeInt4(0x200, buffer, 4);
        SMBUtil.writeInt4(0x300, buffer, 8);
        SMBUtil.writeInt4(0x400, buffer, 12);

        // Decode
        response.decode(buffer, 0, 32);

        // Verify data integrity
        byte[] actualData = response.getData();
        assertEquals(16, actualData.length);
        for (int i = 0; i < 16; i++) {
            assertEquals(expectedData[i], actualData[i], "Data mismatch at index " + i);
        }
    }
}

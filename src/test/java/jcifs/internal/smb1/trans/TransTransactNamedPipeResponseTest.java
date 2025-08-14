package jcifs.internal.smb1.trans;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.Arrays;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import jcifs.Configuration;
import jcifs.internal.SMBProtocolDecodingException;

/**
 * Test class for TransTransactNamedPipeResponse
 */
class TransTransactNamedPipeResponseTest {

    @Mock
    private Configuration mockConfig;

    private TransTransactNamedPipeResponse response;
    private byte[] outputBuffer;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        outputBuffer = new byte[1024];
        response = new TransTransactNamedPipeResponse(mockConfig, outputBuffer);
    }

    @Test
    void testConstructor() {
        // Verify that the response is created with correct configuration and buffer
        assertNotNull(response);

        // Use reflection to verify the outputBuffer is set correctly
        try {
            Field outputBufferField = TransTransactNamedPipeResponse.class.getDeclaredField("outputBuffer");
            outputBufferField.setAccessible(true);
            byte[] actualBuffer = (byte[]) outputBufferField.get(response);
            assertSame(outputBuffer, actualBuffer);
        } catch (Exception e) {
            fail("Failed to access outputBuffer field: " + e.getMessage());
        }
    }

    @Test
    void testWriteSetupWireFormat() {
        // Test that writeSetupWireFormat returns 0
        byte[] dst = new byte[100];
        int result = response.writeSetupWireFormat(dst, 10);
        assertEquals(0, result);
    }

    @Test
    void testWriteParametersWireFormat() {
        // Test that writeParametersWireFormat returns 0
        byte[] dst = new byte[100];
        int result = response.writeParametersWireFormat(dst, 20);
        assertEquals(0, result);
    }

    @Test
    void testWriteDataWireFormat() {
        // Test that writeDataWireFormat returns 0
        byte[] dst = new byte[100];
        int result = response.writeDataWireFormat(dst, 30);
        assertEquals(0, result);
    }

    @Test
    void testReadSetupWireFormat() {
        // Test that readSetupWireFormat returns 0
        byte[] buffer = new byte[100];
        int result = response.readSetupWireFormat(buffer, 10, 50);
        assertEquals(0, result);
    }

    @Test
    void testReadParametersWireFormat() {
        // Test that readParametersWireFormat returns 0
        byte[] buffer = new byte[100];
        int result = response.readParametersWireFormat(buffer, 20, 60);
        assertEquals(0, result);
    }

    @Test
    void testReadDataWireFormatSuccess() throws SMBProtocolDecodingException {
        // Test successful data read
        byte[] testData = "Test data for named pipe".getBytes();
        byte[] buffer = new byte[100];
        System.arraycopy(testData, 0, buffer, 10, testData.length);

        int result = response.readDataWireFormat(buffer, 10, testData.length);

        assertEquals(testData.length, result);
        // Verify data was copied to outputBuffer
        byte[] expectedData = new byte[testData.length];
        System.arraycopy(outputBuffer, 0, expectedData, 0, testData.length);
        assertArrayEquals(testData, expectedData);
    }

    @Test
    void testReadDataWireFormatExceedsBuffer() {
        // Test when data length exceeds outputBuffer size
        byte[] buffer = new byte[2000];
        int dataLen = outputBuffer.length + 100; // Exceeds outputBuffer size

        SMBProtocolDecodingException exception =
                assertThrows(SMBProtocolDecodingException.class, () -> response.readDataWireFormat(buffer, 0, dataLen));

        assertEquals("Payload exceeds buffer size", exception.getMessage());
    }

    @ParameterizedTest
    @ValueSource(ints = { 0, 1, 10, 100, 500, 1024 })
    void testReadDataWireFormatVariousSizes(int dataSize) throws SMBProtocolDecodingException {
        // Test with various data sizes within buffer limit
        byte[] testData = new byte[dataSize];
        Arrays.fill(testData, (byte) 0xAB);
        byte[] buffer = new byte[dataSize + 100];
        System.arraycopy(testData, 0, buffer, 20, dataSize);

        int result = response.readDataWireFormat(buffer, 20, dataSize);

        assertEquals(dataSize, result);
        // Verify correct data was copied
        for (int i = 0; i < dataSize; i++) {
            assertEquals((byte) 0xAB, outputBuffer[i]);
        }
    }

    @Test
    void testReadDataWireFormatZeroLength() throws SMBProtocolDecodingException {
        // Test with zero-length data
        byte[] buffer = new byte[100];
        int result = response.readDataWireFormat(buffer, 50, 0);
        assertEquals(0, result);
    }

    @Test
    void testReadDataWireFormatAtBufferBoundary() throws SMBProtocolDecodingException {
        // Test with data length exactly matching outputBuffer size
        byte[] testData = new byte[outputBuffer.length];
        Arrays.fill(testData, (byte) 0xFF);
        byte[] buffer = new byte[outputBuffer.length + 100];
        System.arraycopy(testData, 0, buffer, 0, outputBuffer.length);

        int result = response.readDataWireFormat(buffer, 0, outputBuffer.length);

        assertEquals(outputBuffer.length, result);
        assertArrayEquals(testData, outputBuffer);
    }

    @Test
    void testToString() {
        // Test toString method
        String result = response.toString();
        assertNotNull(result);
        assertTrue(result.startsWith("TransTransactNamedPipeResponse["));
        assertTrue(result.endsWith("]"));
    }

    @Test
    void testGetResponseLength() throws Exception {
        // Test getResponseLength method
        // First, set dataCount using reflection (since setDataCount is in parent class)
        Method setDataCountMethod = SmbComTransactionResponse.class.getDeclaredMethod("setDataCount", int.class);
        setDataCountMethod.setAccessible(true);
        setDataCountMethod.invoke(response, 256);

        int responseLength = response.getResponseLength();
        assertEquals(256, responseLength);
    }

    @Test
    void testGetResponseLengthZero() {
        // Test getResponseLength when dataCount is zero (default)
        int responseLength = response.getResponseLength();
        assertEquals(0, responseLength);
    }

    @Test
    void testMultipleReadDataWireFormatCalls() throws SMBProtocolDecodingException {
        // Test multiple calls to readDataWireFormat to ensure buffer is overwritten
        byte[] firstData = "First data set".getBytes();
        byte[] secondData = "Second data set".getBytes();
        byte[] buffer1 = new byte[100];
        byte[] buffer2 = new byte[100];

        System.arraycopy(firstData, 0, buffer1, 0, firstData.length);
        System.arraycopy(secondData, 0, buffer2, 0, secondData.length);

        // First read
        response.readDataWireFormat(buffer1, 0, firstData.length);
        byte[] firstResult = new byte[firstData.length];
        System.arraycopy(outputBuffer, 0, firstResult, 0, firstData.length);
        assertArrayEquals(firstData, firstResult);

        // Second read (should overwrite)
        response.readDataWireFormat(buffer2, 0, secondData.length);
        byte[] secondResult = new byte[secondData.length];
        System.arraycopy(outputBuffer, 0, secondResult, 0, secondData.length);
        assertArrayEquals(secondData, secondResult);
    }

    @Test
    void testReadDataWireFormatWithOffset() throws SMBProtocolDecodingException {
        // Test reading data from different buffer offsets
        byte[] testData = "Test data with offset".getBytes();
        byte[] buffer = new byte[200];
        int offset = 50;
        System.arraycopy(testData, 0, buffer, offset, testData.length);

        int result = response.readDataWireFormat(buffer, offset, testData.length);

        assertEquals(testData.length, result);
        byte[] actualData = new byte[testData.length];
        System.arraycopy(outputBuffer, 0, actualData, 0, testData.length);
        assertArrayEquals(testData, actualData);
    }

    @Test
    void testReadDataWireFormatNullOutputBuffer() {
        // Test behavior when outputBuffer is null (edge case)
        TransTransactNamedPipeResponse nullBufferResponse = new TransTransactNamedPipeResponse(mockConfig, null);
        byte[] buffer = new byte[100];

        assertThrows(NullPointerException.class, () -> nullBufferResponse.readDataWireFormat(buffer, 0, 50));
    }

    @Test
    void testReadDataWireFormatEmptyOutputBuffer() throws SMBProtocolDecodingException {
        // Test with empty outputBuffer
        TransTransactNamedPipeResponse emptyBufferResponse = new TransTransactNamedPipeResponse(mockConfig, new byte[0]);
        byte[] buffer = new byte[100];

        // Should work with zero length
        int result = emptyBufferResponse.readDataWireFormat(buffer, 0, 0);
        assertEquals(0, result);

        // Should throw exception with non-zero length
        assertThrows(SMBProtocolDecodingException.class, () -> emptyBufferResponse.readDataWireFormat(buffer, 0, 1));
    }
}

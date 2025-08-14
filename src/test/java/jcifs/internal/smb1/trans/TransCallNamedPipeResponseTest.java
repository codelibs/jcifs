package jcifs.internal.smb1.trans;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Field;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import jcifs.Configuration;
import jcifs.internal.SMBProtocolDecodingException;

/**
 * Test class for TransCallNamedPipeResponse
 */
class TransCallNamedPipeResponseTest {

    @Mock
    private Configuration mockConfig;

    private TransCallNamedPipeResponse response;
    private byte[] outputBuffer;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        outputBuffer = new byte[1024];
        response = new TransCallNamedPipeResponse(mockConfig, outputBuffer);
    }

    @Test
    void testConstructor() {
        assertNotNull(response);
        // Verify that the outputBuffer is stored properly
        byte[] testData = new byte[] { 1, 2, 3, 4, 5 };
        TransCallNamedPipeResponse testResponse = new TransCallNamedPipeResponse(mockConfig, testData);
        assertNotNull(testResponse);
    }

    @Test
    void testWriteSetupWireFormat() {
        byte[] dst = new byte[100];
        int result = response.writeSetupWireFormat(dst, 0);
        assertEquals(0, result);
    }

    @Test
    void testWriteParametersWireFormat() {
        byte[] dst = new byte[100];
        int result = response.writeParametersWireFormat(dst, 0);
        assertEquals(0, result);
    }

    @Test
    void testWriteDataWireFormat() {
        byte[] dst = new byte[100];
        int result = response.writeDataWireFormat(dst, 0);
        assertEquals(0, result);
    }

    @Test
    void testReadSetupWireFormat() {
        byte[] buffer = new byte[100];
        int result = response.readSetupWireFormat(buffer, 0, 100);
        assertEquals(0, result);
    }

    @Test
    void testReadParametersWireFormat() {
        byte[] buffer = new byte[100];
        int result = response.readParametersWireFormat(buffer, 0, 100);
        assertEquals(0, result);
    }

    @Test
    void testReadDataWireFormatWithValidLength() throws SMBProtocolDecodingException {
        // Prepare test data
        byte[] sourceData = { 10, 20, 30, 40, 50 };
        byte[] buffer = new byte[100];
        System.arraycopy(sourceData, 0, buffer, 10, sourceData.length);

        // Execute
        int result = response.readDataWireFormat(buffer, 10, sourceData.length);

        // Verify
        assertEquals(sourceData.length, result);
        // Check that data was copied to output buffer
        for (int i = 0; i < sourceData.length; i++) {
            assertEquals(sourceData[i], outputBuffer[i]);
        }
    }

    @Test
    void testReadDataWireFormatWithEmptyData() throws SMBProtocolDecodingException {
        byte[] buffer = new byte[100];
        int result = response.readDataWireFormat(buffer, 0, 0);
        assertEquals(0, result);
    }

    @Test
    void testReadDataWireFormatAtBufferBoundary() throws SMBProtocolDecodingException {
        // Test with data exactly matching output buffer size
        byte[] smallOutputBuffer = new byte[5];
        TransCallNamedPipeResponse smallResponse = new TransCallNamedPipeResponse(mockConfig, smallOutputBuffer);

        byte[] sourceData = { 1, 2, 3, 4, 5 };
        byte[] buffer = new byte[10];
        System.arraycopy(sourceData, 0, buffer, 2, sourceData.length);

        int result = smallResponse.readDataWireFormat(buffer, 2, sourceData.length);

        assertEquals(sourceData.length, result);
        assertArrayEquals(sourceData, smallOutputBuffer);
    }

    @Test
    void testReadDataWireFormatExceedsBufferSize() {
        // Create a response with small output buffer
        byte[] smallOutputBuffer = new byte[5];
        TransCallNamedPipeResponse smallResponse = new TransCallNamedPipeResponse(mockConfig, smallOutputBuffer);

        byte[] buffer = new byte[100];

        // Try to read more data than output buffer can hold
        SMBProtocolDecodingException exception =
                assertThrows(SMBProtocolDecodingException.class, () -> smallResponse.readDataWireFormat(buffer, 0, 10));

        assertEquals("Payload exceeds buffer size", exception.getMessage());
    }

    @ParameterizedTest
    @ValueSource(ints = { 1, 10, 100, 500, 1024 })
    void testReadDataWireFormatWithVariousSizes(int dataSize) throws SMBProtocolDecodingException {
        if (dataSize > outputBuffer.length) {
            return; // Skip sizes larger than buffer
        }

        byte[] sourceData = new byte[dataSize];
        for (int i = 0; i < dataSize; i++) {
            sourceData[i] = (byte) (i % 256);
        }

        byte[] buffer = new byte[dataSize + 50];
        System.arraycopy(sourceData, 0, buffer, 10, dataSize);

        int result = response.readDataWireFormat(buffer, 10, dataSize);

        assertEquals(dataSize, result);
        for (int i = 0; i < dataSize; i++) {
            assertEquals(sourceData[i], outputBuffer[i]);
        }
    }

    @Test
    void testToString() {
        String result = response.toString();
        assertNotNull(result);
        assertTrue(result.startsWith("TransCallNamedPipeResponse["));
        assertTrue(result.endsWith("]"));
    }

    @Test
    void testGetResponseLength() throws Exception {
        // Use reflection to set dataCount
        Field dataCountField = SmbComTransactionResponse.class.getDeclaredField("dataCount");
        dataCountField.setAccessible(true);
        dataCountField.setInt(response, 42);

        assertEquals(42, response.getResponseLength());
    }

    @Test
    void testGetResponseLengthWithZeroDataCount() {
        assertEquals(0, response.getResponseLength());
    }

    @Test
    void testMultipleReads() throws SMBProtocolDecodingException {
        // First read
        byte[] firstData = { 1, 2, 3 };
        byte[] buffer1 = new byte[10];
        System.arraycopy(firstData, 0, buffer1, 0, firstData.length);
        response.readDataWireFormat(buffer1, 0, firstData.length);

        // Verify first data
        for (int i = 0; i < firstData.length; i++) {
            assertEquals(firstData[i], outputBuffer[i]);
        }

        // Second read (should overwrite)
        byte[] secondData = { 10, 20, 30, 40 };
        byte[] buffer2 = new byte[10];
        System.arraycopy(secondData, 0, buffer2, 0, secondData.length);
        response.readDataWireFormat(buffer2, 0, secondData.length);

        // Verify second data overwrote first
        for (int i = 0; i < secondData.length; i++) {
            assertEquals(secondData[i], outputBuffer[i]);
        }
    }

    @Test
    void testReadDataWireFormatWithDifferentOffsets() throws SMBProtocolDecodingException {
        byte[] sourceData = { 11, 22, 33, 44, 55 };
        byte[] buffer = new byte[50];

        // Test with offset at beginning
        System.arraycopy(sourceData, 0, buffer, 0, sourceData.length);
        int result1 = response.readDataWireFormat(buffer, 0, sourceData.length);
        assertEquals(sourceData.length, result1);

        // Test with offset in middle
        byte[] outputBuffer2 = new byte[1024];
        TransCallNamedPipeResponse response2 = new TransCallNamedPipeResponse(mockConfig, outputBuffer2);
        System.arraycopy(sourceData, 0, buffer, 20, sourceData.length);
        int result2 = response2.readDataWireFormat(buffer, 20, sourceData.length);
        assertEquals(sourceData.length, result2);

        // Test with offset near end
        byte[] outputBuffer3 = new byte[1024];
        TransCallNamedPipeResponse response3 = new TransCallNamedPipeResponse(mockConfig, outputBuffer3);
        System.arraycopy(sourceData, 0, buffer, 45, sourceData.length);
        int result3 = response3.readDataWireFormat(buffer, 45, sourceData.length);
        assertEquals(sourceData.length, result3);
    }

    @Test
    void testConstructorWithNullBuffer() {
        // This should not throw an exception
        TransCallNamedPipeResponse nullBufferResponse = new TransCallNamedPipeResponse(mockConfig, null);
        assertNotNull(nullBufferResponse);

        // But trying to read data should cause NullPointerException
        byte[] buffer = new byte[10];
        assertThrows(NullPointerException.class, () -> nullBufferResponse.readDataWireFormat(buffer, 0, 5));
    }

    @Test
    void testReadDataWireFormatWithNegativeLength() {
        byte[] buffer = new byte[100];
        // Negative length should cause ArrayIndexOutOfBoundsException from System.arraycopy
        assertThrows(ArrayIndexOutOfBoundsException.class, () -> response.readDataWireFormat(buffer, 0, -1));
    }
}

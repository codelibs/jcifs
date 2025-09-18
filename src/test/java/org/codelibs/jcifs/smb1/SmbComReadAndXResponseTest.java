package org.codelibs.jcifs.smb1;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

/**
 * Unit tests for the {@link SmbComReadAndXResponse} class.
 */
public class SmbComReadAndXResponseTest {

    private SmbComReadAndXResponse response;

    @BeforeEach
    public void setUp() {
        response = new SmbComReadAndXResponse();
    }

    @Test
    @DisplayName("Constructor should create non-null instance")
    public void constructorShouldCreateNonNullInstance() {
        assertNotNull(response);
    }

    @Test
    @DisplayName("Constructor with parameters should set buffer and offset")
    public void constructorWithParametersShouldSetBufferAndOffset() {
        byte[] b = new byte[0];
        response = new SmbComReadAndXResponse(b, 0);
        assertNotNull(response);
        assertEquals(b, response.b);
        assertEquals(0, response.off);
    }

    @Test
    @DisplayName("setParam should update buffer and offset")
    public void setParamShouldUpdateBufferAndOffset() {
        byte[] b = new byte[0];
        response.setParam(b, 0);
        assertEquals(b, response.b);
        assertEquals(0, response.off);
    }

    @Test
    @DisplayName("writeParameterWordsWireFormat should return zero")
    public void writeParameterWordsWireFormatShouldReturnZero() {
        assertEquals(0, response.writeParameterWordsWireFormat(new byte[0], 0));
    }

    @Test
    @DisplayName("writeBytesWireFormat should return zero")
    public void writeBytesWireFormatShouldReturnZero() {
        assertEquals(0, response.writeBytesWireFormat(new byte[0], 0));
    }

    @Test
    @DisplayName("readBytesWireFormat should return zero")
    public void readBytesWireFormatShouldReturnZero() {
        assertEquals(0, response.readBytesWireFormat(new byte[0], 0));
    }

    @Nested
    class WhenReadingParameterWordsWireFormat {

        private final byte[] buffer = new byte[20];
        private final int dataCompactionMode = 1;
        private final int dataLength = 1024;
        private final int dataOffset = 54;

        @BeforeEach
        public void setUp() {
            // Build a sample buffer
            int bufferIndex = 0;
            bufferIndex += 2; // reserved
            writeInt2(dataCompactionMode, buffer, bufferIndex);
            bufferIndex += 2;
            bufferIndex += 2; // reserved
            writeInt2(dataLength, buffer, bufferIndex);
            bufferIndex += 2;
            writeInt2(dataOffset, buffer, bufferIndex);
        }

        @Test
        @DisplayName("readParameterWordsWireFormat should parse buffer data correctly")
        public void readParameterWordsWireFormatShouldParseBufferCorrectly() {
            int bytesRead = response.readParameterWordsWireFormat(buffer, 0);

            assertEquals(20, bytesRead);
            assertEquals(dataCompactionMode, response.dataCompactionMode);
            assertEquals(dataLength, response.dataLength);
            assertEquals(dataOffset, response.dataOffset);
        }
    }

    @Test
    @DisplayName("toString should include key response fields")
    public void toStringShouldIncludeKeyFields() {
        response.dataCompactionMode = 1;
        response.dataLength = 1024;
        response.dataOffset = 54;

        String result = response.toString();

        // Verify that toString includes the key fields
        assertNotNull(result);
        assertTrue(result.contains("SmbComReadAndXResponse"));
        assertTrue(result.contains("dataCompactionMode=1"));
        assertTrue(result.contains("dataLength=1024"));
        assertTrue(result.contains("dataOffset=54"));
    }

    // Helper method to write a 2-byte integer to a byte array
    private void writeInt2(int val, byte[] dst, int dstIndex) {
        dst[dstIndex] = (byte) val;
        dst[dstIndex + 1] = (byte) (val >> 8);
    }
}

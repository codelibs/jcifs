package org.codelibs.jcifs.smb1;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.BeforeEach;
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
    public void testConstructor() {
        assertNotNull(response);
    }

    @Test
    public void testConstructorWithParameters() {
        byte[] b = new byte[0];
        response = new SmbComReadAndXResponse(b, 0);
        assertNotNull(response);
        assertEquals(b, response.b);
        assertEquals(0, response.off);
    }

    @Test
    public void testSetParam() {
        byte[] b = new byte[0];
        response.setParam(b, 0);
        assertEquals(b, response.b);
        assertEquals(0, response.off);
    }

    @Test
    public void testWriteParameterWordsWireFormat() {
        assertEquals(0, response.writeParameterWordsWireFormat(new byte[0], 0));
    }

    @Test
    public void testWriteBytesWireFormat() {
        assertEquals(0, response.writeBytesWireFormat(new byte[0], 0));
    }

    @Test
    public void testReadBytesWireFormat() {
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
        public void testReadParameterWordsWireFormat() {
            int bytesRead = response.readParameterWordsWireFormat(buffer, 0);

            assertEquals(20, bytesRead);
            assertEquals(dataCompactionMode, response.dataCompactionMode);
            assertEquals(dataLength, response.dataLength);
            assertEquals(dataOffset, response.dataOffset);
        }
    }

    @Test
    public void testToString() {
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

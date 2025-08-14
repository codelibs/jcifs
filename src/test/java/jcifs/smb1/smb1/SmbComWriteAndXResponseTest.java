package jcifs.smb1.smb1;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

/**
 * Tests for the SmbComWriteAndXResponse class.
 */
class SmbComWriteAndXResponseTest {

    /**
     * Test the readParameterWordsWireFormat method.
     */
    @Test
    void testReadParameterWordsWireFormat() {
        SmbComWriteAndXResponse response = new SmbComWriteAndXResponse();
        byte[] buffer = new byte[] { 0x0A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }; // count = 10

        int bytesRead = response.readParameterWordsWireFormat(buffer, 0);

        // The count should be read from the buffer.
        assertEquals(10L, response.count);
        // The method should return the number of bytes read.
        assertEquals(8, bytesRead);
    }

    /**
     * Test the writeParameterWordsWireFormat method.
     */
    @Test
    void testWriteParameterWordsWireFormat() {
        SmbComWriteAndXResponse response = new SmbComWriteAndXResponse();
        byte[] dst = new byte[0];

        int bytesWritten = response.writeParameterWordsWireFormat(dst, 0);

        // This method does nothing and should return 0.
        assertEquals(0, bytesWritten);
    }

    /**
     * Test the writeBytesWireFormat method.
     */
    @Test
    void testWriteBytesWireFormat() {
        SmbComWriteAndXResponse response = new SmbComWriteAndXResponse();
        byte[] dst = new byte[0];

        int bytesWritten = response.writeBytesWireFormat(dst, 0);

        // This method does nothing and should return 0.
        assertEquals(0, bytesWritten);
    }

    /**
     * Test the readBytesWireFormat method.
     */
    @Test
    void testReadBytesWireFormat() {
        SmbComWriteAndXResponse response = new SmbComWriteAndXResponse();
        byte[] buffer = new byte[0];

        int bytesRead = response.readBytesWireFormat(buffer, 0);

        // This method does nothing and should return 0.
        assertEquals(0, bytesRead);
    }

    /**
     * Test the toString method.
     */
    @Test
    void testToString() {
        SmbComWriteAndXResponse response = new SmbComWriteAndXResponse();
        response.count = 12345L;

        String result = response.toString();

        // The toString method should return a string containing the count.
        assertTrue(result.contains("count=12345"));
    }
}
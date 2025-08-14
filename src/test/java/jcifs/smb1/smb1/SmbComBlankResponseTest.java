package jcifs.smb1.smb1;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Tests for the SmbComBlankResponse class.
 */
class SmbComBlankResponseTest {

    private SmbComBlankResponse response;
    private byte[] buffer;

    @BeforeEach
    void setUp() {
        response = new SmbComBlankResponse();
        buffer = new byte[100];
    }

    /**
     * Test for the writeParameterWordsWireFormat method.
     * It should always return 0.
     */
    @Test
    void testWriteParameterWordsWireFormat() {
        assertEquals(0, response.writeParameterWordsWireFormat(buffer, 0), "writeParameterWordsWireFormat should return 0");
    }

    /**
     * Test for the writeBytesWireFormat method.
     * It should always return 0.
     */
    @Test
    void testWriteBytesWireFormat() {
        assertEquals(0, response.writeBytesWireFormat(buffer, 0), "writeBytesWireFormat should return 0");
    }

    /**
     * Test for the readParameterWordsWireFormat method.
     * It should always return 0.
     */
    @Test
    void testReadParameterWordsWireFormat() {
        assertEquals(0, response.readParameterWordsWireFormat(buffer, 0), "readParameterWordsWireFormat should return 0");
    }

    /**
     * Test for the readBytesWireFormat method.
     * It should always return 0.
     */
    @Test
    void testReadBytesWireFormat() {
        assertEquals(0, response.readBytesWireFormat(buffer, 0), "readBytesWireFormat should return 0");
    }

    /**
     * Test for the toString method.
     * It should return a string containing the class name.
     */
    @Test
    void testToString() {
        String toString = response.toString();
        assertTrue(toString.contains("SmbComBlankResponse"), "toString should contain the class name");
    }
}

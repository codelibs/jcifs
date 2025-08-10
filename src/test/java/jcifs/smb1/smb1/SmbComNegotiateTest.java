package jcifs.smb1.smb1;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

import java.io.UnsupportedEncodingException;

/**
 * Tests for the SmbComNegotiate class.
 */
class SmbComNegotiateTest {

    private SmbComNegotiate smbComNegotiate;
    private static final String DIALECTS = "\u0002NT LM 0.12\u0000";

    @BeforeEach
    void setUp() {
        // Create a new instance before each test
        smbComNegotiate = new SmbComNegotiate();
    }

    /**
     * Test the constructor of SmbComNegotiate.
     * It should initialize the command and flags2 with default values.
     */
    @Test
    void testConstructor() {
        // Verify that the command is set to SMB_COM_NEGOTIATE
        assertEquals(ServerMessageBlock.SMB_COM_NEGOTIATE, smbComNegotiate.command, "Constructor should set the command to SMB_COM_NEGOTIATE.");
        // Verify that flags2 is set to the default flags
        assertEquals(ServerMessageBlock.DEFAULT_FLAGS2, smbComNegotiate.flags2, "Constructor should set flags2 to DEFAULT_FLAGS2.");
    }

    /**
     * Test the writeParameterWordsWireFormat method.
     * This method should do nothing and return 0.
     */
    @Test
    void testWriteParameterWordsWireFormat() {
        byte[] dst = new byte[10];
        int dstIndex = 0;
        // The method should return 0 as it writes no parameter words
        int result = smbComNegotiate.writeParameterWordsWireFormat(dst, dstIndex);
        assertEquals(0, result, "writeParameterWordsWireFormat should return 0.");
    }

    /**
     * Test the writeBytesWireFormat method.
     * It should write the dialect string to the destination array.
     */
    @Test
    void testWriteBytesWireFormat() throws UnsupportedEncodingException {
        byte[] expectedBytes = DIALECTS.getBytes("ASCII");
        byte[] dst = new byte[expectedBytes.length];
        int dstIndex = 0;

        // Execute the method to write bytes
        int bytesWritten = smbComNegotiate.writeBytesWireFormat(dst, dstIndex);

        // Verify the number of bytes written
        assertEquals(expectedBytes.length, bytesWritten, "The number of bytes written should match the length of the dialect string.");
        // Verify the content of the destination array
        assertArrayEquals(expectedBytes, dst, "The destination array should contain the ASCII bytes of the dialect string.");
    }

    /**
     * Test the readParameterWordsWireFormat method.
     * This method should do nothing and return 0.
     */
    @Test
    void testReadParameterWordsWireFormat() {
        byte[] buffer = new byte[10];
        int bufferIndex = 0;
        // The method should return 0 as it reads no parameter words
        int result = smbComNegotiate.readParameterWordsWireFormat(buffer, bufferIndex);
        assertEquals(0, result, "readParameterWordsWireFormat should return 0.");
    }

    /**
     * Test the readBytesWireFormat method.
     * This method should do nothing and return 0.
     */
    @Test
    void testReadBytesWireFormat() {
        byte[] buffer = new byte[10];
        int bufferIndex = 0;
        // The method should return 0 as it reads no bytes
        int result = smbComNegotiate.readBytesWireFormat(buffer, bufferIndex);
        assertEquals(0, result, "readBytesWireFormat should return 0.");
    }

    /**
     * Test the toString method.
     * It should return a string representation of the SmbComNegotiate object.
     */
    @Test
    void testToString() {
        String result = smbComNegotiate.toString();
        assertTrue(result.startsWith("SmbComNegotiate["), "String should start with SmbComNegotiate[");
        assertTrue(result.contains("wordCount=0"), "String should contain wordCount=0");
        assertTrue(result.contains("dialects=NT LM 0.12]"), "String should contain dialects=NT LM 0.12]");
    }
}

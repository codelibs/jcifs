package jcifs.internal.smb1.trans2;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Properties;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.MockitoAnnotations;

import jcifs.Configuration;
import jcifs.config.PropertyConfiguration;
import jcifs.internal.smb1.ServerMessageBlock;
import jcifs.internal.smb1.trans.SmbComTransaction;

class Trans2FindFirst2ResponseTest {

    private Trans2FindFirst2Response response;
    private Configuration config;

    @BeforeEach
    void setUp() throws Exception {
        MockitoAnnotations.openMocks(this);
        Properties props = new Properties();
        config = new PropertyConfiguration(props);
        response = new Trans2FindFirst2Response(config);
    }

    @Test
    void testConstructor() {
        // Test that the constructor properly initializes the object
        assertNotNull(response);
        // The command should be SMB_COM_TRANSACTION2 (0x32 = 50)
        assertEquals(ServerMessageBlock.SMB_COM_TRANSACTION2, response.getCommand());
        // The subcommand should be TRANS2_FIND_FIRST2 (0x01 = 1)
        assertEquals(SmbComTransaction.TRANS2_FIND_FIRST2, response.getSubCommand());
    }

    @Test
    void testIsEndOfSearch() {
        // Test the isEndOfSearch method
        // By default, it should be false
        assertFalse(response.isEndOfSearch());
    }

    @Test
    void testGetNumEntries() {
        // Test the getNumEntries method
        // By default, it should be 0
        assertEquals(0, response.getNumEntries());
    }

    @Test
    void testGetResults() {
        // Test the getResults method
        // By default, it should return null until results are set
        assertNull(response.getResults());
    }

    @Test
    void testGetLastName() {
        // Test the getLastName method
        // By default, it should return null
        assertNull(response.getLastName());
    }

    @Test
    void testGetSubCommand() {
        // Test that the subcommand is properly set
        assertEquals(SmbComTransaction.TRANS2_FIND_FIRST2, response.getSubCommand());
    }

    @Test
    void testReadParametersWireFormat() {
        // Test reading parameters from a properly formatted buffer
        byte[] buffer = new byte[20];

        // Set up the buffer with test data
        // sid (2 bytes)
        buffer[0] = 0x01;
        buffer[1] = 0x00;
        // numEntries (2 bytes)
        buffer[2] = 0x05;
        buffer[3] = 0x00;
        // isEndOfSearch (2 bytes, bit 0 of first byte)
        buffer[4] = 0x01; // end of search = true
        buffer[5] = 0x00;
        // eaErrorOffset (2 bytes)
        buffer[6] = 0x00;
        buffer[7] = 0x00;
        // lastNameOffset (2 bytes)
        buffer[8] = 0x10;
        buffer[9] = 0x00;

        int result = response.readParametersWireFormat(buffer, 0, 10);

        // Should read 10 bytes
        assertEquals(10, result);
        // Check the values were parsed correctly
        assertEquals(1, response.getSid());
        assertEquals(5, response.getNumEntries());
        assertTrue(response.isEndOfSearch());
    }

    @Test
    void testReadDataWireFormat_emptyBuffer() throws Exception {
        // Test reading data from an empty buffer
        byte[] buffer = new byte[10];

        // Set data count to test return value
        response.setDataCount(5);

        // With 0 entries, should return dataCount
        int result = response.readDataWireFormat(buffer, 0, 0);
        // Should return dataCount
        assertEquals(5, result);
    }

    @Test
    void testGetSid() {
        // Test the getSid method
        // By default, it should be 0
        assertEquals(0, response.getSid());
    }

    @Test
    void testGetResumeKey() {
        // Test the getResumeKey method
        // By default, it should be 0
        assertEquals(0, response.getResumeKey());
    }

    @Test
    void testToString() {
        // Test the toString method
        String result = response.toString();
        assertNotNull(result);
        assertTrue(result.contains("Trans2FindFirst2Response"));
        assertTrue(result.contains("sid="));
        assertTrue(result.contains("searchCount="));
        assertTrue(result.contains("isEndOfSearch="));
        assertTrue(result.contains("lastName="));
    }

    @Test
    void testReadParametersWireFormat_NotFindFirst() {
        // Test reading parameters when subcommand is not TRANS2_FIND_FIRST2
        response.setSubCommand(SmbComTransaction.TRANS2_FIND_NEXT2);

        byte[] buffer = new byte[20];
        // numEntries (2 bytes) - sid is skipped for FIND_NEXT
        buffer[0] = 0x03;
        buffer[1] = 0x00;
        // isEndOfSearch (2 bytes)
        buffer[2] = 0x00; // end of search = false
        buffer[3] = 0x00;
        // eaErrorOffset (2 bytes)
        buffer[4] = 0x00;
        buffer[5] = 0x00;
        // lastNameOffset (2 bytes)
        buffer[6] = 0x08;
        buffer[7] = 0x00;

        int result = response.readParametersWireFormat(buffer, 0, 8);

        // Should read 8 bytes (no sid for FIND_NEXT)
        assertEquals(8, result);
        assertEquals(3, response.getNumEntries());
        assertFalse(response.isEndOfSearch());
        assertEquals(0, response.getSid()); // sid should remain 0
    }
}

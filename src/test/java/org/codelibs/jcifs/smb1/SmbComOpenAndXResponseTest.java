package org.codelibs.jcifs.smb1;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Unit tests for the SmbComOpenAndXResponse class.
 */
class SmbComOpenAndXResponseTest {

    private SmbComOpenAndXResponse response;

    @BeforeEach
    void setUp() {
        response = new SmbComOpenAndXResponse();
    }

    @Test
    void testConstructor() {
        assertNotNull(response);
        // Default values from constructor
        assertEquals(0, response.fid);
        assertEquals(0, response.fileAttributes);
        assertEquals(0L, response.lastWriteTime);
        assertEquals(0, response.dataSize);
        assertEquals(0, response.grantedAccess);
        assertEquals(0, response.fileType);
        assertEquals(0, response.deviceState);
        assertEquals(0, response.action);
        assertEquals(0, response.serverFid);
    }

    @Test
    void testSetFid() {
        response.fid = 123;
        assertEquals(123, response.fid);
    }

    @Test
    void testSetFileAttributes() {
        response.fileAttributes = 0x20; // ATTR_ARCHIVE
        assertEquals(0x20, response.fileAttributes);
    }

    @Test
    void testSetLastWriteTime() {
        long time = System.currentTimeMillis();
        response.lastWriteTime = time;
        assertEquals(time, response.lastWriteTime);
    }

    @Test
    void testSetDataSize() {
        response.dataSize = 1024;
        assertEquals(1024, response.dataSize);
    }

    @Test
    void testSetGrantedAccess() {
        response.grantedAccess = 0x02; // FILE_WRITE_DATA
        assertEquals(0x02, response.grantedAccess);
    }

    @Test
    void testSetFileType() {
        response.fileType = 1;
        assertEquals(1, response.fileType);
    }

    @Test
    void testSetDeviceState() {
        response.deviceState = 0x8000;
        assertEquals(0x8000, response.deviceState);
    }

    @Test
    void testSetAction() {
        response.action = 2;
        assertEquals(2, response.action);
    }

    @Test
    void testSetServerFid() {
        response.serverFid = 456;
        assertEquals(456, response.serverFid);
    }

    @Test
    void testToString() {
        // Set up the response object with test values
        response.fid = 1;
        response.fileAttributes = 2;
        response.lastWriteTime = 3;
        response.dataSize = 4;
        response.grantedAccess = 5;
        response.fileType = 6;
        response.deviceState = 7;
        response.action = 8;
        response.serverFid = 9;

        // Call toString method
        String result = response.toString();

        // Assert that the output string contains the expected field values
        assertNotNull(result);
        assertTrue(result.contains("SmbComOpenAndXResponse"));
        assertTrue(result.contains("fid=1"));
        assertTrue(result.contains("fileAttributes=2"));
        assertTrue(result.contains("dataSize=4"));
    }

    @Test
    void testWriteParameterWordsWireFormat() {
        byte[] dst = new byte[1024];
        int result = response.writeParameterWordsWireFormat(dst, 0);

        // The method should write parameter words
        assertTrue(result >= 0, "writeParameterWordsWireFormat should return non-negative value");
    }

    @Test
    void testReadParameterWordsWireFormat() {
        byte[] buffer = new byte[1024];
        int result = response.readParameterWordsWireFormat(buffer, 0);

        // The method should read parameter words
        assertTrue(result >= 0, "readParameterWordsWireFormat should return non-negative value");
    }

    @Test
    void testWriteBytesWireFormat() {
        byte[] dst = new byte[1024];
        int result = response.writeBytesWireFormat(dst, 0);

        // The method should write bytes
        assertEquals(0, result, "writeBytesWireFormat should return 0 for response");
    }

    @Test
    void testReadBytesWireFormat() {
        byte[] buffer = new byte[1024];
        int result = response.readBytesWireFormat(buffer, 0);

        // The method should read bytes
        assertEquals(0, result, "readBytesWireFormat should return 0 for response");
    }
}
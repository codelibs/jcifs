package jcifs.smb1.smb1;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

/**
 * Tests for the NetShareEnumResponse class.
 */
class NetShareEnumResponseTest {

    /**
     * Tests the readParametersWireFormat method.
     */
    @Test
    void testReadParametersWireFormat() {
        NetShareEnumResponse response = new NetShareEnumResponse();
        // Parameters: status (2 bytes), converter (2 bytes), numEntries (2 bytes), totalAvailableEntries (2 bytes)
        byte[] buffer = {
            0x00, 0x00, // status = 0 (Success)
            0x12, 0x34, // converter = 0x3412
            0x02, 0x00, // numEntries = 2
            0x05, 0x00  // totalAvailableEntries = 5
        };

        int bytesRead = response.readParametersWireFormat(buffer, 0, buffer.length);

        assertEquals(8, bytesRead, "Should read 8 bytes for parameters.");
        assertEquals(0, response.status, "Status should be 0.");
        assertEquals(2, response.numEntries, "Number of entries should be 2.");
    }

    /**
     * Tests the readDataWireFormat method.
     * This test simulates a response with two share entries.
     */
    @Test
    void testReadDataWireFormat() throws IOException {
        NetShareEnumResponse response = new NetShareEnumResponse();
        
        // Manually set parameters that would be read by readParametersWireFormat
        response.numEntries = 2;
        byte[] params = { 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x02, 0x00 };
        response.readParametersWireFormat(params, 0, params.length);

        // Data block: 2 entries
        byte[] data = new byte[100];
        // Entry 1: SHARE1, type 0 (Disk), remark "Remark 1"
        System.arraycopy("SHARE1".getBytes(StandardCharsets.US_ASCII), 0, data, 0, 6);
        data[14] = 0x00; data[15] = 0x00; // type = 0
        data[16] = 40; data[17] = 0; data[18] = 0; data[19] = 0; // remark offset

        // Entry 2: IPC$, type 3 (IPC), remark "Inter-Process Communication"
        System.arraycopy("IPC$".getBytes(StandardCharsets.US_ASCII), 0, data, 20, 4);
        data[34] = 0x03; data[35] = 0x00; // type = 3
        data[36] = 60; data[37] = 0; data[38] = 0; data[39] = 0; // remark offset

        // Remarks data
        System.arraycopy("Remark 1".getBytes(StandardCharsets.US_ASCII), 0, data, 40, 8);
        System.arraycopy("Inter-Process Communication".getBytes(StandardCharsets.US_ASCII), 0, data, 60, 27);

        int bytesRead = response.readDataWireFormat(data, 0, data.length);

        assertEquals(40, bytesRead, "Should read 40 bytes for the two entries.");
        assertNotNull(response.results, "Results should not be null.");
        assertEquals(2, response.results.length, "Should have 2 share entries.");

        SmbShareInfo share1 = (SmbShareInfo) response.results[0];
        assertEquals("SHARE1", share1.getName().trim(), "Share 1 name should be correct.");
        assertEquals(0, share1.type, "Share 1 raw type should be 0.");
        assertEquals("Remark 1", share1.remark.trim(), "Share 1 remark should be correct.");

        SmbShareInfo share2 = (SmbShareInfo) response.results[1];
        assertEquals("IPC$", share2.getName().trim(), "Share 2 name should be correct.");
        assertEquals(3, share2.type, "Share 2 raw type should be 3.");
        assertEquals("Inter-Process Communication", share2.remark.trim(), "Share 2 remark should be correct.");
    }

    /**
     * Tests the toString method for a meaningful representation.
     */
    @Test
    void testToString() {
        NetShareEnumResponse response = new NetShareEnumResponse();
        response.status = 0;
        response.numEntries = 2;
        byte[] buffer = { 0x00, 0x00, 0x12, 0x34, 0x02, 0x00, 0x05, 0x00 };
        response.readParametersWireFormat(buffer, 0, buffer.length);

        String resultString = response.toString();
        assertTrue(resultString.contains("status=0"), "toString should contain the status.");
        assertTrue(resultString.contains("converter=13330"), "toString should contain the converter.");
        assertTrue(resultString.contains("entriesReturned=2"), "toString should contain the number of entries.");
        assertTrue(resultString.contains("totalAvailableEntries=5"), "toString should contain the total available entries.");
    }

    /**
     * Tests the empty write methods to ensure they do nothing and return 0.
     */
    @Test
    void testWriteMethods() {
        NetShareEnumResponse response = new NetShareEnumResponse();
        byte[] dst = new byte[10];
        assertEquals(0, response.writeSetupWireFormat(dst, 0), "writeSetupWireFormat should return 0.");
        assertEquals(0, response.writeParametersWireFormat(dst, 0), "writeParametersWireFormat should return 0.");
        assertEquals(0, response.writeDataWireFormat(dst, 0), "writeDataWireFormat should return 0.");
    }

    /**
     * Tests the readSetupWireFormat method.
     */
    @Test
    void testReadSetupWireFormat() {
        NetShareEnumResponse response = new NetShareEnumResponse();
        byte[] buffer = new byte[10];
        assertEquals(0, response.readSetupWireFormat(buffer, 0, buffer.length), "readSetupWireFormat should return 0.");
    }
}
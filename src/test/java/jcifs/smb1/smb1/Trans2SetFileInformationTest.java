package jcifs.smb1.smb1;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class Trans2SetFileInformationTest {

    private Trans2SetFileInformation trans2SetFileInformation;
    private final int fid = 123;
    private final int attributes = 1;
    private final long createTime = System.currentTimeMillis();
    private final long lastWriteTime = System.currentTimeMillis();

    @BeforeEach
    void setUp() {
        trans2SetFileInformation = new Trans2SetFileInformation(fid, attributes, createTime, lastWriteTime);
    }

    @Test
    void testConstructor() {
        // Then
        assertEquals(SmbConstants.SMB_COM_TRANSACTION2, trans2SetFileInformation.command);
        assertEquals(Trans2SetFileInformation.TRANS2_SET_FILE_INFORMATION, trans2SetFileInformation.subCommand);
        assertEquals(6, trans2SetFileInformation.maxParameterCount);
        assertEquals(0, trans2SetFileInformation.maxDataCount);
        assertEquals(0, trans2SetFileInformation.maxSetupCount);
    }

    @Test
    void testWriteSetupWireFormat() {
        // Given
        byte[] dst = new byte[2];

        // When
        int result = trans2SetFileInformation.writeSetupWireFormat(dst, 0);

        // Then
        assertEquals(2, result);
        assertEquals(trans2SetFileInformation.subCommand, dst[0]);
        assertEquals(0, dst[1]);
    }

    @Test
    void testWriteParametersWireFormat() {
        // Given
        byte[] dst = new byte[6];

        // When
        int result = trans2SetFileInformation.writeParametersWireFormat(dst, 0);

        // Then
        assertEquals(6, result);
        assertEquals(fid, (dst[1] << 8) | (dst[0] & 0xFF));
        assertEquals(Trans2SetFileInformation.SMB_FILE_BASIC_INFO, (dst[3] << 8) | (dst[2] & 0xFF));
        assertEquals(0, (dst[5] << 8) | (dst[4] & 0xFF));
    }

    @Test
    void testWriteDataWireFormat() {
        // Given
        byte[] dst = new byte[32];

        // When
        int result = trans2SetFileInformation.writeDataWireFormat(dst, 0);

        // Then
        assertEquals(32, result);
    }

    @Test
    void testReadSetupWireFormat() {
        // When
        int result = trans2SetFileInformation.readSetupWireFormat(new byte[0], 0, 0);

        // Then
        assertEquals(0, result);
    }

    @Test
    void testReadParametersWireFormat() {
        // When
        int result = trans2SetFileInformation.readParametersWireFormat(new byte[0], 0, 0);

        // Then
        assertEquals(0, result);
    }

    @Test
    void testReadDataWireFormat() {
        // When
        int result = trans2SetFileInformation.readDataWireFormat(new byte[0], 0, 0);

        // Then
        assertEquals(0, result);
    }

    @Test
    void testToString() {
        // When
        String result = trans2SetFileInformation.toString();

        // Then
        assertTrue(result.startsWith("Trans2SetFileInformation["));
        assertTrue(result.contains("fid=" + fid));
    }
}
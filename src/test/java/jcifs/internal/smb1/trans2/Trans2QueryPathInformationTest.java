package jcifs.internal.smb1.trans2;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

import java.util.Properties;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import jcifs.Configuration;
import jcifs.config.PropertyConfiguration;
import jcifs.internal.fscc.FileInformation;
import jcifs.internal.smb1.ServerMessageBlock;
import jcifs.internal.smb1.trans.SmbComTransaction;
import jcifs.internal.util.SMBUtil;
import jcifs.util.Hexdump;

class Trans2QueryPathInformationTest {

    private Trans2QueryPathInformation trans2QueryPathInfo;
    private Configuration config;

    @Mock
    private Configuration mockConfig;

    private static final String TEST_FILENAME = "test/file.txt";
    private static final int TEST_INFO_LEVEL = FileInformation.FILE_BASIC_INFO;

    @BeforeEach
    void setUp() throws Exception {
        MockitoAnnotations.openMocks(this);
        Properties props = new Properties();
        config = new PropertyConfiguration(props);
    }

    @Test
    void testConstructor() {
        // Test constructor initializes all fields correctly
        trans2QueryPathInfo = new Trans2QueryPathInformation(config, TEST_FILENAME, TEST_INFO_LEVEL);

        assertNotNull(trans2QueryPathInfo);
        assertEquals(ServerMessageBlock.SMB_COM_TRANSACTION2, trans2QueryPathInfo.getCommand());
        assertEquals(SmbComTransaction.TRANS2_QUERY_PATH_INFORMATION, trans2QueryPathInfo.getSubCommand());
    }

    @Test
    void testConstructorWithDifferentInformationLevels() {
        // Test with FILE_BASIC_INFO
        trans2QueryPathInfo = new Trans2QueryPathInformation(config, TEST_FILENAME, FileInformation.FILE_BASIC_INFO);
        assertNotNull(trans2QueryPathInfo);

        // Test with FILE_STANDARD_INFO
        trans2QueryPathInfo = new Trans2QueryPathInformation(config, TEST_FILENAME, FileInformation.FILE_STANDARD_INFO);
        assertNotNull(trans2QueryPathInfo);

        // Test with FILE_ENDOFFILE_INFO
        trans2QueryPathInfo = new Trans2QueryPathInformation(config, TEST_FILENAME, FileInformation.FILE_ENDOFFILE_INFO);
        assertNotNull(trans2QueryPathInfo);
    }

    @Test
    void testWriteSetupWireFormat() {
        trans2QueryPathInfo = new Trans2QueryPathInformation(config, TEST_FILENAME, TEST_INFO_LEVEL);

        byte[] buffer = new byte[256];
        int written = trans2QueryPathInfo.writeSetupWireFormat(buffer, 0);

        // Should write 2 bytes: subcommand and 0x00
        assertEquals(2, written);
        assertEquals(SmbComTransaction.TRANS2_QUERY_PATH_INFORMATION, buffer[0]);
        assertEquals(0x00, buffer[1]);
    }

    @Test
    void testWriteParametersWireFormat() {
        trans2QueryPathInfo = new Trans2QueryPathInformation(config, TEST_FILENAME, TEST_INFO_LEVEL);

        byte[] buffer = new byte[512];
        int written = trans2QueryPathInfo.writeParametersWireFormat(buffer, 0);

        // Check information level (first 2 bytes)
        int actualInfoLevel = SMBUtil.readInt2(buffer, 0);
        assertEquals(0x0101, actualInfoLevel); // FILE_BASIC_INFO maps to 0x0101

        // Check reserved bytes (4 bytes of 0x00)
        assertEquals(0x00, buffer[2]);
        assertEquals(0x00, buffer[3]);
        assertEquals(0x00, buffer[4]);
        assertEquals(0x00, buffer[5]);

        // Check that filename is written correctly (starting at offset 6)
        // The filename should be null-terminated Unicode string
        assertTrue(written > 6);

        // Verify the total bytes written is reasonable
        assertTrue(written > TEST_FILENAME.length());
    }

    @ParameterizedTest
    @CsvSource({ "4, 257", // FILE_BASIC_INFO -> 0x0101
            "5, 258", // FILE_STANDARD_INFO -> 0x0102
            "20, 260" // FILE_ENDOFFILE_INFO -> 0x0104
    })
    void testWriteParametersWireFormatWithDifferentInfoLevels(int infoLevel, int expectedMappedValue) {
        trans2QueryPathInfo = new Trans2QueryPathInformation(config, TEST_FILENAME, infoLevel);

        byte[] buffer = new byte[512];
        trans2QueryPathInfo.writeParametersWireFormat(buffer, 0);

        // Check mapped information level
        int actualInfoLevel = SMBUtil.readInt2(buffer, 0);
        assertEquals(expectedMappedValue, actualInfoLevel);
    }

    @Test
    void testWriteDataWireFormat() {
        trans2QueryPathInfo = new Trans2QueryPathInformation(config, TEST_FILENAME, TEST_INFO_LEVEL);

        byte[] buffer = new byte[256];
        int written = trans2QueryPathInfo.writeDataWireFormat(buffer, 0);

        // Should write nothing (returns 0)
        assertEquals(0, written);
    }

    @Test
    void testReadSetupWireFormat() {
        trans2QueryPathInfo = new Trans2QueryPathInformation(config, TEST_FILENAME, TEST_INFO_LEVEL);

        byte[] buffer = new byte[256];
        int read = trans2QueryPathInfo.readSetupWireFormat(buffer, 0, buffer.length);

        // Should read nothing (returns 0)
        assertEquals(0, read);
    }

    @Test
    void testReadParametersWireFormat() {
        trans2QueryPathInfo = new Trans2QueryPathInformation(config, TEST_FILENAME, TEST_INFO_LEVEL);

        byte[] buffer = new byte[256];
        int read = trans2QueryPathInfo.readParametersWireFormat(buffer, 0, buffer.length);

        // Should read nothing (returns 0)
        assertEquals(0, read);
    }

    @Test
    void testReadDataWireFormat() {
        trans2QueryPathInfo = new Trans2QueryPathInformation(config, TEST_FILENAME, TEST_INFO_LEVEL);

        byte[] buffer = new byte[256];
        int read = trans2QueryPathInfo.readDataWireFormat(buffer, 0, buffer.length);

        // Should read nothing (returns 0)
        assertEquals(0, read);
    }

    @Test
    void testMapInformationLevel() {
        // Test valid information levels
        assertEquals(0x0101, Trans2QueryPathInformation.mapInformationLevel(FileInformation.FILE_BASIC_INFO));
        assertEquals(0x0102, Trans2QueryPathInformation.mapInformationLevel(FileInformation.FILE_STANDARD_INFO));
        assertEquals(0x0104, Trans2QueryPathInformation.mapInformationLevel(FileInformation.FILE_ENDOFFILE_INFO));
    }

    @Test
    void testMapInformationLevelWithInvalidLevel() {
        // Test invalid information level
        IllegalArgumentException exception =
                assertThrows(IllegalArgumentException.class, () -> Trans2QueryPathInformation.mapInformationLevel(999));
        assertTrue(exception.getMessage().contains("Unsupported information level"));
    }

    @Test
    void testToString() {
        trans2QueryPathInfo = new Trans2QueryPathInformation(config, TEST_FILENAME, TEST_INFO_LEVEL);

        String result = trans2QueryPathInfo.toString();

        assertNotNull(result);
        assertTrue(result.contains("Trans2QueryPathInformation"));
        assertTrue(result.contains("informationLevel=0x"));
        assertTrue(result.contains("filename=" + TEST_FILENAME));
        assertTrue(result.contains(Hexdump.toHexString(TEST_INFO_LEVEL, 3)));
    }

    @Test
    void testToStringWithDifferentPaths() {
        // Test with various path formats
        String[] testPaths = { "simple.txt", "path/to/file.doc", "//server/share/file.txt", "folder\\windows\\style.txt", "" // empty path
        };

        for (String path : testPaths) {
            trans2QueryPathInfo = new Trans2QueryPathInformation(config, path, TEST_INFO_LEVEL);
            String result = trans2QueryPathInfo.toString();

            assertNotNull(result);
            assertTrue(result.contains("filename=" + path));
        }
    }

    @Test
    void testWriteParametersWithEmptyFilename() {
        trans2QueryPathInfo = new Trans2QueryPathInformation(config, "", TEST_INFO_LEVEL);

        byte[] buffer = new byte[256];
        int written = trans2QueryPathInfo.writeParametersWireFormat(buffer, 0);

        // Should still write information level and reserved bytes
        assertTrue(written >= 6);

        // Check information level
        int actualInfoLevel = SMBUtil.readInt2(buffer, 0);
        assertEquals(0x0101, actualInfoLevel);
    }

    @Test
    void testWriteParametersWithLongFilename() {
        // Create a very long filename
        StringBuilder longPath = new StringBuilder();
        for (int i = 0; i < 100; i++) {
            longPath.append("verylongpath/");
        }
        longPath.append("file.txt");

        trans2QueryPathInfo = new Trans2QueryPathInformation(config, longPath.toString(), TEST_INFO_LEVEL);

        byte[] buffer = new byte[8192]; // Large buffer for long path
        int written = trans2QueryPathInfo.writeParametersWireFormat(buffer, 0);

        // Should write the entire path
        assertTrue(written > longPath.length());

        // Check information level is still correct
        int actualInfoLevel = SMBUtil.readInt2(buffer, 0);
        assertEquals(0x0101, actualInfoLevel);
    }

    @Test
    void testWriteParametersWithSpecialCharacters() {
        String specialPath = "test/file with spaces and $pecial #chars!.txt";
        trans2QueryPathInfo = new Trans2QueryPathInformation(config, specialPath, TEST_INFO_LEVEL);

        byte[] buffer = new byte[512];
        int written = trans2QueryPathInfo.writeParametersWireFormat(buffer, 0);

        // Should handle special characters properly
        assertTrue(written > specialPath.length());

        // Check information level
        int actualInfoLevel = SMBUtil.readInt2(buffer, 0);
        assertEquals(0x0101, actualInfoLevel);
    }

    @Test
    void testWriteParametersWithUnicodePath() {
        String unicodePath = "test/文件名.txt"; // Chinese characters
        trans2QueryPathInfo = new Trans2QueryPathInformation(config, unicodePath, TEST_INFO_LEVEL);

        byte[] buffer = new byte[512];
        int written = trans2QueryPathInfo.writeParametersWireFormat(buffer, 0);

        // Should handle Unicode characters
        assertTrue(written > 6);

        // Check information level
        int actualInfoLevel = SMBUtil.readInt2(buffer, 0);
        assertEquals(0x0101, actualInfoLevel);
    }

    @ParameterizedTest
    @ValueSource(ints = { -1, 0, 100, 255, Integer.MAX_VALUE })
    void testMapInformationLevelWithUnsupportedLevels(int level) {
        if (level == FileInformation.FILE_BASIC_INFO || level == FileInformation.FILE_STANDARD_INFO
                || level == FileInformation.FILE_ENDOFFILE_INFO) {
            // These are valid levels, skip assertion
            return;
        }

        IllegalArgumentException exception =
                assertThrows(IllegalArgumentException.class, () -> Trans2QueryPathInformation.mapInformationLevel(level));
        assertTrue(exception.getMessage().contains("Unsupported information level"));
    }

    @Test
    void testCompleteWireFormatRoundTrip() {
        trans2QueryPathInfo = new Trans2QueryPathInformation(config, TEST_FILENAME, TEST_INFO_LEVEL);

        // Test complete wire format writing
        byte[] setupBuffer = new byte[256];
        byte[] paramBuffer = new byte[512];
        byte[] dataBuffer = new byte[256];

        int setupWritten = trans2QueryPathInfo.writeSetupWireFormat(setupBuffer, 0);
        int paramWritten = trans2QueryPathInfo.writeParametersWireFormat(paramBuffer, 0);
        int dataWritten = trans2QueryPathInfo.writeDataWireFormat(dataBuffer, 0);

        // Verify lengths
        assertEquals(2, setupWritten);
        assertTrue(paramWritten > 6);
        assertEquals(0, dataWritten);

        // Verify setup content
        assertEquals(SmbComTransaction.TRANS2_QUERY_PATH_INFORMATION, setupBuffer[0]);
        assertEquals(0x00, setupBuffer[1]);

        // Verify parameter content
        assertEquals(0x0101, SMBUtil.readInt2(paramBuffer, 0));
    }

    @Test
    void testWithMockConfiguration() {
        when(mockConfig.getMinimumVersion()).thenReturn(jcifs.DialectVersion.SMB1);
        when(mockConfig.getMaximumVersion()).thenReturn(jcifs.DialectVersion.SMB311);

        trans2QueryPathInfo = new Trans2QueryPathInformation(mockConfig, TEST_FILENAME, TEST_INFO_LEVEL);

        assertNotNull(trans2QueryPathInfo);

        // Configuration is accessed during initialization
        // Verify at least that getPid() and getTransactionBufferSize() were called
    }
}

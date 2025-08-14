package jcifs.internal.smb1.trans2;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import jcifs.Configuration;
import jcifs.internal.smb1.ServerMessageBlock;
import jcifs.internal.util.SMBUtil;

/**
 * Test class for Trans2FindFirst2
 */
@DisplayName("Trans2FindFirst2 Tests")
class Trans2FindFirst2Test {

    @Mock
    private Configuration mockConfig;

    private Trans2FindFirst2 trans2FindFirst2;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        when(mockConfig.getMaximumBufferSize()).thenReturn(65535);
        when(mockConfig.getTransactionBufferSize()).thenReturn(65535);
        when(mockConfig.isUseUnicode()).thenReturn(true);
        when(mockConfig.isForceUnicode()).thenReturn(false);
        when(mockConfig.getOemEncoding()).thenReturn("ASCII");
    }

    @Test
    @DisplayName("Test constructor with standard path")
    void testConstructorWithStandardPath() {
        // Test standard path without trailing backslash
        trans2FindFirst2 = new Trans2FindFirst2(mockConfig, "\\test\\path", "*.txt", 0x16, 10, 1024);

        assertEquals(ServerMessageBlock.SMB_COM_TRANSACTION2, trans2FindFirst2.getCommand());
        assertEquals(Trans2FindFirst2.TRANS2_FIND_FIRST2, trans2FindFirst2.getSubCommand());
        assertEquals("\\test\\path\\", trans2FindFirst2.getPath());
    }

    @Test
    @DisplayName("Test constructor with path ending in backslash")
    void testConstructorWithPathEndingInBackslash() {
        // Test path already ending with backslash
        trans2FindFirst2 = new Trans2FindFirst2(mockConfig, "\\test\\path\\", "*.doc", 0x16, 20, 2048);

        assertEquals("\\test\\path\\", trans2FindFirst2.getPath());
    }

    @Test
    @DisplayName("Test constructor with root path")
    void testConstructorWithRootPath() {
        // Test root path
        trans2FindFirst2 = new Trans2FindFirst2(mockConfig, "\\", "*.*", 0x16, 15, 4096);

        assertEquals("\\", trans2FindFirst2.getPath());
    }

    @ParameterizedTest
    @DisplayName("Test search attributes masking")
    @ValueSource(ints = { 0x00, 0x16, 0x37, 0xFF })
    void testSearchAttributesMasking(int searchAttributes) {
        trans2FindFirst2 = new Trans2FindFirst2(mockConfig, "\\test", "*.*", searchAttributes, 10, 1024);

        // Verify attributes are masked with 0x37
        int expectedAttributes = searchAttributes & 0x37;

        // Write parameters to verify the masked value is used
        byte[] buffer = new byte[100];
        int written = trans2FindFirst2.writeParametersWireFormat(buffer, 0);

        // Read back the search attributes
        int writtenAttributes = SMBUtil.readInt2(buffer, 0);
        assertEquals(expectedAttributes, writtenAttributes);
    }

    @Test
    @DisplayName("Test writeSetupWireFormat")
    void testWriteSetupWireFormat() {
        trans2FindFirst2 = new Trans2FindFirst2(mockConfig, "\\test", "*.*", 0x16, 10, 1024);

        byte[] buffer = new byte[10];
        int written = trans2FindFirst2.writeSetupWireFormat(buffer, 0);

        assertEquals(2, written);
        assertEquals((byte) Trans2FindFirst2.TRANS2_FIND_FIRST2, buffer[0]);
        assertEquals((byte) 0x00, buffer[1]);
    }

    @Test
    @DisplayName("Test writeParametersWireFormat")
    void testWriteParametersWireFormat() {
        trans2FindFirst2 = new Trans2FindFirst2(mockConfig, "\\test\\dir", "*.txt", 0xFF, 100, 8192);

        byte[] buffer = new byte[256];
        int written = trans2FindFirst2.writeParametersWireFormat(buffer, 0);

        assertTrue(written > 12); // Minimum size for fixed parameters

        // Verify search attributes (masked with 0x37)
        assertEquals(0x37, SMBUtil.readInt2(buffer, 0));

        // Verify max items
        assertEquals(100, SMBUtil.readInt2(buffer, 2));

        // Verify flags (should be 0x00)
        assertEquals(0x00, SMBUtil.readInt2(buffer, 4));

        // Verify information level (SMB_FILE_BOTH_DIRECTORY_INFO)
        assertEquals(Trans2FindFirst2.SMB_FILE_BOTH_DIRECTORY_INFO, SMBUtil.readInt2(buffer, 6));

        // Verify search storage type (should be 0)
        assertEquals(0, SMBUtil.readInt4(buffer, 8));

        // Verify the path is included
        String writtenPath = readStringFromBuffer(buffer, 12, written - 12);
        assertEquals("\\test\\dir\\*.txt", writtenPath);
    }

    @ParameterizedTest
    @DisplayName("Test writeParametersWireFormat with various wildcards")
    @CsvSource({ "'\\path', '*.txt', '\\path\\*.txt'", "'\\path\\', '*.doc', '\\path\\*.doc'", "'\\', '*.*', '\\*.*'",
            "'\\test', 'file?.txt', '\\test\\file?.txt'" })
    void testWriteParametersWireFormatWithVariousWildcards(String path, String wildcard, String expectedFullPath) {
        trans2FindFirst2 = new Trans2FindFirst2(mockConfig, path, wildcard, 0x16, 10, 1024);

        byte[] buffer = new byte[256];
        int written = trans2FindFirst2.writeParametersWireFormat(buffer, 0);

        String writtenPath = readStringFromBuffer(buffer, 12, written - 12);
        assertEquals(expectedFullPath, writtenPath);
    }

    @Test
    @DisplayName("Test writeDataWireFormat returns 0")
    void testWriteDataWireFormat() {
        trans2FindFirst2 = new Trans2FindFirst2(mockConfig, "\\test", "*.*", 0x16, 10, 1024);

        byte[] buffer = new byte[100];
        int written = trans2FindFirst2.writeDataWireFormat(buffer, 0);

        assertEquals(0, written);
    }

    @Test
    @DisplayName("Test readSetupWireFormat returns 0")
    void testReadSetupWireFormat() {
        trans2FindFirst2 = new Trans2FindFirst2(mockConfig, "\\test", "*.*", 0x16, 10, 1024);

        byte[] buffer = new byte[100];
        int read = trans2FindFirst2.readSetupWireFormat(buffer, 0, 100);

        assertEquals(0, read);
    }

    @Test
    @DisplayName("Test readParametersWireFormat returns 0")
    void testReadParametersWireFormat() {
        trans2FindFirst2 = new Trans2FindFirst2(mockConfig, "\\test", "*.*", 0x16, 10, 1024);

        byte[] buffer = new byte[100];
        int read = trans2FindFirst2.readParametersWireFormat(buffer, 0, 100);

        assertEquals(0, read);
    }

    @Test
    @DisplayName("Test readDataWireFormat returns 0")
    void testReadDataWireFormat() {
        trans2FindFirst2 = new Trans2FindFirst2(mockConfig, "\\test", "*.*", 0x16, 10, 1024);

        byte[] buffer = new byte[100];
        int read = trans2FindFirst2.readDataWireFormat(buffer, 0, 100);

        assertEquals(0, read);
    }

    @Test
    @DisplayName("Test toString method")
    void testToString() {
        trans2FindFirst2 = new Trans2FindFirst2(mockConfig, "\\test\\path", "*.txt", 0x16, 50, 2048);

        String result = trans2FindFirst2.toString();

        assertNotNull(result);
        assertTrue(result.contains("Trans2FindFirst2"));
        assertTrue(result.contains("searchAttributes=0x16"));
        assertTrue(result.contains("searchCount=50"));
        assertTrue(result.contains("flags=0x00"));
        assertTrue(result.contains("informationLevel=0x104"));
        assertTrue(result.contains("searchStorageType=0"));
        assertTrue(result.contains("filename=\\test\\path\\"));
    }

    @Test
    @DisplayName("Test constants values")
    void testConstants() {
        // Test flag constants
        assertEquals(0x01, Trans2FindFirst2.FLAGS_CLOSE_AFTER_THIS_REQUEST);
        assertEquals(0x02, Trans2FindFirst2.FLAGS_CLOSE_IF_END_REACHED);
        assertEquals(0x04, Trans2FindFirst2.FLAGS_RETURN_RESUME_KEYS);
        assertEquals(0x08, Trans2FindFirst2.FLAGS_RESUME_FROM_PREVIOUS_END);
        assertEquals(0x10, Trans2FindFirst2.FLAGS_FIND_WITH_BACKUP_INTENT);

        // Test information level constants
        assertEquals(1, Trans2FindFirst2.SMB_INFO_STANDARD);
        assertEquals(2, Trans2FindFirst2.SMB_INFO_QUERY_EA_SIZE);
        assertEquals(3, Trans2FindFirst2.SMB_INFO_QUERY_EAS_FROM_LIST);
        assertEquals(0x101, Trans2FindFirst2.SMB_FIND_FILE_DIRECTORY_INFO);
        assertEquals(0x102, Trans2FindFirst2.SMB_FIND_FILE_FULL_DIRECTORY_INFO);
        assertEquals(0x103, Trans2FindFirst2.SMB_FILE_NAMES_INFO);
        assertEquals(0x104, Trans2FindFirst2.SMB_FILE_BOTH_DIRECTORY_INFO);
    }

    @Test
    @DisplayName("Test with empty wildcard")
    void testWithEmptyWildcard() {
        trans2FindFirst2 = new Trans2FindFirst2(mockConfig, "\\test", "", 0x16, 10, 1024);

        byte[] buffer = new byte[256];
        int written = trans2FindFirst2.writeParametersWireFormat(buffer, 0);

        String writtenPath = readStringFromBuffer(buffer, 12, written - 12);
        assertEquals("\\test\\", writtenPath);
    }

    @Test
    @DisplayName("Test with special characters in path")
    void testWithSpecialCharactersInPath() {
        trans2FindFirst2 = new Trans2FindFirst2(mockConfig, "\\test\\path with spaces", "*.txt", 0x16, 10, 1024);

        byte[] buffer = new byte[256];
        int written = trans2FindFirst2.writeParametersWireFormat(buffer, 0);

        String writtenPath = readStringFromBuffer(buffer, 12, written - 12);
        assertEquals("\\test\\path with spaces\\*.txt", writtenPath);
    }

    @Test
    @DisplayName("Test with maximum values")
    void testWithMaximumValues() {
        trans2FindFirst2 = new Trans2FindFirst2(mockConfig, "\\test", "*.*", 0xFFFF, 65535, Integer.MAX_VALUE);

        byte[] buffer = new byte[256];
        int written = trans2FindFirst2.writeParametersWireFormat(buffer, 0);

        // Verify search attributes are still masked
        assertEquals(0x37, SMBUtil.readInt2(buffer, 0));

        // Verify max items
        assertEquals(65535, SMBUtil.readInt2(buffer, 2));
    }

    @Test
    @DisplayName("Test with minimum values")
    void testWithMinimumValues() {
        trans2FindFirst2 = new Trans2FindFirst2(mockConfig, "\\", "*", 0, 0, 0);

        byte[] buffer = new byte[256];
        int written = trans2FindFirst2.writeParametersWireFormat(buffer, 0);

        assertEquals(0, SMBUtil.readInt2(buffer, 0)); // search attributes
        assertEquals(0, SMBUtil.readInt2(buffer, 2)); // max items
    }

    // Helper method to read string from buffer
    private String readStringFromBuffer(byte[] buffer, int offset, int length) {
        // Simple ASCII string reading for test purposes
        StringBuilder sb = new StringBuilder();
        for (int i = offset; i < offset + length && buffer[i] != 0; i++) {
            if (buffer[i] != 0) {
                sb.append((char) buffer[i]);
            }
        }
        return sb.toString();
    }
}

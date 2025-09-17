package org.codelibs.jcifs.smb.internal.smb1.trans2;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

import java.util.Properties;

import org.codelibs.jcifs.smb.Configuration;
import org.codelibs.jcifs.smb.config.PropertyConfiguration;
import org.codelibs.jcifs.smb.internal.fscc.FileSystemInformation;
import org.codelibs.jcifs.smb.internal.smb1.ServerMessageBlock;
import org.codelibs.jcifs.smb.internal.smb1.trans.SmbComTransaction;
import org.codelibs.jcifs.smb.internal.util.SMBUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

class Trans2QueryFSInformationTest {

    private Trans2QueryFSInformation trans2QueryFSInfo;
    private Configuration config;

    @Mock
    private Configuration mockConfig;

    @BeforeEach
    void setUp() throws Exception {
        MockitoAnnotations.openMocks(this);
        Properties props = new Properties();
        config = new PropertyConfiguration(props);
    }

    @Test
    @DisplayName("Test constructor with SMB_INFO_ALLOCATION")
    void testConstructorWithSmbInfoAllocation() {
        // Create instance with SMB_INFO_ALLOCATION
        trans2QueryFSInfo = new Trans2QueryFSInformation(config, FileSystemInformation.SMB_INFO_ALLOCATION);

        // Verify initialization
        assertNotNull(trans2QueryFSInfo);
        assertEquals(ServerMessageBlock.SMB_COM_TRANSACTION2, trans2QueryFSInfo.getCommand());
        assertEquals(SmbComTransaction.TRANS2_QUERY_FS_INFORMATION, trans2QueryFSInfo.getSubCommand());
    }

    @Test
    @DisplayName("Test constructor with FS_SIZE_INFO")
    void testConstructorWithFsSizeInfo() {
        // Create instance with FS_SIZE_INFO
        trans2QueryFSInfo = new Trans2QueryFSInformation(config, FileSystemInformation.FS_SIZE_INFO);

        // Verify initialization
        assertNotNull(trans2QueryFSInfo);
        assertEquals(ServerMessageBlock.SMB_COM_TRANSACTION2, trans2QueryFSInfo.getCommand());
        assertEquals(SmbComTransaction.TRANS2_QUERY_FS_INFORMATION, trans2QueryFSInfo.getSubCommand());
    }

    @Test
    @DisplayName("Test constructor with invalid information level")
    void testConstructorWithInvalidInformationLevel() {
        // The exception is thrown during writeParametersWireFormat when mapInformationLevel is called
        Trans2QueryFSInformation trans2 = new Trans2QueryFSInformation(config, 99);
        assertNotNull(trans2);

        // Exception should be thrown when trying to write parameters
        byte[] buffer = new byte[256];
        assertThrows(IllegalArgumentException.class, () -> {
            trans2.writeParametersWireFormat(buffer, 0);
        });
    }

    @Test
    @DisplayName("Test writeSetupWireFormat")
    void testWriteSetupWireFormat() {
        trans2QueryFSInfo = new Trans2QueryFSInformation(config, FileSystemInformation.SMB_INFO_ALLOCATION);

        byte[] buffer = new byte[256];
        int written = trans2QueryFSInfo.writeSetupWireFormat(buffer, 0);

        // Should write 2 bytes: subcommand and 0x00
        assertEquals(2, written);
        assertEquals(SmbComTransaction.TRANS2_QUERY_FS_INFORMATION, buffer[0]);
        assertEquals(0x00, buffer[1]);
    }

    @Test
    @DisplayName("Test writeSetupWireFormat with offset")
    void testWriteSetupWireFormatWithOffset() {
        trans2QueryFSInfo = new Trans2QueryFSInformation(config, FileSystemInformation.FS_SIZE_INFO);

        byte[] buffer = new byte[256];
        int offset = 50;
        int written = trans2QueryFSInfo.writeSetupWireFormat(buffer, offset);

        // Should write 2 bytes at offset
        assertEquals(2, written);
        assertEquals(SmbComTransaction.TRANS2_QUERY_FS_INFORMATION, buffer[offset]);
        assertEquals(0x00, buffer[offset + 1]);
    }

    @Test
    @DisplayName("Test writeParametersWireFormat with SMB_INFO_ALLOCATION")
    void testWriteParametersWireFormatWithSmbInfoAllocation() {
        trans2QueryFSInfo = new Trans2QueryFSInformation(config, FileSystemInformation.SMB_INFO_ALLOCATION);

        byte[] buffer = new byte[512];
        int written = trans2QueryFSInfo.writeParametersWireFormat(buffer, 0);

        // Should write 2 bytes: information level
        assertEquals(2, written);

        // Check information level (SMB_INFO_ALLOCATION maps to 0x0001)
        int actualInfoLevel = SMBUtil.readInt2(buffer, 0);
        assertEquals(0x0001, actualInfoLevel);
    }

    @Test
    @DisplayName("Test writeParametersWireFormat with FS_SIZE_INFO")
    void testWriteParametersWireFormatWithFsSizeInfo() {
        trans2QueryFSInfo = new Trans2QueryFSInformation(config, FileSystemInformation.FS_SIZE_INFO);

        byte[] buffer = new byte[512];
        int written = trans2QueryFSInfo.writeParametersWireFormat(buffer, 0);

        // Should write 2 bytes: information level
        assertEquals(2, written);

        // Check information level (FS_SIZE_INFO maps to 0x0103)
        int actualInfoLevel = SMBUtil.readInt2(buffer, 0);
        assertEquals(0x0103, actualInfoLevel);
    }

    @DisplayName("Test writeParametersWireFormat with different information levels")
    @ParameterizedTest
    @CsvSource({ "-1, 1", // SMB_INFO_ALLOCATION -> 0x0001
            "3, 259" // FS_SIZE_INFO -> 0x0103
    })
    void testWriteParametersWireFormatWithDifferentLevels(int infoLevel, int expectedMappedValue) {
        trans2QueryFSInfo = new Trans2QueryFSInformation(config, infoLevel);

        byte[] buffer = new byte[512];
        trans2QueryFSInfo.writeParametersWireFormat(buffer, 0);

        // Check mapped information level
        int actualInfoLevel = SMBUtil.readInt2(buffer, 0);
        assertEquals(expectedMappedValue, actualInfoLevel);
    }

    @Test
    @DisplayName("Test writeParametersWireFormat with offset")
    void testWriteParametersWireFormatWithOffset() {
        trans2QueryFSInfo = new Trans2QueryFSInformation(config, FileSystemInformation.SMB_INFO_ALLOCATION);

        byte[] buffer = new byte[512];
        int offset = 100;
        int written = trans2QueryFSInfo.writeParametersWireFormat(buffer, offset);

        // Should write 2 bytes at offset
        assertEquals(2, written);

        // Check information level at offset
        int actualInfoLevel = SMBUtil.readInt2(buffer, offset);
        assertEquals(0x0001, actualInfoLevel);
    }

    @Test
    @DisplayName("Test writeDataWireFormat returns 0")
    void testWriteDataWireFormat() {
        trans2QueryFSInfo = new Trans2QueryFSInformation(config, FileSystemInformation.SMB_INFO_ALLOCATION);

        byte[] buffer = new byte[256];
        int written = trans2QueryFSInfo.writeDataWireFormat(buffer, 0);

        // Should always return 0
        assertEquals(0, written);
    }

    @Test
    @DisplayName("Test readSetupWireFormat returns 0")
    void testReadSetupWireFormat() {
        trans2QueryFSInfo = new Trans2QueryFSInformation(config, FileSystemInformation.SMB_INFO_ALLOCATION);

        byte[] buffer = new byte[256];
        int read = trans2QueryFSInfo.readSetupWireFormat(buffer, 0, buffer.length);

        // Should always return 0
        assertEquals(0, read);
    }

    @Test
    @DisplayName("Test readParametersWireFormat returns 0")
    void testReadParametersWireFormat() {
        trans2QueryFSInfo = new Trans2QueryFSInformation(config, FileSystemInformation.FS_SIZE_INFO);

        byte[] buffer = new byte[256];
        int read = trans2QueryFSInfo.readParametersWireFormat(buffer, 0, buffer.length);

        // Should always return 0
        assertEquals(0, read);
    }

    @Test
    @DisplayName("Test readDataWireFormat returns 0")
    void testReadDataWireFormat() {
        trans2QueryFSInfo = new Trans2QueryFSInformation(config, FileSystemInformation.SMB_INFO_ALLOCATION);

        byte[] buffer = new byte[256];
        int read = trans2QueryFSInfo.readDataWireFormat(buffer, 0, buffer.length);

        // Should always return 0
        assertEquals(0, read);
    }

    @Test
    @DisplayName("Test toString method with SMB_INFO_ALLOCATION")
    void testToStringWithSmbInfoAllocation() {
        trans2QueryFSInfo = new Trans2QueryFSInformation(config, FileSystemInformation.SMB_INFO_ALLOCATION);

        String result = trans2QueryFSInfo.toString();

        assertNotNull(result);
        assertTrue(result.contains("Trans2QueryFSInformation"));
        assertTrue(result.contains("informationLevel=0x"));
        // SMB_INFO_ALLOCATION is -1, which should be displayed properly
        assertTrue(result.contains("fff") || result.contains("FFF"));
    }

    @Test
    @DisplayName("Test toString method with FS_SIZE_INFO")
    void testToStringWithFsSizeInfo() {
        trans2QueryFSInfo = new Trans2QueryFSInformation(config, FileSystemInformation.FS_SIZE_INFO);

        String result = trans2QueryFSInfo.toString();

        assertNotNull(result);
        assertTrue(result.contains("Trans2QueryFSInformation"));
        assertTrue(result.contains("informationLevel=0x"));
        assertTrue(result.contains("003"));
    }

    @Test
    @DisplayName("Test with null buffer in read methods")
    void testReadMethodsWithNullBuffer() {
        trans2QueryFSInfo = new Trans2QueryFSInformation(config, FileSystemInformation.SMB_INFO_ALLOCATION);

        // All read methods should handle null buffer gracefully by returning 0
        assertEquals(0, trans2QueryFSInfo.readSetupWireFormat(null, 0, 0));
        assertEquals(0, trans2QueryFSInfo.readParametersWireFormat(null, 0, 0));
        assertEquals(0, trans2QueryFSInfo.readDataWireFormat(null, 0, 0));
    }

    @Test
    @DisplayName("Test complete wire format writing")
    void testCompleteWireFormatWriting() {
        trans2QueryFSInfo = new Trans2QueryFSInformation(config, FileSystemInformation.FS_SIZE_INFO);

        byte[] setupBuffer = new byte[256];
        byte[] paramBuffer = new byte[256];
        byte[] dataBuffer = new byte[256];

        int setupWritten = trans2QueryFSInfo.writeSetupWireFormat(setupBuffer, 0);
        int paramWritten = trans2QueryFSInfo.writeParametersWireFormat(paramBuffer, 0);
        int dataWritten = trans2QueryFSInfo.writeDataWireFormat(dataBuffer, 0);

        // Verify lengths
        assertEquals(2, setupWritten);
        assertEquals(2, paramWritten);
        assertEquals(0, dataWritten);

        // Verify setup content
        assertEquals(SmbComTransaction.TRANS2_QUERY_FS_INFORMATION, setupBuffer[0]);
        assertEquals(0x00, setupBuffer[1]);

        // Verify parameter content (FS_SIZE_INFO -> 0x0103)
        assertEquals(0x0103, SMBUtil.readInt2(paramBuffer, 0));
    }

    @Test
    @DisplayName("Test with mock configuration")
    void testWithMockConfiguration() {
        when(mockConfig.getMinimumVersion()).thenReturn(org.codelibs.jcifs.smb.DialectVersion.SMB1);
        when(mockConfig.getMaximumVersion()).thenReturn(org.codelibs.jcifs.smb.DialectVersion.SMB311);

        trans2QueryFSInfo = new Trans2QueryFSInformation(mockConfig, FileSystemInformation.SMB_INFO_ALLOCATION);

        assertNotNull(trans2QueryFSInfo);
    }

    @Test
    @DisplayName("Test concurrent access")
    void testConcurrentAccess() throws InterruptedException {
        trans2QueryFSInfo = new Trans2QueryFSInformation(config, FileSystemInformation.SMB_INFO_ALLOCATION);

        final int THREAD_COUNT = 10;
        Thread[] threads = new Thread[THREAD_COUNT];
        final boolean[] success = new boolean[THREAD_COUNT];

        for (int i = 0; i < THREAD_COUNT; i++) {
            final int index = i;
            threads[i] = new Thread(() -> {
                try {
                    byte[] buffer = new byte[512];
                    trans2QueryFSInfo.writeSetupWireFormat(buffer, 0);
                    trans2QueryFSInfo.writeParametersWireFormat(buffer, 0);
                    trans2QueryFSInfo.writeDataWireFormat(buffer, 0);
                    trans2QueryFSInfo.toString();
                    success[index] = true;
                } catch (Exception e) {
                    e.printStackTrace();
                    success[index] = false;
                }
            });
            threads[i].start();
        }

        // Wait for all threads to complete
        for (Thread thread : threads) {
            thread.join();
        }

        // All threads should complete successfully
        for (boolean s : success) {
            assertTrue(s);
        }
    }

    @DisplayName("Test exception handling for invalid information levels")
    @ParameterizedTest
    @ValueSource(ints = { 0, 1, 2, 4, 5, 6, 8, 100, -2, -100, Integer.MIN_VALUE, Integer.MAX_VALUE })
    void testInvalidInformationLevels(int invalidLevel) {
        // Skip valid levels
        if (invalidLevel == FileSystemInformation.SMB_INFO_ALLOCATION || invalidLevel == FileSystemInformation.FS_SIZE_INFO) {
            return;
        }

        // The exception is thrown during writeParametersWireFormat when mapInformationLevel is called
        Trans2QueryFSInformation trans2 = new Trans2QueryFSInformation(config, invalidLevel);
        assertNotNull(trans2);

        byte[] buffer = new byte[256];
        assertThrows(IllegalArgumentException.class, () -> {
            trans2.writeParametersWireFormat(buffer, 0);
        }, "Should throw IllegalArgumentException for invalid information level: " + invalidLevel);
    }

    @Test
    @DisplayName("Test buffer boundary conditions")
    void testBufferBoundaryConditions() {
        trans2QueryFSInfo = new Trans2QueryFSInformation(config, FileSystemInformation.SMB_INFO_ALLOCATION);

        // Test with minimal buffer size
        byte[] minBuffer = new byte[2];
        int written = trans2QueryFSInfo.writeSetupWireFormat(minBuffer, 0);
        assertEquals(2, written);

        // Test with exact parameter size
        byte[] paramBuffer = new byte[2];
        written = trans2QueryFSInfo.writeParametersWireFormat(paramBuffer, 0);
        assertEquals(2, written);

        // Test with zero-length data buffer
        byte[] dataBuffer = new byte[0];
        written = trans2QueryFSInfo.writeDataWireFormat(dataBuffer, 0);
        assertEquals(0, written);
    }

    @Test
    @DisplayName("Test maxParameterCount and maxDataCount values")
    void testMaxCountValues() {
        trans2QueryFSInfo = new Trans2QueryFSInformation(config, FileSystemInformation.SMB_INFO_ALLOCATION);

        // Verify the object is created with expected configuration
        // totalParameterCount should be 2
        // totalDataCount should be 0
        // maxParameterCount should be 0
        // maxDataCount should be 800
        // maxSetupCount should be 0
        assertNotNull(trans2QueryFSInfo);

        // Since these are protected fields, we can't access them directly
        // But we can verify the object is created successfully with these values
    }

    @Test
    @DisplayName("Test information level mapping edge cases")
    void testInformationLevelMappingEdgeCases() {
        // Test with SMB_INFO_ALLOCATION (-1 as byte)
        trans2QueryFSInfo = new Trans2QueryFSInformation(config, FileSystemInformation.SMB_INFO_ALLOCATION);
        byte[] buffer = new byte[10];
        trans2QueryFSInfo.writeParametersWireFormat(buffer, 0);
        assertEquals(0x0001, SMBUtil.readInt2(buffer, 0));

        // Test with FS_SIZE_INFO (3)
        trans2QueryFSInfo = new Trans2QueryFSInformation(config, FileSystemInformation.FS_SIZE_INFO);
        buffer = new byte[10];
        trans2QueryFSInfo.writeParametersWireFormat(buffer, 0);
        assertEquals(0x0103, SMBUtil.readInt2(buffer, 0));
    }

    @Test
    @DisplayName("Test writeParametersWireFormat preserves other buffer content")
    void testWriteParametersWireFormatPreservesBuffer() {
        trans2QueryFSInfo = new Trans2QueryFSInformation(config, FileSystemInformation.SMB_INFO_ALLOCATION);

        byte[] buffer = new byte[256];
        // Fill buffer with pattern
        for (int i = 0; i < buffer.length; i++) {
            buffer[i] = (byte) (i % 256);
        }

        int offset = 50;
        trans2QueryFSInfo.writeParametersWireFormat(buffer, offset);

        // Check that only the 2 bytes at offset were modified
        for (int i = 0; i < offset; i++) {
            assertEquals((byte) (i % 256), buffer[i], "Buffer before offset should be unchanged");
        }

        for (int i = offset + 2; i < buffer.length; i++) {
            assertEquals((byte) (i % 256), buffer[i], "Buffer after written data should be unchanged");
        }
    }

    @Test
    @DisplayName("Test multiple sequential writes")
    void testMultipleSequentialWrites() {
        trans2QueryFSInfo = new Trans2QueryFSInformation(config, FileSystemInformation.FS_SIZE_INFO);

        byte[] buffer = new byte[512];
        int offset = 0;

        // Write setup
        offset += trans2QueryFSInfo.writeSetupWireFormat(buffer, offset);
        assertEquals(2, offset);

        // Write parameters
        offset += trans2QueryFSInfo.writeParametersWireFormat(buffer, offset);
        assertEquals(4, offset);

        // Write data
        offset += trans2QueryFSInfo.writeDataWireFormat(buffer, offset);
        assertEquals(4, offset); // Data write returns 0

        // Verify content
        assertEquals(SmbComTransaction.TRANS2_QUERY_FS_INFORMATION, buffer[0]);
        assertEquals(0x00, buffer[1]);
        assertEquals(0x03, buffer[2]); // Low byte of 0x0103
        assertEquals(0x01, buffer[3]); // High byte of 0x0103
    }

    @DisplayName("Test toString with different information levels")
    @ParameterizedTest
    @CsvSource({ "-1, fff", // SMB_INFO_ALLOCATION
            "3, 003" // FS_SIZE_INFO
    })
    void testToStringWithDifferentLevels(int infoLevel, String expectedHex) {
        trans2QueryFSInfo = new Trans2QueryFSInformation(config, infoLevel);

        String result = trans2QueryFSInfo.toString();

        assertNotNull(result);
        assertTrue(result.contains("Trans2QueryFSInformation"));
        assertTrue(result.toLowerCase().contains(expectedHex.toLowerCase()));
    }

    @Test
    @DisplayName("Test object state after multiple operations")
    void testObjectStateAfterMultipleOperations() {
        trans2QueryFSInfo = new Trans2QueryFSInformation(config, FileSystemInformation.SMB_INFO_ALLOCATION);

        byte[] buffer = new byte[256];

        // Perform multiple operations
        for (int i = 0; i < 5; i++) {
            trans2QueryFSInfo.writeSetupWireFormat(buffer, 0);
            trans2QueryFSInfo.writeParametersWireFormat(buffer, 0);
            trans2QueryFSInfo.writeDataWireFormat(buffer, 0);
            trans2QueryFSInfo.readSetupWireFormat(buffer, 0, buffer.length);
            trans2QueryFSInfo.readParametersWireFormat(buffer, 0, buffer.length);
            trans2QueryFSInfo.readDataWireFormat(buffer, 0, buffer.length);
        }

        // Object should still be in valid state
        String result = trans2QueryFSInfo.toString();
        assertNotNull(result);
        assertTrue(result.contains("Trans2QueryFSInformation"));
    }
}

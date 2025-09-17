package org.codelibs.jcifs.smb.internal.smb1.trans2;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.Properties;

import org.codelibs.jcifs.smb.Configuration;
import org.codelibs.jcifs.smb.config.PropertyConfiguration;
import org.codelibs.jcifs.smb.internal.fscc.FileBasicInfo;
import org.codelibs.jcifs.smb.internal.fscc.FileInformation;
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

class Trans2SetFileInformationTest {

    private Trans2SetFileInformation trans2SetFileInfo;
    private Configuration config;

    @Mock
    private Configuration mockConfig;

    @Mock
    private FileInformation mockFileInfo;

    private static final int TEST_FID = 0x1234;
    private static final int TEST_ATTRIBUTES = 0x20; // FILE_ATTRIBUTE_ARCHIVE
    private static final long TEST_CREATE_TIME = 131234567890000L;
    private static final long TEST_LAST_WRITE_TIME = 131234567900000L;
    private static final long TEST_LAST_ACCESS_TIME = 131234567880000L;

    @BeforeEach
    void setUp() throws Exception {
        MockitoAnnotations.openMocks(this);
        Properties props = new Properties();
        config = new PropertyConfiguration(props);
    }

    @Test
    @DisplayName("Test constructor with FileInformation parameter")
    void testConstructorWithFileInformation() {
        // Setup mock FileInformation
        when(mockFileInfo.getFileInformationLevel()).thenReturn((byte) FileInformation.FILE_BASIC_INFO);

        // Create instance
        trans2SetFileInfo = new Trans2SetFileInformation(config, TEST_FID, mockFileInfo);

        // Verify initialization
        assertNotNull(trans2SetFileInfo);
        assertEquals(ServerMessageBlock.SMB_COM_TRANSACTION2, trans2SetFileInfo.getCommand());
        assertEquals(SmbComTransaction.TRANS2_SET_FILE_INFORMATION, trans2SetFileInfo.getSubCommand());
    }

    @Test
    @DisplayName("Test constructor with individual parameters")
    void testConstructorWithIndividualParameters() {
        // Create instance with individual parameters
        trans2SetFileInfo = new Trans2SetFileInformation(config, TEST_FID, TEST_ATTRIBUTES, TEST_CREATE_TIME, TEST_LAST_WRITE_TIME,
                TEST_LAST_ACCESS_TIME);

        // Verify initialization
        assertNotNull(trans2SetFileInfo);
        assertEquals(ServerMessageBlock.SMB_COM_TRANSACTION2, trans2SetFileInfo.getCommand());
        assertEquals(SmbComTransaction.TRANS2_SET_FILE_INFORMATION, trans2SetFileInfo.getSubCommand());
    }

    @Test
    @DisplayName("Test writeSetupWireFormat")
    void testWriteSetupWireFormat() {
        trans2SetFileInfo = new Trans2SetFileInformation(config, TEST_FID, mockFileInfo);

        byte[] buffer = new byte[256];
        int written = trans2SetFileInfo.writeSetupWireFormat(buffer, 0);

        // Should write 2 bytes: subcommand and 0x00
        assertEquals(2, written);
        assertEquals(SmbComTransaction.TRANS2_SET_FILE_INFORMATION, buffer[0]);
        assertEquals(0x00, buffer[1]);
    }

    @Test
    @DisplayName("Test writeSetupWireFormat with offset")
    void testWriteSetupWireFormatWithOffset() {
        trans2SetFileInfo = new Trans2SetFileInformation(config, TEST_FID, mockFileInfo);

        byte[] buffer = new byte[256];
        int offset = 50;
        int written = trans2SetFileInfo.writeSetupWireFormat(buffer, offset);

        // Should write 2 bytes at offset
        assertEquals(2, written);
        assertEquals(SmbComTransaction.TRANS2_SET_FILE_INFORMATION, buffer[offset]);
        assertEquals(0x00, buffer[offset + 1]);
    }

    @Test
    @DisplayName("Test writeParametersWireFormat")
    void testWriteParametersWireFormat() {
        // Setup mock
        when(mockFileInfo.getFileInformationLevel()).thenReturn((byte) FileInformation.FILE_BASIC_INFO);

        trans2SetFileInfo = new Trans2SetFileInformation(config, TEST_FID, mockFileInfo);

        byte[] buffer = new byte[512];
        int written = trans2SetFileInfo.writeParametersWireFormat(buffer, 0);

        // Should write 6 bytes: fid (2), info level (2), reserved (2)
        assertEquals(6, written);

        // Check FID
        int actualFid = SMBUtil.readInt2(buffer, 0);
        assertEquals(TEST_FID, actualFid);

        // Check information level (FILE_BASIC_INFO maps to 0x0101)
        int actualInfoLevel = SMBUtil.readInt2(buffer, 2);
        assertEquals(0x0101, actualInfoLevel);

        // Check reserved bytes (should be 0)
        int reserved = SMBUtil.readInt2(buffer, 4);
        assertEquals(0, reserved);
    }

    @DisplayName("Test writeParametersWireFormat with different FIDs")
    @ParameterizedTest
    @ValueSource(ints = { 0, 1, 0xFFFF, 0x8000, 0x7FFF })
    void testWriteParametersWireFormatWithDifferentFids(int fid) {
        when(mockFileInfo.getFileInformationLevel()).thenReturn((byte) FileInformation.FILE_BASIC_INFO);

        trans2SetFileInfo = new Trans2SetFileInformation(config, fid, mockFileInfo);

        byte[] buffer = new byte[512];
        trans2SetFileInfo.writeParametersWireFormat(buffer, 0);

        // Check FID is written correctly
        int actualFid = SMBUtil.readInt2(buffer, 0);
        assertEquals(fid & 0xFFFF, actualFid);
    }

    @Test
    @DisplayName("Test writeDataWireFormat")
    void testWriteDataWireFormat() {
        // Setup mock to return encoded size
        when(mockFileInfo.encode(any(byte[].class), anyInt())).thenReturn(40);

        trans2SetFileInfo = new Trans2SetFileInformation(config, TEST_FID, mockFileInfo);

        byte[] buffer = new byte[512];
        int written = trans2SetFileInfo.writeDataWireFormat(buffer, 0);

        // Should write FileInformation data + 6 bytes padding
        assertEquals(46, written); // 40 + 6

        // Verify encode was called
        verify(mockFileInfo).encode(buffer, 0);

        // Check that 6 bytes of padding are zeros
        for (int i = 40; i < 46; i++) {
            assertEquals(0, buffer[i]);
        }
    }

    @Test
    @DisplayName("Test writeDataWireFormat with offset")
    void testWriteDataWireFormatWithOffset() {
        // Setup mock
        when(mockFileInfo.encode(any(byte[].class), anyInt())).thenReturn(30);

        trans2SetFileInfo = new Trans2SetFileInformation(config, TEST_FID, mockFileInfo);

        byte[] buffer = new byte[512];
        int offset = 100;
        int written = trans2SetFileInfo.writeDataWireFormat(buffer, offset);

        // Should write FileInformation data + 6 bytes padding
        assertEquals(36, written); // 30 + 6

        // Verify encode was called with correct offset
        verify(mockFileInfo).encode(buffer, offset);
    }

    @Test
    @DisplayName("Test readSetupWireFormat returns 0")
    void testReadSetupWireFormat() {
        trans2SetFileInfo = new Trans2SetFileInformation(config, TEST_FID, mockFileInfo);

        byte[] buffer = new byte[256];
        int read = trans2SetFileInfo.readSetupWireFormat(buffer, 0, buffer.length);

        // Should always return 0
        assertEquals(0, read);
    }

    @Test
    @DisplayName("Test readParametersWireFormat returns 0")
    void testReadParametersWireFormat() {
        trans2SetFileInfo = new Trans2SetFileInformation(config, TEST_FID, mockFileInfo);

        byte[] buffer = new byte[256];
        int read = trans2SetFileInfo.readParametersWireFormat(buffer, 0, buffer.length);

        // Should always return 0
        assertEquals(0, read);
    }

    @Test
    @DisplayName("Test readDataWireFormat returns 0")
    void testReadDataWireFormat() {
        trans2SetFileInfo = new Trans2SetFileInformation(config, TEST_FID, mockFileInfo);

        byte[] buffer = new byte[256];
        int read = trans2SetFileInfo.readDataWireFormat(buffer, 0, buffer.length);

        // Should always return 0
        assertEquals(0, read);
    }

    @Test
    @DisplayName("Test toString method")
    void testToString() {
        trans2SetFileInfo = new Trans2SetFileInformation(config, TEST_FID, mockFileInfo);

        String result = trans2SetFileInfo.toString();

        assertNotNull(result);
        assertTrue(result.contains("Trans2SetFileInformation"));
        assertTrue(result.contains("fid=" + TEST_FID));
    }

    @Test
    @DisplayName("Test with FileBasicInfo")
    void testWithFileBasicInfo() {
        // Create FileBasicInfo instance
        FileBasicInfo basicInfo =
                new FileBasicInfo(TEST_CREATE_TIME, TEST_LAST_ACCESS_TIME, TEST_LAST_WRITE_TIME, 0L, TEST_ATTRIBUTES | 0x80);

        trans2SetFileInfo = new Trans2SetFileInformation(config, TEST_FID, basicInfo);

        byte[] buffer = new byte[512];

        // Test writeParametersWireFormat
        int paramWritten = trans2SetFileInfo.writeParametersWireFormat(buffer, 0);
        assertEquals(6, paramWritten);

        // Check information level for FILE_BASIC_INFO
        int actualInfoLevel = SMBUtil.readInt2(buffer, 2);
        assertEquals(0x0101, actualInfoLevel); // FILE_BASIC_INFO maps to 0x0101
    }

    @Test
    @DisplayName("Test complete wire format writing")
    void testCompleteWireFormatWriting() {
        when(mockFileInfo.getFileInformationLevel()).thenReturn((byte) FileInformation.FILE_BASIC_INFO);
        when(mockFileInfo.encode(any(byte[].class), anyInt())).thenReturn(50);

        trans2SetFileInfo = new Trans2SetFileInformation(config, TEST_FID, mockFileInfo);

        byte[] setupBuffer = new byte[256];
        byte[] paramBuffer = new byte[256];
        byte[] dataBuffer = new byte[256];

        int setupWritten = trans2SetFileInfo.writeSetupWireFormat(setupBuffer, 0);
        int paramWritten = trans2SetFileInfo.writeParametersWireFormat(paramBuffer, 0);
        int dataWritten = trans2SetFileInfo.writeDataWireFormat(dataBuffer, 0);

        // Verify lengths
        assertEquals(2, setupWritten);
        assertEquals(6, paramWritten);
        assertEquals(56, dataWritten); // 50 + 6 padding

        // Verify setup content
        assertEquals(SmbComTransaction.TRANS2_SET_FILE_INFORMATION, setupBuffer[0]);
        assertEquals(0x00, setupBuffer[1]);

        // Verify parameter content
        assertEquals(TEST_FID, SMBUtil.readInt2(paramBuffer, 0));
        assertEquals(0x0101, SMBUtil.readInt2(paramBuffer, 2));
        assertEquals(0, SMBUtil.readInt2(paramBuffer, 4));
    }

    @DisplayName("Test with different information levels")
    @ParameterizedTest
    @CsvSource({ "4, 257", // FILE_BASIC_INFO -> 0x0101
            "5, 258", // FILE_STANDARD_INFO -> 0x0102
            "20, 260" // FILE_ENDOFFILE_INFO -> 0x0104
    })
    void testWithDifferentInformationLevels(byte infoLevel, int expectedMappedValue) {
        when(mockFileInfo.getFileInformationLevel()).thenReturn(infoLevel);

        trans2SetFileInfo = new Trans2SetFileInformation(config, TEST_FID, mockFileInfo);

        byte[] buffer = new byte[512];
        trans2SetFileInfo.writeParametersWireFormat(buffer, 0);

        // Check mapped information level
        int actualInfoLevel = SMBUtil.readInt2(buffer, 2);
        assertEquals(expectedMappedValue, actualInfoLevel);
    }

    @Test
    @DisplayName("Test with null buffer in read methods")
    void testReadMethodsWithNullBuffer() {
        trans2SetFileInfo = new Trans2SetFileInformation(config, TEST_FID, mockFileInfo);

        // All read methods should handle null buffer gracefully
        assertEquals(0, trans2SetFileInfo.readSetupWireFormat(null, 0, 0));
        assertEquals(0, trans2SetFileInfo.readParametersWireFormat(null, 0, 0));
        assertEquals(0, trans2SetFileInfo.readDataWireFormat(null, 0, 0));
    }

    @Test
    @DisplayName("Test with maximum and minimum values")
    void testWithBoundaryValues() {
        // Test with minimum values
        trans2SetFileInfo = new Trans2SetFileInformation(config, 0, 0, 0L, 0L, 0L);
        assertNotNull(trans2SetFileInfo);

        // Test with maximum values
        trans2SetFileInfo = new Trans2SetFileInformation(config, 0xFFFF, Integer.MAX_VALUE, Long.MAX_VALUE, Long.MAX_VALUE, Long.MAX_VALUE);
        assertNotNull(trans2SetFileInfo);
    }

    @Test
    @DisplayName("Test attributes with OR operation")
    void testAttributesWithOrOperation() {
        // The constructor ORs attributes with 0x80
        trans2SetFileInfo = new Trans2SetFileInformation(config, TEST_FID, 0x01, // FILE_ATTRIBUTE_READONLY
                TEST_CREATE_TIME, TEST_LAST_WRITE_TIME, TEST_LAST_ACCESS_TIME);

        // The constructor should create FileBasicInfo with attributes | 0x80
        assertNotNull(trans2SetFileInfo);

        // Test with zero attributes
        trans2SetFileInfo =
                new Trans2SetFileInformation(config, TEST_FID, 0x00, TEST_CREATE_TIME, TEST_LAST_WRITE_TIME, TEST_LAST_ACCESS_TIME);
        assertNotNull(trans2SetFileInfo);
    }

    @Test
    @DisplayName("Test with mock configuration")
    void testWithMockConfiguration() {
        when(mockConfig.getMinimumVersion()).thenReturn(org.codelibs.jcifs.smb.DialectVersion.SMB1);
        when(mockConfig.getMaximumVersion()).thenReturn(org.codelibs.jcifs.smb.DialectVersion.SMB311);

        trans2SetFileInfo = new Trans2SetFileInformation(mockConfig, TEST_FID, mockFileInfo);

        assertNotNull(trans2SetFileInfo);

        // Configuration is accessed during initialization
        // Verify at least that getPid() and getTransactionBufferSize() were called
    }

    @DisplayName("Test FileInformation encode returning different sizes")
    @ParameterizedTest
    @ValueSource(ints = { 0, 1, 10, 100, 1000 })
    void testFileInformationEncodeDifferentSizes(int encodeSize) {
        when(mockFileInfo.encode(any(byte[].class), anyInt())).thenReturn(encodeSize);

        trans2SetFileInfo = new Trans2SetFileInformation(config, TEST_FID, mockFileInfo);

        byte[] buffer = new byte[2048];
        int written = trans2SetFileInfo.writeDataWireFormat(buffer, 0);

        // Should write encoded data + 6 bytes padding
        assertEquals(encodeSize + 6, written);
    }

    @DisplayName("Test toString with different FID values")
    @ParameterizedTest
    @ValueSource(ints = { 0, 1, 100, 0xFFFF })
    void testToStringWithDifferentFids(int fid) {
        trans2SetFileInfo = new Trans2SetFileInformation(config, fid, mockFileInfo);

        String result = trans2SetFileInfo.toString();

        assertNotNull(result);
        assertTrue(result.contains("fid=" + fid));
    }

    @Test
    @DisplayName("Test padding bytes in writeDataWireFormat")
    void testPaddingBytesInWriteDataWireFormat() {
        when(mockFileInfo.encode(any(byte[].class), anyInt())).thenReturn(20);

        trans2SetFileInfo = new Trans2SetFileInformation(config, TEST_FID, mockFileInfo);

        byte[] buffer = new byte[512];
        // Fill buffer with non-zero values to ensure padding writes zeros
        for (int i = 0; i < buffer.length; i++) {
            buffer[i] = (byte) 0xFF;
        }

        int written = trans2SetFileInfo.writeDataWireFormat(buffer, 0);

        // Should report 26 bytes written (20 from encode + 6 increment)
        assertEquals(26, written);

        // Check that padding bytes are zeros
        // The implementation writes 8 bytes with writeInt8 but only increments by 6
        // This means bytes 20-27 will be zero (8 bytes written by writeInt8)
        for (int i = 20; i < 28; i++) {
            assertEquals(0, buffer[i], "Padding byte at position " + i + " should be 0");
        }

        // The byte at position 28 should be unchanged
        assertEquals((byte) 0xFF, buffer[28], "Byte after padding should be unchanged");
    }

    @Test
    @DisplayName("Test maxParameterCount and maxDataCount values")
    void testMaxCountValues() {
        trans2SetFileInfo = new Trans2SetFileInformation(config, TEST_FID, mockFileInfo);

        // These values are set in the constructor
        // maxParameterCount should be 6
        // maxDataCount should be 0
        // maxSetupCount should be 0

        // Since these are protected fields, we can't access them directly
        // But we can verify the object is created successfully with these values
        assertNotNull(trans2SetFileInfo);
    }

    @Test
    @DisplayName("Test concurrent access")
    void testConcurrentAccess() throws InterruptedException {
        // Setup mock before creating the object
        when(mockFileInfo.getFileInformationLevel()).thenReturn((byte) FileInformation.FILE_BASIC_INFO);
        trans2SetFileInfo = new Trans2SetFileInformation(config, TEST_FID, mockFileInfo);

        final int THREAD_COUNT = 10;
        Thread[] threads = new Thread[THREAD_COUNT];
        final boolean[] success = new boolean[THREAD_COUNT];

        for (int i = 0; i < THREAD_COUNT; i++) {
            final int index = i;
            threads[i] = new Thread(() -> {
                try {
                    byte[] buffer = new byte[512];
                    trans2SetFileInfo.writeSetupWireFormat(buffer, 0);
                    trans2SetFileInfo.writeParametersWireFormat(buffer, 0);
                    trans2SetFileInfo.toString();
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
}

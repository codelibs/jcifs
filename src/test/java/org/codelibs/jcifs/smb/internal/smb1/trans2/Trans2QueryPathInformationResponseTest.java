package org.codelibs.jcifs.smb.internal.smb1.trans2;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.codelibs.jcifs.smb.CIFSException;
import org.codelibs.jcifs.smb.Configuration;
import org.codelibs.jcifs.smb.internal.SMBProtocolDecodingException;
import org.codelibs.jcifs.smb.internal.fscc.FileBasicInfo;
import org.codelibs.jcifs.smb.internal.fscc.FileInformation;
import org.codelibs.jcifs.smb.internal.fscc.FileInternalInfo;
import org.codelibs.jcifs.smb.internal.fscc.FileStandardInfo;
import org.codelibs.jcifs.smb.internal.smb1.trans.SmbComTransaction;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

/**
 * Unit tests for Trans2QueryPathInformationResponse class
 */
class Trans2QueryPathInformationResponseTest {

    @Mock
    private Configuration mockConfig;

    private Trans2QueryPathInformationResponse response;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    @DisplayName("Test constructor with FILE_BASIC_INFO level")
    void testConstructorWithFileBasicInfo() {
        response = new Trans2QueryPathInformationResponse(mockConfig, FileInformation.FILE_BASIC_INFO);

        assertNotNull(response);
        assertEquals(SmbComTransaction.TRANS2_QUERY_PATH_INFORMATION, response.getSubCommand());
    }

    @Test
    @DisplayName("Test constructor with FILE_STANDARD_INFO level")
    void testConstructorWithFileStandardInfo() {
        response = new Trans2QueryPathInformationResponse(mockConfig, FileInformation.FILE_STANDARD_INFO);

        assertNotNull(response);
        assertEquals(SmbComTransaction.TRANS2_QUERY_PATH_INFORMATION, response.getSubCommand());
    }

    @Test
    @DisplayName("Test constructor with FILE_INTERNAL_INFO level")
    void testConstructorWithFileInternalInfo() {
        response = new Trans2QueryPathInformationResponse(mockConfig, FileInformation.FILE_INTERNAL_INFO);

        assertNotNull(response);
        assertEquals(SmbComTransaction.TRANS2_QUERY_PATH_INFORMATION, response.getSubCommand());
    }

    @Test
    @DisplayName("Test getInfo when info is null")
    void testGetInfoWhenNull() {
        response = new Trans2QueryPathInformationResponse(mockConfig, FileInformation.FILE_BASIC_INFO);

        assertNull(response.getInfo());
    }

    @Test
    @DisplayName("Test getInfo with type when info is null")
    void testGetInfoWithTypeWhenNull() {
        response = new Trans2QueryPathInformationResponse(mockConfig, FileInformation.FILE_BASIC_INFO);

        assertThrows(NullPointerException.class, () -> {
            response.getInfo(FileBasicInfo.class);
        });
    }

    @Test
    @DisplayName("Test getInfo with compatible type")
    void testGetInfoWithCompatibleType() throws Exception {
        response = new Trans2QueryPathInformationResponse(mockConfig, FileInformation.FILE_BASIC_INFO);

        // Simulate setting info through readDataWireFormat
        byte[] buffer = createMockFileBasicInfoBuffer();
        response.setDataCount(buffer.length);
        response.readDataWireFormat(buffer, 0, buffer.length);

        FileBasicInfo info = response.getInfo(FileBasicInfo.class);
        assertNotNull(info);
        assertTrue(info instanceof FileBasicInfo);
    }

    @Test
    @DisplayName("Test getInfo with incompatible type throws CIFSException")
    void testGetInfoWithIncompatibleType() throws Exception {
        response = new Trans2QueryPathInformationResponse(mockConfig, FileInformation.FILE_BASIC_INFO);

        // Simulate setting info through readDataWireFormat
        byte[] buffer = createMockFileBasicInfoBuffer();
        response.setDataCount(buffer.length);
        response.readDataWireFormat(buffer, 0, buffer.length);

        CIFSException exception = assertThrows(CIFSException.class, () -> {
            response.getInfo(FileInternalInfo.class);
        });

        assertEquals("Incompatible file information class", exception.getMessage());
    }

    @Test
    @DisplayName("Test writeSetupWireFormat returns 0")
    void testWriteSetupWireFormat() {
        response = new Trans2QueryPathInformationResponse(mockConfig, FileInformation.FILE_BASIC_INFO);
        byte[] dst = new byte[100];

        int result = response.writeSetupWireFormat(dst, 0);

        assertEquals(0, result);
    }

    @Test
    @DisplayName("Test writeParametersWireFormat returns 0")
    void testWriteParametersWireFormat() {
        response = new Trans2QueryPathInformationResponse(mockConfig, FileInformation.FILE_BASIC_INFO);
        byte[] dst = new byte[100];

        int result = response.writeParametersWireFormat(dst, 0);

        assertEquals(0, result);
    }

    @Test
    @DisplayName("Test writeDataWireFormat returns 0")
    void testWriteDataWireFormat() {
        response = new Trans2QueryPathInformationResponse(mockConfig, FileInformation.FILE_BASIC_INFO);
        byte[] dst = new byte[100];

        int result = response.writeDataWireFormat(dst, 0);

        assertEquals(0, result);
    }

    @Test
    @DisplayName("Test readSetupWireFormat returns 0")
    void testReadSetupWireFormat() {
        response = new Trans2QueryPathInformationResponse(mockConfig, FileInformation.FILE_BASIC_INFO);
        byte[] buffer = new byte[100];

        int result = response.readSetupWireFormat(buffer, 0, buffer.length);

        assertEquals(0, result);
    }

    @Test
    @DisplayName("Test readParametersWireFormat returns 2")
    void testReadParametersWireFormat() {
        response = new Trans2QueryPathInformationResponse(mockConfig, FileInformation.FILE_BASIC_INFO);
        byte[] buffer = new byte[100];

        int result = response.readParametersWireFormat(buffer, 0, buffer.length);

        assertEquals(2, result);
    }

    @ParameterizedTest
    @ValueSource(bytes = { FileInformation.FILE_BASIC_INFO, FileInformation.FILE_STANDARD_INFO, FileInformation.FILE_INTERNAL_INFO })
    @DisplayName("Test readDataWireFormat with different information levels")
    void testReadDataWireFormatWithDifferentLevels(byte infoLevel) throws SMBProtocolDecodingException {
        response = new Trans2QueryPathInformationResponse(mockConfig, infoLevel);

        byte[] buffer = createMockBuffer(infoLevel);
        response.setDataCount(buffer.length);

        int bytesRead = response.readDataWireFormat(buffer, 0, buffer.length);

        assertTrue(bytesRead > 0);
        assertNotNull(response.getInfo());

        // Verify the correct type was created
        if (infoLevel == FileInformation.FILE_BASIC_INFO) {
            assertTrue(response.getInfo() instanceof FileBasicInfo);
        } else if (infoLevel == FileInformation.FILE_STANDARD_INFO) {
            assertTrue(response.getInfo() instanceof FileStandardInfo);
        } else if (infoLevel == FileInformation.FILE_INTERNAL_INFO) {
            assertTrue(response.getInfo() instanceof FileInternalInfo);
        }
    }

    @Test
    @DisplayName("Test readDataWireFormat with unsupported information level")
    void testReadDataWireFormatWithUnsupportedLevel() throws SMBProtocolDecodingException {
        byte unsupportedLevel = (byte) 0xFF;
        response = new Trans2QueryPathInformationResponse(mockConfig, unsupportedLevel);

        byte[] buffer = new byte[100];
        response.setDataCount(buffer.length);

        int bytesRead = response.readDataWireFormat(buffer, 0, buffer.length);

        assertEquals(0, bytesRead);
        assertNull(response.getInfo());
    }

    @Test
    @DisplayName("Test readDataWireFormat with empty buffer throws exception")
    void testReadDataWireFormatWithEmptyBuffer() {
        response = new Trans2QueryPathInformationResponse(mockConfig, FileInformation.FILE_BASIC_INFO);

        byte[] buffer = new byte[0];
        response.setDataCount(0);

        // The implementation will try to decode even with an empty buffer, causing ArrayIndexOutOfBoundsException
        assertThrows(ArrayIndexOutOfBoundsException.class, () -> {
            response.readDataWireFormat(buffer, 0, 0);
        });
    }

    @Test
    @DisplayName("Test toString method")
    void testToString() {
        response = new Trans2QueryPathInformationResponse(mockConfig, FileInformation.FILE_BASIC_INFO);

        String result = response.toString();

        assertNotNull(result);
        assertTrue(result.startsWith("Trans2QueryPathInformationResponse["));
        assertTrue(result.endsWith("]"));
    }

    @Test
    @DisplayName("Test readDataWireFormat with partial buffer")
    void testReadDataWireFormatWithPartialBuffer() throws SMBProtocolDecodingException {
        response = new Trans2QueryPathInformationResponse(mockConfig, FileInformation.FILE_BASIC_INFO);

        byte[] buffer = createMockFileBasicInfoBuffer();
        response.setDataCount(buffer.length / 2); // Set data count to half the buffer

        int bytesRead = response.readDataWireFormat(buffer, 0, buffer.length);

        assertTrue(bytesRead > 0);
        assertNotNull(response.getInfo());
    }

    @Test
    @DisplayName("Test readDataWireFormat with offset")
    void testReadDataWireFormatWithOffset() throws SMBProtocolDecodingException {
        response = new Trans2QueryPathInformationResponse(mockConfig, FileInformation.FILE_BASIC_INFO);

        byte[] buffer = new byte[200];
        int offset = 50;
        byte[] infoData = createMockFileBasicInfoBuffer();
        System.arraycopy(infoData, 0, buffer, offset, infoData.length);
        response.setDataCount(infoData.length);

        int bytesRead = response.readDataWireFormat(buffer, offset, buffer.length - offset);

        assertTrue(bytesRead > 0);
        assertNotNull(response.getInfo());
    }

    // Helper methods to create mock buffers for different file information types

    private byte[] createMockFileBasicInfoBuffer() {
        // Create a buffer that represents FileBasicInfo data
        // FileBasicInfo typically contains creation time, last access time, last write time, change time, and attributes
        byte[] buffer = new byte[40];

        // Mock times (8 bytes each)
        for (int i = 0; i < 32; i++) {
            buffer[i] = (byte) (i % 256);
        }

        // Mock attributes (4 bytes)
        buffer[32] = 0x01;
        buffer[33] = 0x00;
        buffer[34] = 0x00;
        buffer[35] = 0x00;

        return buffer;
    }

    private byte[] createMockFileStandardInfoBuffer() {
        // Create a buffer that represents FileStandardInfo data
        byte[] buffer = new byte[24];

        // Mock allocation size (8 bytes)
        for (int i = 0; i < 8; i++) {
            buffer[i] = (byte) i;
        }

        // Mock end of file (8 bytes)
        for (int i = 8; i < 16; i++) {
            buffer[i] = (byte) (i * 2);
        }

        // Mock number of links (4 bytes)
        buffer[16] = 0x01;
        buffer[17] = 0x00;
        buffer[18] = 0x00;
        buffer[19] = 0x00;

        // Mock delete pending and directory flags
        buffer[20] = 0x00;
        buffer[21] = 0x00;

        return buffer;
    }

    private byte[] createMockFileInternalInfoBuffer() {
        // Create a buffer that represents FileInternalInfo data
        // FileInternalInfo contains an 8-byte index number
        byte[] buffer = new byte[8];

        for (int i = 0; i < 8; i++) {
            buffer[i] = (byte) (0xFF - i);
        }

        return buffer;
    }

    private byte[] createMockBuffer(byte infoLevel) {
        switch (infoLevel) {
        case FileInformation.FILE_BASIC_INFO:
            return createMockFileBasicInfoBuffer();
        case FileInformation.FILE_STANDARD_INFO:
            return createMockFileStandardInfoBuffer();
        case FileInformation.FILE_INTERNAL_INFO:
            return createMockFileInternalInfoBuffer();
        default:
            return new byte[0];
        }
    }

}
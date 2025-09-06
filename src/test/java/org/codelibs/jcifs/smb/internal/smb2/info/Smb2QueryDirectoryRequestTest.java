package org.codelibs.jcifs.smb.internal.smb2.info;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.nio.charset.StandardCharsets;

import org.codelibs.jcifs.smb.CIFSContext;
import org.codelibs.jcifs.smb.Configuration;
import org.codelibs.jcifs.smb.internal.smb2.Smb2Constants;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

/**
 * Test class for Smb2QueryDirectoryRequest
 */
class Smb2QueryDirectoryRequestTest {

    @Mock
    private Configuration mockConfig;

    @Mock
    private CIFSContext mockContext;

    private Smb2QueryDirectoryRequest request;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        when(mockConfig.getMaximumBufferSize()).thenReturn(65536);
        when(mockConfig.getListSize()).thenReturn(65536);
        when(mockContext.getConfig()).thenReturn(mockConfig);
    }

    @Test
    @DisplayName("Test constructor with configuration only")
    void testConstructorWithConfig() {
        request = new Smb2QueryDirectoryRequest(mockConfig);

        assertNotNull(request);
        assertEquals(14, request.getCommand());
        verify(mockConfig).getMaximumBufferSize();
        verify(mockConfig).getListSize();
    }

    @Test
    @DisplayName("Test constructor with configuration and fileId")
    void testConstructorWithConfigAndFileId() {
        byte[] fileId = new byte[16];
        for (int i = 0; i < 16; i++) {
            fileId[i] = (byte) i;
        }

        request = new Smb2QueryDirectoryRequest(mockConfig, fileId);

        assertNotNull(request);
        assertEquals(14, request.getCommand());
        verify(mockConfig).getMaximumBufferSize();
        verify(mockConfig).getListSize();
    }

    @Test
    @DisplayName("Test setFileId method")
    void testSetFileId() {
        request = new Smb2QueryDirectoryRequest(mockConfig);
        byte[] fileId = new byte[16];
        for (int i = 0; i < 16; i++) {
            fileId[i] = (byte) (i + 1);
        }

        request.setFileId(fileId);

        // Verify by writing to buffer and checking the fileId position
        byte[] buffer = new byte[1024];
        request.writeBytesWireFormat(buffer, Smb2Constants.SMB2_HEADER_LENGTH);

        // FileId is at offset 8 in the request structure
        for (int i = 0; i < 16; i++) {
            assertEquals(fileId[i], buffer[Smb2Constants.SMB2_HEADER_LENGTH + 8 + i]);
        }
    }

    @Test
    @DisplayName("Test setFileInformationClass method")
    void testSetFileInformationClass() {
        request = new Smb2QueryDirectoryRequest(mockConfig);

        request.setFileInformationClass(Smb2QueryDirectoryRequest.FILE_FULL_DIRECTORY_INFO);

        // Verify by writing to buffer and checking the fileInformationClass position
        byte[] buffer = new byte[1024];
        request.writeBytesWireFormat(buffer, Smb2Constants.SMB2_HEADER_LENGTH);

        // FileInformationClass is at offset 2 in the request structure
        assertEquals(Smb2QueryDirectoryRequest.FILE_FULL_DIRECTORY_INFO, buffer[Smb2Constants.SMB2_HEADER_LENGTH + 2]);
    }

    @Test
    @DisplayName("Test setQueryFlags method")
    void testSetQueryFlags() {
        request = new Smb2QueryDirectoryRequest(mockConfig);
        byte flags = Smb2QueryDirectoryRequest.SMB2_RESTART_SCANS | Smb2QueryDirectoryRequest.SMB2_RETURN_SINGLE_ENTRY;

        request.setQueryFlags(flags);

        // Verify by writing to buffer and checking the queryFlags position
        byte[] buffer = new byte[1024];
        request.writeBytesWireFormat(buffer, Smb2Constants.SMB2_HEADER_LENGTH);

        // QueryFlags is at offset 3 in the request structure
        assertEquals(flags, buffer[Smb2Constants.SMB2_HEADER_LENGTH + 3]);
    }

    @Test
    @DisplayName("Test setFileIndex method")
    void testSetFileIndex() {
        request = new Smb2QueryDirectoryRequest(mockConfig);
        int fileIndex = 0x12345678;

        request.setFileIndex(fileIndex);

        // Verify by writing to buffer and checking the fileIndex position
        byte[] buffer = new byte[1024];
        request.writeBytesWireFormat(buffer, Smb2Constants.SMB2_HEADER_LENGTH);

        // FileIndex is at offset 4 in the request structure
        int readIndex = (buffer[Smb2Constants.SMB2_HEADER_LENGTH + 4] & 0xFF) | ((buffer[Smb2Constants.SMB2_HEADER_LENGTH + 5] & 0xFF) << 8)
                | ((buffer[Smb2Constants.SMB2_HEADER_LENGTH + 6] & 0xFF) << 16)
                | ((buffer[Smb2Constants.SMB2_HEADER_LENGTH + 7] & 0xFF) << 24);
        assertEquals(fileIndex, readIndex);
    }

    @Test
    @DisplayName("Test setFileName method with null")
    void testSetFileNameNull() {
        request = new Smb2QueryDirectoryRequest(mockConfig);

        request.setFileName(null);

        // Verify size calculation doesn't include filename
        int expectedSize = Smb2Constants.SMB2_HEADER_LENGTH + 32;
        assertEquals(((expectedSize + 7) & ~7), request.size());
    }

    @Test
    @DisplayName("Test setFileName method with non-null value")
    void testSetFileNameNonNull() {
        request = new Smb2QueryDirectoryRequest(mockConfig);
        String fileName = "test.txt";

        request.setFileName(fileName);

        // Verify size calculation includes filename
        int expectedSize = Smb2Constants.SMB2_HEADER_LENGTH + 32 + (fileName.length() * 2);
        assertEquals(((expectedSize + 7) & ~7), request.size());
    }

    @Test
    @DisplayName("Test createResponse method")
    void testCreateResponse() {
        request = new Smb2QueryDirectoryRequest(mockConfig);
        request.setFileInformationClass(Smb2QueryDirectoryRequest.FILE_ID_BOTH_DIRECTORY_INFO);

        Smb2QueryDirectoryResponse response = request.createResponse(mockContext, request);

        assertNotNull(response);
        verify(mockContext).getConfig();
    }

    @Test
    @DisplayName("Test writeBytesWireFormat with all fields set")
    void testWriteBytesWireFormatComplete() {
        request = new Smb2QueryDirectoryRequest(mockConfig);

        // Set all fields
        byte[] fileId = new byte[16];
        for (int i = 0; i < 16; i++) {
            fileId[i] = (byte) (i * 2);
        }
        request.setFileId(fileId);
        request.setFileInformationClass(Smb2QueryDirectoryRequest.FILE_ID_FULL_DIRECTORY_INFO);
        request.setQueryFlags(Smb2QueryDirectoryRequest.SMB2_INDEX_SPECIFIED);
        request.setFileIndex(0xABCDEF01);
        request.setFileName("*.txt");

        byte[] buffer = new byte[1024];
        int bytesWritten = request.writeBytesWireFormat(buffer, Smb2Constants.SMB2_HEADER_LENGTH);

        // Verify structure size
        assertEquals(33, buffer[Smb2Constants.SMB2_HEADER_LENGTH] | (buffer[Smb2Constants.SMB2_HEADER_LENGTH + 1] << 8));

        // Verify file information class
        assertEquals(Smb2QueryDirectoryRequest.FILE_ID_FULL_DIRECTORY_INFO, buffer[Smb2Constants.SMB2_HEADER_LENGTH + 2]);

        // Verify query flags
        assertEquals(Smb2QueryDirectoryRequest.SMB2_INDEX_SPECIFIED, buffer[Smb2Constants.SMB2_HEADER_LENGTH + 3]);

        // Verify file index
        int readFileIndex =
                (buffer[Smb2Constants.SMB2_HEADER_LENGTH + 4] & 0xFF) | ((buffer[Smb2Constants.SMB2_HEADER_LENGTH + 5] & 0xFF) << 8)
                        | ((buffer[Smb2Constants.SMB2_HEADER_LENGTH + 6] & 0xFF) << 16)
                        | ((buffer[Smb2Constants.SMB2_HEADER_LENGTH + 7] & 0xFF) << 24);
        assertEquals(0xABCDEF01, readFileIndex);

        // Verify file ID
        for (int i = 0; i < 16; i++) {
            assertEquals(fileId[i], buffer[Smb2Constants.SMB2_HEADER_LENGTH + 8 + i]);
        }

        // Verify filename
        byte[] expectedFileName = "*.txt".getBytes(StandardCharsets.UTF_16LE);
        assertTrue(bytesWritten > 32);
        assertEquals(32 + expectedFileName.length, bytesWritten);
    }

    @Test
    @DisplayName("Test writeBytesWireFormat without fileName")
    void testWriteBytesWireFormatNoFileName() {
        request = new Smb2QueryDirectoryRequest(mockConfig);

        byte[] buffer = new byte[1024];
        int bytesWritten = request.writeBytesWireFormat(buffer, Smb2Constants.SMB2_HEADER_LENGTH);

        assertEquals(32, bytesWritten);

        // Verify filename offset and length are 0
        int fnOffset = buffer[Smb2Constants.SMB2_HEADER_LENGTH + 24] | (buffer[Smb2Constants.SMB2_HEADER_LENGTH + 25] << 8);
        int fnLength = buffer[Smb2Constants.SMB2_HEADER_LENGTH + 26] | (buffer[Smb2Constants.SMB2_HEADER_LENGTH + 27] << 8);

        assertEquals(0, fnOffset);
        assertEquals(0, fnLength);
    }

    @Test
    @DisplayName("Test readBytesWireFormat returns 0")
    void testReadBytesWireFormat() {
        request = new Smb2QueryDirectoryRequest(mockConfig);
        byte[] buffer = new byte[100];

        int bytesRead = request.readBytesWireFormat(buffer, 0);

        assertEquals(0, bytesRead);
    }

    @Test
    @DisplayName("Test size calculation with different buffer sizes")
    void testSizeCalculationWithDifferentBufferSizes() {
        // Test with smaller maximum buffer size
        when(mockConfig.getMaximumBufferSize()).thenReturn(8192);
        when(mockConfig.getListSize()).thenReturn(16384);

        request = new Smb2QueryDirectoryRequest(mockConfig);
        assertNotNull(request);

        // Test with smaller list size
        when(mockConfig.getMaximumBufferSize()).thenReturn(16384);
        when(mockConfig.getListSize()).thenReturn(8192);

        request = new Smb2QueryDirectoryRequest(mockConfig);
        assertNotNull(request);
    }

    @Test
    @DisplayName("Test all file information class constants")
    void testFileInformationClassConstants() {
        assertEquals(0x01, Smb2QueryDirectoryRequest.FILE_DIRECTORY_INFO);
        assertEquals(0x02, Smb2QueryDirectoryRequest.FILE_FULL_DIRECTORY_INFO);
        assertEquals(0x03, Smb2QueryDirectoryRequest.FILE_BOTH_DIRECTORY_INFO);
        assertEquals(0x0C, Smb2QueryDirectoryRequest.FILE_NAMES_INFO);
        assertEquals(0x24, Smb2QueryDirectoryRequest.FILE_ID_BOTH_DIRECTORY_INFO);
        assertEquals(0x26, Smb2QueryDirectoryRequest.FILE_ID_FULL_DIRECTORY_INFO);
    }

    @Test
    @DisplayName("Test all query flags constants")
    void testQueryFlagsConstants() {
        assertEquals(0x01, Smb2QueryDirectoryRequest.SMB2_RESTART_SCANS);
        assertEquals(0x02, Smb2QueryDirectoryRequest.SMB2_RETURN_SINGLE_ENTRY);
        assertEquals(0x04, Smb2QueryDirectoryRequest.SMB2_INDEX_SPECIFIED);
        assertEquals(0x10, Smb2QueryDirectoryRequest.SMB2_REOPEN);
    }

    @Test
    @DisplayName("Test with Unicode filename")
    void testUnicodeFileName() {
        request = new Smb2QueryDirectoryRequest(mockConfig);
        String unicodeFileName = "テスト文件.txt";

        request.setFileName(unicodeFileName);

        byte[] buffer = new byte[1024];
        int bytesWritten = request.writeBytesWireFormat(buffer, Smb2Constants.SMB2_HEADER_LENGTH);

        byte[] expectedBytes = unicodeFileName.getBytes(StandardCharsets.UTF_16LE);
        assertEquals(32 + expectedBytes.length, bytesWritten);

        // Verify filename length in header
        int fnLength = buffer[Smb2Constants.SMB2_HEADER_LENGTH + 26] | (buffer[Smb2Constants.SMB2_HEADER_LENGTH + 27] << 8);
        assertEquals(expectedBytes.length, fnLength);
    }

    @Test
    @DisplayName("Test with empty filename")
    void testEmptyFileName() {
        request = new Smb2QueryDirectoryRequest(mockConfig);
        request.setFileName("");

        byte[] buffer = new byte[1024];
        int bytesWritten = request.writeBytesWireFormat(buffer, Smb2Constants.SMB2_HEADER_LENGTH);

        assertEquals(32, bytesWritten);

        // Verify filename length is 0
        int fnLength = buffer[Smb2Constants.SMB2_HEADER_LENGTH + 26] | (buffer[Smb2Constants.SMB2_HEADER_LENGTH + 27] << 8);
        assertEquals(0, fnLength);
    }

    @Test
    @DisplayName("Test with wildcard patterns")
    void testWildcardPatterns() {
        request = new Smb2QueryDirectoryRequest(mockConfig);

        // Test various wildcard patterns
        String[] patterns = { "*", "*.txt", "test*.*", "?test?.doc" };

        for (String pattern : patterns) {
            request.setFileName(pattern);

            byte[] buffer = new byte[1024];
            int bytesWritten = request.writeBytesWireFormat(buffer, Smb2Constants.SMB2_HEADER_LENGTH);

            byte[] expectedBytes = pattern.getBytes(StandardCharsets.UTF_16LE);
            assertEquals(32 + expectedBytes.length, bytesWritten);
        }
    }

    @Test
    @DisplayName("Test combined query flags")
    void testCombinedQueryFlags() {
        request = new Smb2QueryDirectoryRequest(mockConfig);

        byte combinedFlags = (byte) (Smb2QueryDirectoryRequest.SMB2_RESTART_SCANS | Smb2QueryDirectoryRequest.SMB2_RETURN_SINGLE_ENTRY
                | Smb2QueryDirectoryRequest.SMB2_INDEX_SPECIFIED | Smb2QueryDirectoryRequest.SMB2_REOPEN);

        request.setQueryFlags(combinedFlags);

        byte[] buffer = new byte[1024];
        request.writeBytesWireFormat(buffer, Smb2Constants.SMB2_HEADER_LENGTH);

        assertEquals(combinedFlags, buffer[Smb2Constants.SMB2_HEADER_LENGTH + 3]);
    }
}

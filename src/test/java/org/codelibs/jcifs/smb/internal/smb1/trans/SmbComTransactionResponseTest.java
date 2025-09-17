package org.codelibs.jcifs.smb.internal.smb1.trans;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import org.codelibs.jcifs.smb.Configuration;
import org.codelibs.jcifs.smb.impl.FileEntry;
import org.codelibs.jcifs.smb.internal.SMBProtocolDecodingException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

/**
 * Test class for SmbComTransactionResponse
 */
class SmbComTransactionResponseTest {

    @Mock
    private Configuration mockConfig;

    @Mock
    private FileEntry mockFileEntry1;

    @Mock
    private FileEntry mockFileEntry2;

    private TestSmbComTransactionResponse response;

    // Test implementation of abstract SmbComTransactionResponse
    private static class TestSmbComTransactionResponse extends SmbComTransactionResponse {
        private int setupWireFormatReturn = 0;
        private int parametersWireFormatReturn = 0;
        private int dataWireFormatReturn = 0;
        private boolean throwExceptionOnReadParameters = false;
        private boolean throwExceptionOnReadData = false;

        public TestSmbComTransactionResponse(Configuration config) {
            super(config);
        }

        public TestSmbComTransactionResponse(Configuration config, byte command, byte subcommand) {
            super(config, command, subcommand);
        }

        // Expose errorCode setter for testing - access protected field directly
        public void setTestErrorCode(int code) {
            this.errorCode = code;
        }

        @Override
        protected int writeSetupWireFormat(byte[] dst, int dstIndex) {
            return setupWireFormatReturn;
        }

        @Override
        protected int writeParametersWireFormat(byte[] dst, int dstIndex) {
            return parametersWireFormatReturn;
        }

        @Override
        protected int writeDataWireFormat(byte[] dst, int dstIndex) {
            return dataWireFormatReturn;
        }

        @Override
        protected int readSetupWireFormat(byte[] buffer, int bufferIndex, int len) {
            return 0;
        }

        @Override
        protected int readParametersWireFormat(byte[] buffer, int bufferIndex, int len) throws SMBProtocolDecodingException {
            if (throwExceptionOnReadParameters) {
                throw new SMBProtocolDecodingException("Test exception in readParametersWireFormat");
            }
            return parametersWireFormatReturn;
        }

        @Override
        protected int readDataWireFormat(byte[] buffer, int bufferIndex, int len) throws SMBProtocolDecodingException {
            if (throwExceptionOnReadData) {
                throw new SMBProtocolDecodingException("Test exception in readDataWireFormat");
            }
            return dataWireFormatReturn;
        }

        // Helper methods for testing
        void setSetupWireFormatReturn(int value) {
            this.setupWireFormatReturn = value;
        }

        void setParametersWireFormatReturn(int value) {
            this.parametersWireFormatReturn = value;
        }

        void setDataWireFormatReturn(int value) {
            this.dataWireFormatReturn = value;
        }

        void setThrowExceptionOnReadParameters(boolean value) {
            this.throwExceptionOnReadParameters = value;
        }

        void setThrowExceptionOnReadData(boolean value) {
            this.throwExceptionOnReadData = value;
        }
    }

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        when(mockConfig.getMaximumBufferSize()).thenReturn(65535);
        when(mockConfig.getPid()).thenReturn(1234);
        response = new TestSmbComTransactionResponse(mockConfig);
    }

    @Test
    @DisplayName("Test constructor initialization with config only")
    void testConstructorWithConfigOnly() {
        TestSmbComTransactionResponse resp = new TestSmbComTransactionResponse(mockConfig);
        assertNotNull(resp);
        assertEquals(0, resp.getSubCommand());
    }

    @Test
    @DisplayName("Test constructor initialization with command and subcommand")
    void testConstructorWithCommandAndSubcommand() {
        byte command = (byte) 0x25;
        byte subcommand = (byte) 0x01;
        TestSmbComTransactionResponse resp = new TestSmbComTransactionResponse(mockConfig, command, subcommand);
        assertNotNull(resp);
        assertEquals(command, resp.getCommand());
        assertEquals(subcommand, resp.getSubCommand());
    }

    @Test
    @DisplayName("Test dataCount getter and setter")
    void testDataCountGetterSetter() {
        assertEquals(0, response.getDataCount());
        response.setDataCount(100);
        assertEquals(100, response.getDataCount());
    }

    @Test
    @DisplayName("Test buffer management")
    void testBufferManagement() {
        byte[] buffer = new byte[1024];
        buffer[0] = 0x42;
        buffer[1] = 0x43;

        response.setBuffer(buffer);

        byte[] released = response.releaseBuffer();
        assertSame(buffer, released);
        assertEquals(0x42, released[0]);
        assertEquals(0x43, released[1]);

        // After release, getting buffer again should return null
        assertNull(response.releaseBuffer());
    }

    @Test
    @DisplayName("Test subCommand getter and setter")
    void testSubCommandGetterSetter() {
        byte subcommand = (byte) 0x05;
        response.setSubCommand(subcommand);
        assertEquals(subcommand, response.getSubCommand());
    }

    @Test
    @DisplayName("Test status getter and setter")
    void testStatusGetterSetter() {
        assertEquals(0, response.getStatus());
        response.setStatus(404);
        assertEquals(404, response.getStatus());
    }

    @Test
    @DisplayName("Test numEntries getter and setter")
    void testNumEntriesGetterSetter() {
        assertEquals(0, response.getNumEntries());
        response.setNumEntries(10);
        assertEquals(10, response.getNumEntries());
    }

    @Test
    @DisplayName("Test results array management")
    void testResultsArrayManagement() {
        FileEntry[] entries = { mockFileEntry1, mockFileEntry2 };
        response.setResults(entries);

        FileEntry[] retrievedEntries = response.getResults();
        assertSame(entries, retrievedEntries);
        assertEquals(2, retrievedEntries.length);
        assertSame(mockFileEntry1, retrievedEntries[0]);
        assertSame(mockFileEntry2, retrievedEntries[1]);
    }

    @Test
    @DisplayName("Test nextElement method")
    void testNextElement() {
        // First call returns self
        SmbComTransactionResponse result = response.nextElement();
        assertSame(response, result);
    }

    @Test
    @DisplayName("Test hasMoreElements method")
    void testHasMoreElements() {
        // Test initial state
        assertTrue(response.hasMoreElements());

        // Test after setting error code (not status)
        response.setTestErrorCode(1); // Non-zero errorCode indicates error
        assertFalse(response.hasMoreElements());

        // Reset error and test hasMore flag
        response.setTestErrorCode(0);
        response.hasMore = false;
        assertFalse(response.hasMoreElements());
    }

    @Test
    @DisplayName("Test reset functionality")
    void testReset() {
        // Reset should not throw exception
        assertDoesNotThrow(() -> response.reset());
    }

    @Test
    @DisplayName("Test encode operation")
    void testEncode() {
        byte[] buffer = new byte[1024];
        int length = response.encode(buffer, 0);
        assertTrue(length >= 0);
    }

    @Test
    @DisplayName("Test decode operation")
    void testDecode() {
        byte[] buffer = new byte[1024];
        // Fill with basic SMB header structure
        System.arraycopy(new byte[] { (byte) 0xFF, 'S', 'M', 'B' }, 0, buffer, 0, 4);
        buffer[4] = 1; // wordCount
        buffer[7] = 0; // byteCount low
        buffer[8] = 0; // byteCount high

        assertDoesNotThrow(() -> response.decode(buffer, 0));
    }

    @Test
    @DisplayName("Test writeParameterWordsWireFormat")
    void testWriteParameterWordsWireFormat() {
        byte[] dst = new byte[256];
        int result = response.writeParameterWordsWireFormat(dst, 0);
        assertEquals(0, result);
    }

    @Test
    @DisplayName("Test writeDataWireFormat")
    void testWriteDataWireFormat() {
        byte[] dst = new byte[256];
        int result = response.writeDataWireFormat(dst, 0);
        assertEquals(0, result);
    }

    @Test
    @DisplayName("Test readParametersWireFormat")
    void testReadParametersWireFormat() throws SMBProtocolDecodingException {
        byte[] buffer = new byte[256];
        response.setParametersWireFormatReturn(42);
        int result = response.readParametersWireFormat(buffer, 0, buffer.length);
        assertEquals(42, result);
    }

    @Test
    @DisplayName("Test readDataWireFormat")
    void testReadDataWireFormat() throws SMBProtocolDecodingException {
        byte[] buffer = new byte[256];
        response.setDataWireFormatReturn(84);
        int result = response.readDataWireFormat(buffer, 0, buffer.length);
        assertEquals(84, result);
    }

    @Test
    @DisplayName("Test readParametersWireFormat with exception")
    void testReadParametersWireFormatWithException() {
        response.setThrowExceptionOnReadParameters(true);
        byte[] buffer = new byte[256];

        assertThrows(SMBProtocolDecodingException.class, () -> {
            response.readParametersWireFormat(buffer, 0, buffer.length);
        });
    }

    @Test
    @DisplayName("Test readDataWireFormat with exception")
    void testReadDataWireFormatWithException() {
        response.setThrowExceptionOnReadData(true);
        byte[] buffer = new byte[256];

        assertThrows(SMBProtocolDecodingException.class, () -> {
            response.readDataWireFormat(buffer, 0, buffer.length);
        });
    }

    @Test
    @DisplayName("Test toString method")
    void testToString() {
        String result = response.toString();
        assertNotNull(result);
        // The toString method includes various parameter information
        assertTrue(result.contains("totalParameterCount"));
        assertTrue(result.contains("totalDataCount"));
        assertTrue(result.contains("dataCount"));
    }

    @Test
    @DisplayName("Test configuration usage")
    void testConfigurationUsage() {
        // Verify configuration is used - getPid() is called in parent constructor
        verify(mockConfig, atLeastOnce()).getPid();
    }

    @Test
    @DisplayName("Test transaction response with different commands")
    void testTransactionResponseWithDifferentCommands() {
        // Test with TRANSACTION command
        TestSmbComTransactionResponse resp1 =
                new TestSmbComTransactionResponse(mockConfig, SmbComTransaction.SMB_COM_TRANSACTION, (byte) 0x01);
        assertEquals(SmbComTransaction.SMB_COM_TRANSACTION, resp1.getCommand());

        // Test with NT_TRANSACT command
        TestSmbComTransactionResponse resp2 =
                new TestSmbComTransactionResponse(mockConfig, SmbComTransaction.SMB_COM_NT_TRANSACT, (byte) 0x02);
        assertEquals(SmbComTransaction.SMB_COM_NT_TRANSACT, resp2.getCommand());
    }

    @Test
    @DisplayName("Test response state transitions")
    void testResponseStateTransitions() {
        // Test initial state
        assertTrue(response.hasMoreElements());

        // Test state after nextElement call
        response.nextElement();
        // Response behavior may change after nextElement

        // Test state after error (using errorCode, not status)
        response.setTestErrorCode(1);
        assertFalse(response.hasMoreElements());

        // Test state after reset
        response.reset();
        // After reset, hasMore should be true again
        assertTrue(response.hasMoreElements());
    }

    @Test
    @DisplayName("Test data handling with various sizes")
    void testDataHandlingWithVariousSizes() {
        // Test with small data count
        response.setDataCount(10);
        assertEquals(10, response.getDataCount());

        // Test with large data count
        response.setDataCount(65535);
        assertEquals(65535, response.getDataCount());

        // Test with zero data count
        response.setDataCount(0);
        assertEquals(0, response.getDataCount());
    }

    @Test
    @DisplayName("Test entry management")
    void testEntryManagement() {
        // Test with null entries
        response.setResults(null);
        assertNull(response.getResults());

        // Test with empty entries
        FileEntry[] emptyEntries = new FileEntry[0];
        response.setResults(emptyEntries);
        assertSame(emptyEntries, response.getResults());
        assertEquals(0, response.getResults().length);

        // Test with multiple entries
        FileEntry[] entries = { mockFileEntry1, mockFileEntry2 };
        response.setResults(entries);
        assertEquals(2, response.getResults().length);
        response.setNumEntries(2);
        assertEquals(2, response.getNumEntries());
    }
}

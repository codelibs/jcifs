package org.codelibs.jcifs.smb.internal.smb1.trans;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import org.codelibs.jcifs.smb.Configuration;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

/**
 * Test class for SmbComTransaction
 */
class SmbComTransactionTest {

    @Mock
    private Configuration mockConfig;

    private TestSmbComTransaction transaction;

    // Test implementation of abstract SmbComTransaction
    private static class TestSmbComTransaction extends SmbComTransaction {
        private int setupWireFormatReturn = 0;
        private int parametersWireFormatReturn = 0;
        private int dataWireFormatReturn = 0;
        private byte[] setupBuffer;
        private byte[] parametersBuffer;
        private byte[] dataBuffer;

        public TestSmbComTransaction(Configuration config, byte command, byte subCommand) {
            super(config, command, subCommand);
        }

        @Override
        protected int writeSetupWireFormat(byte[] dst, int dstIndex) {
            if (setupBuffer != null && setupBuffer.length > 0) {
                System.arraycopy(setupBuffer, 0, dst, dstIndex, setupBuffer.length);
            }
            return setupWireFormatReturn;
        }

        @Override
        protected int writeParametersWireFormat(byte[] dst, int dstIndex) {
            if (parametersBuffer != null && parametersBuffer.length > 0) {
                System.arraycopy(parametersBuffer, 0, dst, dstIndex, parametersBuffer.length);
            }
            return parametersWireFormatReturn;
        }

        @Override
        protected int writeDataWireFormat(byte[] dst, int dstIndex) {
            if (dataBuffer != null && dataBuffer.length > 0) {
                System.arraycopy(dataBuffer, 0, dst, dstIndex, dataBuffer.length);
            }
            return dataWireFormatReturn;
        }

        @Override
        protected int readSetupWireFormat(byte[] buffer, int bufferIndex, int len) {
            return 0;
        }

        @Override
        protected int readParametersWireFormat(byte[] buffer, int bufferIndex, int len) {
            return 0;
        }

        @Override
        protected int readDataWireFormat(byte[] buffer, int bufferIndex, int len) {
            return 0;
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

        void setSetupBuffer(byte[] buffer) {
            this.setupBuffer = buffer;
        }

        void setParametersBuffer(byte[] buffer) {
            this.parametersBuffer = buffer;
        }

        void setDataBuffer(byte[] buffer) {
            this.dataBuffer = buffer;
        }
    }

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        when(mockConfig.getTransactionBufferSize()).thenReturn(65535);
        when(mockConfig.getOemEncoding()).thenReturn("ASCII");
        transaction = new TestSmbComTransaction(mockConfig, SmbComTransaction.SMB_COM_TRANSACTION, SmbComTransaction.TRANS2_FIND_FIRST2);
    }

    @Test
    @DisplayName("Test constructor initialization")
    void testConstructor() {
        // Verify command and subcommand are set correctly
        assertEquals(SmbComTransaction.SMB_COM_TRANSACTION, transaction.getCommand());
        assertEquals(SmbComTransaction.TRANS2_FIND_FIRST2, transaction.getSubCommand());

        // Verify maxDataCount and maxParameterCount are initialized
        assertTrue(transaction.maxDataCount > 0);
        assertTrue(transaction.maxParameterCount > 0);
    }

    @Test
    @DisplayName("Test setMaxBufferSize")
    void testSetMaxBufferSize() {
        transaction.setMaxBufferSize(8192);
        assertEquals(8192, transaction.maxBufferSize);
    }

    @Test
    @DisplayName("Test setMaxDataCount")
    void testSetMaxDataCount() {
        transaction.setMaxDataCount(4096);
        assertEquals(4096, transaction.maxDataCount);
    }

    @Test
    @DisplayName("Test buffer management")
    void testBufferManagement() {
        byte[] buffer = new byte[1024];
        buffer[0] = 0x42;

        transaction.setBuffer(buffer);

        byte[] released = transaction.releaseBuffer();
        assertSame(buffer, released);
        assertEquals(0x42, released[0]);

        // After release, getting buffer again should return null
        assertNull(transaction.releaseBuffer());
    }

    @Test
    @DisplayName("Test subCommand getter and setter")
    void testSubCommand() {
        assertEquals(SmbComTransaction.TRANS2_FIND_FIRST2, transaction.getSubCommand());

        transaction.setSubCommand(SmbComTransaction.TRANS2_QUERY_FS_INFORMATION);
        assertEquals(SmbComTransaction.TRANS2_QUERY_FS_INFORMATION, transaction.getSubCommand());
    }

    @Test
    @DisplayName("Test reset functionality")
    void testReset() {
        // Reset should not throw exception
        assertDoesNotThrow(() -> transaction.reset());

        // Transaction should be ready for reuse
        assertTrue(transaction.hasMoreElements());
    }

    @Test
    @DisplayName("Test reset with key and lastName")
    void testResetWithKeyAndLastName() {
        // Reset with parameters should not throw exception
        assertDoesNotThrow(() -> transaction.reset(123, "testName"));

        // Transaction should be ready for reuse
        assertTrue(transaction.hasMoreElements());
    }

    @Test
    @DisplayName("Test hasMoreElements")
    void testHasMoreElements() {
        assertTrue(transaction.hasMoreElements());
    }

    @Test
    @DisplayName("Test nextElement method")
    void testNextElement() {
        transaction.setMaxBufferSize(4096);
        transaction.setBuffer(new byte[SmbComTransaction.TRANSACTION_BUF_SIZE]);
        transaction.setParametersWireFormatReturn(100);
        transaction.setDataWireFormatReturn(200);

        SmbComTransaction result = transaction.nextElement();

        assertSame(transaction, result);
    }

    @Test
    @DisplayName("Test pad calculation with various offsets")
    void testPadCalculation() {
        // Test pad calculation with different alignment values
        assertEquals(0, transaction.pad(0)); // Already aligned
        assertEquals(0, transaction.pad(4)); // Already aligned
        assertEquals(0, transaction.pad(8)); // Already aligned
        assertEquals(3, transaction.pad(1)); // Need 3 bytes to align to 4
        assertEquals(2, transaction.pad(2)); // Need 2 bytes to align to 4
        assertEquals(1, transaction.pad(3)); // Need 1 byte to align to 4
    }

    @Test
    @DisplayName("Test getPadding method")
    void testGetPadding() {
        int padding = transaction.getPadding();
        assertTrue(padding >= 0);
    }

    @Test
    @DisplayName("Test write operations")
    void testWriteOperations() {
        byte[] dst = new byte[1024];

        // Initialize transaction buffer to avoid NPE
        transaction.setBuffer(new byte[SmbComTransaction.TRANSACTION_BUF_SIZE]);

        // Test parameter words wire format
        int paramWords = transaction.writeParameterWordsWireFormat(dst, 0);
        assertTrue(paramWords >= 0);

        // Test bytes wire format
        int bytes = transaction.writeBytesWireFormat(dst, 0);
        assertTrue(bytes >= 0);
    }

    @Test
    @DisplayName("Test read operations")
    void testReadOperations() {
        byte[] buffer = new byte[256];

        // Test parameter words read
        int paramResult = transaction.readParameterWordsWireFormat(buffer, 0);
        assertEquals(0, paramResult);

        // Test bytes read
        int bytesResult = transaction.readBytesWireFormat(buffer, 0);
        assertEquals(0, bytesResult);
    }

    @Test
    @DisplayName("Test toString method")
    void testToString() {
        String result = transaction.toString();

        assertNotNull(result);
        // The toString method from parent class returns SMB_COM_TRANSACTION, not SmbComTransaction
        assertTrue(result.contains("SMB_COM_TRANSACTION"));
        // Also verify it contains transaction-specific details
        assertTrue(result.contains("totalParameterCount"));
        assertTrue(result.contains("totalDataCount"));
        assertTrue(result.contains("maxParameterCount"));
        assertTrue(result.contains("maxDataCount"));
    }

    @Test
    @DisplayName("Test transaction command constants")
    void testTransactionCommandConstants() {
        assertEquals((byte) 0x25, SmbComTransaction.SMB_COM_TRANSACTION);
        assertEquals((byte) 0xA0, SmbComTransaction.SMB_COM_NT_TRANSACT);
        assertEquals((byte) 0x26, SmbComTransaction.SMB_COM_TRANSACTION_SECONDARY);
        assertEquals((byte) 0xA1, SmbComTransaction.SMB_COM_NT_TRANSACT_SECONDARY);
    }

    @Test
    @DisplayName("Test sub-command constants")
    void testSubCommandConstants() {
        assertEquals((short) 0x0001, SmbComTransaction.TRANS2_FIND_FIRST2);
        assertEquals((short) 0x0002, SmbComTransaction.TRANS2_FIND_NEXT2);
        assertEquals((short) 0x0003, SmbComTransaction.TRANS2_QUERY_FS_INFORMATION);
        assertEquals((short) 0x0005, SmbComTransaction.TRANS2_QUERY_PATH_INFORMATION);
        assertEquals((short) 0x0007, SmbComTransaction.TRANS2_QUERY_FILE_INFORMATION);
        assertEquals((short) 0x0008, SmbComTransaction.TRANS2_SET_FILE_INFORMATION);
        assertEquals((short) 0x0010, SmbComTransaction.TRANS2_GET_DFS_REFERRAL);
    }

    @Test
    @DisplayName("Test encode and decode operations")
    void testEncodeDecodeOperations() {
        byte[] buffer = new byte[1024];

        // Initialize transaction buffer to avoid NPE
        transaction.setBuffer(new byte[SmbComTransaction.TRANSACTION_BUF_SIZE]);

        // Test encode
        int encodeLength = transaction.encode(buffer, 0);
        assertTrue(encodeLength > 0);

        // Test decode - should not throw exception
        assertDoesNotThrow(() -> {
            transaction.decode(buffer, 0);
        });
    }

    @Test
    @DisplayName("Test configuration usage")
    void testConfigurationUsage() {
        // Verify configuration is used
        verify(mockConfig, atLeastOnce()).getTransactionBufferSize();
    }
}

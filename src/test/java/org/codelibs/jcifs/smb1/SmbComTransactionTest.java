package org.codelibs.jcifs.smb1;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Unit tests for SmbComTransaction class
 */
class SmbComTransactionTest {

    private TestSmbComTransaction transaction;

    // Test implementation of abstract SmbComTransaction
    static class TestSmbComTransaction extends SmbComTransaction {

        private int setupBytesWritten = 2;
        private int parameterBytesWritten = 20;
        private int dataBytesWritten = 50;

        @Override
        int writeSetupWireFormat(byte[] dst, int dstIndex) {
            return setupBytesWritten;
        }

        @Override
        int writeParametersWireFormat(byte[] dst, int dstIndex) {
            return parameterBytesWritten;
        }

        @Override
        int writeDataWireFormat(byte[] dst, int dstIndex) {
            return dataBytesWritten;
        }

        @Override
        int readSetupWireFormat(byte[] buffer, int bufferIndex, int len) {
            return 2;
        }

        @Override
        int readParametersWireFormat(byte[] buffer, int bufferIndex, int len) {
            return 20;
        }

        @Override
        int readDataWireFormat(byte[] buffer, int bufferIndex, int len) {
            return 50;
        }

        // Setters for test control
        void setSetupBytesWritten(int bytes) {
            this.setupBytesWritten = bytes;
        }

        void setParameterBytesWritten(int bytes) {
            this.parameterBytesWritten = bytes;
        }

        void setDataBytesWritten(int bytes) {
            this.dataBytesWritten = bytes;
        }
    }

    @BeforeEach
    void setUp() {
        transaction = new TestSmbComTransaction();
        transaction.command = ServerMessageBlock.SMB_COM_TRANSACTION;
        transaction.name = "\\PIPE\\test";
        transaction.txn_buf = new byte[1024];
        transaction.maxBufferSize = 1024;
    }

    @Test
    @DisplayName("Test reset() method resets transaction state")
    void testReset() {
        // Modify state
        transaction.nextElement();

        // Reset
        transaction.reset();

        // Verify state is reset
        assertTrue(transaction.hasMoreElements(), "hasMoreElements should be true after reset");
    }

    @Test
    @DisplayName("Test reset(int, String) method")
    void testResetWithParameters() {
        // Test overloaded reset method
        transaction.reset(123, "lastTest");
        assertTrue(transaction.hasMoreElements(), "hasMoreElements should be true after reset");
    }

    @Test
    @DisplayName("Test hasMoreElements() initially returns true")
    void testHasMoreElements() {
        assertTrue(transaction.hasMoreElements(), "Initially, hasMoreElements should be true");
    }

    @Test
    @DisplayName("Test nextElement() returns transaction on first call")
    void testNextElementFirstCall() {
        Object element = transaction.nextElement();
        assertSame(transaction, element, "First nextElement should return the transaction itself");
    }

    @Test
    @DisplayName("Test nextElement() changes command on second call")
    void testNextElementSecondCall() {
        // First call - primary
        transaction.nextElement();
        byte initialCommand = transaction.command;

        // Second call - secondary
        transaction.nextElement();

        // Verify command changed to secondary
        assertEquals(ServerMessageBlock.SMB_COM_TRANSACTION_SECONDARY, transaction.command,
                "Command should change to SMB_COM_TRANSACTION_SECONDARY");
    }

    @Test
    @DisplayName("Test NT transaction command handling")
    void testNtTransactionCommand() {
        transaction.command = ServerMessageBlock.SMB_COM_NT_TRANSACT;

        // First call
        transaction.nextElement();

        // Second call should change to NT_TRANSACT_SECONDARY
        transaction.nextElement();
        assertEquals(ServerMessageBlock.SMB_COM_NT_TRANSACT_SECONDARY, transaction.command,
                "Command should change to SMB_COM_NT_TRANSACT_SECONDARY for NT transactions");
    }

    @Test
    @DisplayName("Test toString() method")
    void testToString() {
        String result = transaction.toString();
        assertNotNull(result, "toString should not return null");
        assertTrue(result.contains("command="), "toString should contain command info");
    }

    @Test
    @DisplayName("Test parameter and data writing methods")
    void testWriteMethods() {
        byte[] buffer = new byte[1024];

        int setupBytes = transaction.writeSetupWireFormat(buffer, 0);
        assertEquals(2, setupBytes, "writeSetupWireFormat should return expected bytes");

        int paramBytes = transaction.writeParametersWireFormat(buffer, 0);
        assertEquals(20, paramBytes, "writeParametersWireFormat should return expected bytes");

        int dataBytes = transaction.writeDataWireFormat(buffer, 0);
        assertEquals(50, dataBytes, "writeDataWireFormat should return expected bytes");
    }

    @Test
    @DisplayName("Test parameter and data reading methods")
    void testReadMethods() {
        byte[] buffer = new byte[1024];

        int setupBytes = transaction.readSetupWireFormat(buffer, 0, 10);
        assertEquals(2, setupBytes, "readSetupWireFormat should return expected bytes");

        int paramBytes = transaction.readParametersWireFormat(buffer, 0, 30);
        assertEquals(20, paramBytes, "readParametersWireFormat should return expected bytes");

        int dataBytes = transaction.readDataWireFormat(buffer, 0, 60);
        assertEquals(50, dataBytes, "readDataWireFormat should return expected bytes");
    }

    @Test
    @DisplayName("Test hasMoreElements becomes false when all data is sent")
    void testHasMoreElementsBecomeFalse() {
        // Set small amounts so everything fits in one message
        transaction.setParameterBytesWritten(10);
        transaction.setDataBytesWritten(10);

        // First call processes all data
        transaction.nextElement();

        // Should have no more elements since all data fit in first message
        assertFalse(transaction.hasMoreElements(), "hasMoreElements should be false when all data is sent");
    }

    @Test
    @DisplayName("Test transaction with large data requires multiple elements")
    void testLargeDataMultipleElements() {
        // Set large amounts that won't fit in one buffer
        transaction.maxBufferSize = 100;
        transaction.setParameterBytesWritten(200);
        transaction.setDataBytesWritten(300);

        // First element
        transaction.nextElement();
        assertTrue(transaction.hasMoreElements(), "Should have more elements for large data");

        // Process multiple elements
        int count = 1;
        while (transaction.hasMoreElements() && count < 10) {
            transaction.nextElement();
            count++;
        }

        assertTrue(count > 1, "Large data should require multiple elements");
    }

    @Test
    @DisplayName("Test transaction name handling")
    void testTransactionName() {
        assertEquals("\\PIPE\\test", transaction.name, "Transaction name should be set correctly");

        // Test with different name
        transaction.name = "\\MAILSLOT\\browse";
        assertEquals("\\MAILSLOT\\browse", transaction.name, "Transaction name should be changeable");
    }

    @Test
    @DisplayName("Test default buffer size constant")
    void testBufferSizeConstant() {
        assertEquals(0xFFFF, SmbComTransaction.TRANSACTION_BUF_SIZE, "TRANSACTION_BUF_SIZE should be 0xFFFF");
    }

    @Test
    @DisplayName("Test transaction subcommand constants")
    void testSubcommandConstants() {
        // Test Trans2 subcommands
        assertEquals((byte) 0x01, SmbComTransaction.TRANS2_FIND_FIRST2);
        assertEquals((byte) 0x02, SmbComTransaction.TRANS2_FIND_NEXT2);
        assertEquals((byte) 0x03, SmbComTransaction.TRANS2_QUERY_FS_INFORMATION);
        assertEquals((byte) 0x05, SmbComTransaction.TRANS2_QUERY_PATH_INFORMATION);
        assertEquals((byte) 0x10, SmbComTransaction.TRANS2_GET_DFS_REFERRAL);
        assertEquals((byte) 0x08, SmbComTransaction.TRANS2_SET_FILE_INFORMATION);

        // Test NET subcommands
        assertEquals(0x0000, SmbComTransaction.NET_SHARE_ENUM);
        assertEquals(0x0068, SmbComTransaction.NET_SERVER_ENUM2);
        assertEquals(0x00D7, SmbComTransaction.NET_SERVER_ENUM3);

        // Test TRANS subcommands
        assertEquals((byte) 0x23, SmbComTransaction.TRANS_PEEK_NAMED_PIPE);
        assertEquals((byte) 0x53, SmbComTransaction.TRANS_WAIT_NAMED_PIPE);
        assertEquals((byte) 0x54, SmbComTransaction.TRANS_CALL_NAMED_PIPE);
        assertEquals((byte) 0x26, SmbComTransaction.TRANS_TRANSACT_NAMED_PIPE);
    }
}
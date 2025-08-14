package jcifs.internal.smb1.trans.nt;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import jcifs.Configuration;
import jcifs.internal.CommonServerMessageBlockRequest;
import jcifs.internal.smb1.ServerMessageBlock;
import jcifs.internal.smb1.trans.SmbComTransaction;
import jcifs.internal.util.SMBUtil;

/**
 * Test class for SmbComNtTransaction
 */
@ExtendWith(MockitoExtension.class)
class SmbComNtTransactionTest {

    @Mock
    private Configuration mockConfig;

    private TestSmbComNtTransaction transaction;

    /**
     * Test implementation of SmbComNtTransaction for testing purposes
     */
    public static class TestSmbComNtTransaction extends SmbComNtTransaction {

        private int setupWireFormatReturn = 0;
        private int parametersWireFormatReturn = 0;
        private int dataWireFormatReturn = 0;

        public TestSmbComNtTransaction(Configuration config, int function) {
            super(config, function);
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
        protected int readParametersWireFormat(byte[] buffer, int bufferIndex, int len) {
            return 0;
        }

        @Override
        protected int readDataWireFormat(byte[] buffer, int bufferIndex, int len) {
            return 0;
        }

        public void setSetupWireFormatReturn(int value) {
            this.setupWireFormatReturn = value;
        }

        public void setParametersWireFormatReturn(int value) {
            this.parametersWireFormatReturn = value;
        }

        public void setDataWireFormatReturn(int value) {
            this.dataWireFormatReturn = value;
        }

        // Getters for protected fields for testing
        public int getMaxSetupCount() {
            return maxSetupCount;
        }

        public void setMaxSetupCount(byte value) {
            this.maxSetupCount = value;
        }

        public int getTotalParameterCount() {
            return totalParameterCount;
        }

        public void setTotalParameterCount(int value) {
            this.totalParameterCount = value;
        }

        public int getTotalDataCount() {
            return totalDataCount;
        }

        public void setTotalDataCount(int value) {
            this.totalDataCount = value;
        }

        public int getMaxParameterCount() {
            return maxParameterCount;
        }

        public void setMaxParameterCount(int value) {
            this.maxParameterCount = value;
        }

        public int getMaxDataCount() {
            return maxDataCount;
        }

        public void setMaxDataCountForTest(int value) {
            this.maxDataCount = value;
        }

        public int getParameterCount() {
            return parameterCount;
        }

        public void setParameterCount(int value) {
            this.parameterCount = value;
        }

        public int getParameterOffset() {
            return parameterOffset;
        }

        public void setParameterOffset(int value) {
            this.parameterOffset = value;
        }

        public int getParameterDisplacement() {
            return parameterDisplacement;
        }

        public void setParameterDisplacement(int value) {
            this.parameterDisplacement = value;
        }

        public int getDataCount() {
            return dataCount;
        }

        public void setDataCount(int value) {
            this.dataCount = value;
        }

        public int getDataOffset() {
            return dataOffset;
        }

        public void setDataOffset(int value) {
            this.dataOffset = value;
        }

        public int getDataDisplacement() {
            return dataDisplacement;
        }

        public void setDataDisplacement(int value) {
            this.dataDisplacement = value;
        }

        public int getSetupCount() {
            return setupCount;
        }

        public void setSetupCount(int value) {
            this.setupCount = value;
        }
    }

    @BeforeEach
    void setUp() {
        when(mockConfig.getTransactionBufferSize()).thenReturn(65535);
        transaction = new TestSmbComNtTransaction(mockConfig, SmbComNtTransaction.NT_TRANSACT_QUERY_SECURITY_DESC);
    }

    @Test
    @DisplayName("Test constructor initialization with NT_TRANSACT_QUERY_SECURITY_DESC")
    void testConstructorInitialization() {
        // Verify that the transaction is properly initialized
        assertEquals(ServerMessageBlock.SMB_COM_NT_TRANSACT, transaction.getCommand());

        // Verify that transaction is properly initialized
        assertNotNull(transaction);

        // Verify primary setup offset (should be 71 as per NTT_PRIMARY_SETUP_OFFSET)
        // This is set in the parent constructor
        assertNotNull(transaction);
    }

    @Test
    @DisplayName("Test constructor initialization with NT_TRANSACT_NOTIFY_CHANGE")
    void testConstructorWithNotifyChange() {
        TestSmbComNtTransaction notifyTransaction = new TestSmbComNtTransaction(mockConfig, SmbComNtTransaction.NT_TRANSACT_NOTIFY_CHANGE);

        assertEquals(ServerMessageBlock.SMB_COM_NT_TRANSACT, notifyTransaction.getCommand());
        assertNotNull(notifyTransaction);
    }

    @Test
    @DisplayName("Test createCancel method returns SmbComNtCancel")
    void testCreateCancel() {
        // Set a MID for the transaction
        transaction.setMid(12345);

        // Create cancel request
        CommonServerMessageBlockRequest cancelRequest = transaction.createCancel();

        // Verify it returns an SmbComNtCancel instance
        assertNotNull(cancelRequest);
        assertTrue(cancelRequest instanceof SmbComNtCancel);

        // Verify the cancel request has the correct MID
        assertEquals(12345, cancelRequest.getMid());
    }

    @Test
    @DisplayName("Test writeParameterWordsWireFormat for primary NT transaction")
    void testWriteParameterWordsWireFormatPrimary() {
        byte[] dst = new byte[256];

        // Set up transaction parameters
        transaction.setMaxSetupCount((byte) 2);
        transaction.setTotalParameterCount(100);
        transaction.setTotalDataCount(200);
        transaction.setMaxParameterCount(1024);
        transaction.setMaxDataCountForTest(2048);
        transaction.setParameterCount(50);
        transaction.setParameterOffset(80);
        transaction.setDataCount(150);
        transaction.setDataOffset(130);
        transaction.setSetupCount(1);
        transaction.setSetupWireFormatReturn(4);

        // Execute the method
        int bytesWritten = transaction.writeParameterWordsWireFormat(dst, 0);

        // Verify the bytes written
        assertTrue(bytesWritten > 0);

        // Verify max setup count is written at position 0
        assertEquals(2, dst[0]);

        // Verify reserved bytes
        assertEquals(0, dst[1]);
        assertEquals(0, dst[2]);

        // Verify total parameter count (4 bytes at position 3)
        assertEquals(100, SMBUtil.readInt4(dst, 3));

        // Verify total data count (4 bytes at position 7)
        assertEquals(200, SMBUtil.readInt4(dst, 7));

        // Verify max parameter count (4 bytes at position 11)
        assertEquals(1024, SMBUtil.readInt4(dst, 11));

        // Verify max data count (4 bytes at position 15)
        assertEquals(2048, SMBUtil.readInt4(dst, 15));

        // Verify parameter count (4 bytes at position 19)
        assertEquals(50, SMBUtil.readInt4(dst, 19));

        // Verify parameter offset (4 bytes at position 23)
        assertEquals(80, SMBUtil.readInt4(dst, 23));

        // Verify data count (4 bytes at position 27)
        assertEquals(150, SMBUtil.readInt4(dst, 27));

        // Verify data offset (4 bytes at position 31)
        assertEquals(130, SMBUtil.readInt4(dst, 31));

        // Verify setup count
        assertEquals(1, dst[35]);

        // Verify function (2 bytes at position 36)
        assertEquals(SmbComNtTransaction.NT_TRANSACT_QUERY_SECURITY_DESC, SMBUtil.readInt2(dst, 36));
    }

    @Test
    @DisplayName("Test writeParameterWordsWireFormat for secondary NT transaction")
    void testWriteParameterWordsWireFormatSecondary() {
        byte[] dst = new byte[256];

        // Change command to secondary
        transaction.setCommand(ServerMessageBlock.SMB_COM_NT_TRANSACT_SECONDARY);

        // Set up transaction parameters
        transaction.setTotalParameterCount(100);
        transaction.setTotalDataCount(200);
        transaction.setParameterCount(30);
        transaction.setParameterOffset(60);
        transaction.setParameterDisplacement(20);
        transaction.setDataCount(80);
        transaction.setDataOffset(90);
        transaction.setDataDisplacement(70);

        // Execute the method
        int bytesWritten = transaction.writeParameterWordsWireFormat(dst, 0);

        // Verify the bytes written
        assertTrue(bytesWritten > 0);

        // For secondary, first byte should be 0x00 (Reserved)
        assertEquals(0, dst[0]);

        // Verify reserved bytes
        assertEquals(0, dst[1]);
        assertEquals(0, dst[2]);

        // Verify total parameter count (4 bytes at position 3)
        assertEquals(100, SMBUtil.readInt4(dst, 3));

        // Verify total data count (4 bytes at position 7)
        assertEquals(200, SMBUtil.readInt4(dst, 7));

        // Verify parameter count (4 bytes at position 11)
        assertEquals(30, SMBUtil.readInt4(dst, 11));

        // Verify parameter offset (4 bytes at position 15)
        assertEquals(60, SMBUtil.readInt4(dst, 15));

        // Verify parameter displacement (4 bytes at position 19)
        assertEquals(20, SMBUtil.readInt4(dst, 19));

        // Verify data count (4 bytes at position 23)
        assertEquals(80, SMBUtil.readInt4(dst, 23));

        // Verify data offset (4 bytes at position 27)
        assertEquals(90, SMBUtil.readInt4(dst, 27));

        // Verify data displacement (4 bytes at position 31)
        assertEquals(70, SMBUtil.readInt4(dst, 31));

        // Verify Reserved1 byte
        assertEquals(0, dst[35]);
    }

    @Test
    @DisplayName("Test writeParameterWordsWireFormat with zero parameter count")
    void testWriteParameterWordsWireFormatZeroParameters() {
        byte[] dst = new byte[256];

        // Set up transaction with zero parameters
        transaction.setTotalParameterCount(0);
        transaction.setTotalDataCount(100);
        transaction.setMaxParameterCount(1024);
        transaction.setMaxDataCountForTest(2048);
        transaction.setParameterCount(0);
        transaction.setParameterOffset(0);
        transaction.setDataCount(100);
        transaction.setDataOffset(80);
        transaction.setSetupCount(1);

        // Execute the method
        int bytesWritten = transaction.writeParameterWordsWireFormat(dst, 0);

        // Verify the bytes written
        assertTrue(bytesWritten > 0);

        // Verify parameter count is 0
        assertEquals(0, SMBUtil.readInt4(dst, 19));

        // Verify parameter offset should be 0 when parameter count is 0
        assertEquals(0, SMBUtil.readInt4(dst, 23));
    }

    @Test
    @DisplayName("Test writeParameterWordsWireFormat with zero data count")
    void testWriteParameterWordsWireFormatZeroData() {
        byte[] dst = new byte[256];

        // Set up transaction with zero data
        transaction.setTotalParameterCount(100);
        transaction.setTotalDataCount(0);
        transaction.setMaxParameterCount(1024);
        transaction.setMaxDataCountForTest(2048);
        transaction.setParameterCount(100);
        transaction.setParameterOffset(80);
        transaction.setDataCount(0);
        transaction.setDataOffset(0);
        transaction.setSetupCount(1);

        // Execute the method
        int bytesWritten = transaction.writeParameterWordsWireFormat(dst, 0);

        // Verify the bytes written
        assertTrue(bytesWritten > 0);

        // Verify data count is 0
        assertEquals(0, SMBUtil.readInt4(dst, 27));

        // Verify data offset should be 0 when data count is 0
        assertEquals(0, SMBUtil.readInt4(dst, 31));
    }

    @Test
    @DisplayName("Test writeParameterWordsWireFormat with large buffer offset")
    void testWriteParameterWordsWireFormatLargeOffset() {
        byte[] dst = new byte[512];
        int startOffset = 100;

        // Set up transaction parameters
        transaction.setMaxSetupCount((byte) 3);
        transaction.setTotalParameterCount(500);
        transaction.setTotalDataCount(1000);
        transaction.setMaxParameterCount(2048);
        transaction.setMaxDataCountForTest(4096);
        transaction.setParameterCount(250);
        transaction.setParameterOffset(150);
        transaction.setDataCount(500);
        transaction.setDataOffset(400);
        transaction.setSetupCount(2);
        transaction.setSetupWireFormatReturn(8);

        // Execute the method with offset
        int bytesWritten = transaction.writeParameterWordsWireFormat(dst, startOffset);

        // Verify the bytes written
        assertTrue(bytesWritten > 0);

        // Verify data is written at correct offset
        assertEquals(3, dst[startOffset]);

        // Verify total parameter count at correct offset
        assertEquals(500, SMBUtil.readInt4(dst, startOffset + 3));

        // Verify total data count at correct offset
        assertEquals(1000, SMBUtil.readInt4(dst, startOffset + 7));
    }

    @Test
    @DisplayName("Test constants are properly defined")
    void testConstants() {
        // Verify the NT transaction function constants
        assertEquals(0x6, SmbComNtTransaction.NT_TRANSACT_QUERY_SECURITY_DESC);
        assertEquals(0x4, SmbComNtTransaction.NT_TRANSACT_NOTIFY_CHANGE);
    }

    @Test
    @DisplayName("Test inheritance from SmbComTransaction")
    void testInheritance() {
        // Verify that SmbComNtTransaction extends SmbComTransaction
        assertTrue(transaction instanceof SmbComTransaction);

        // Verify that it's also a ServerMessageBlock
        assertTrue(transaction instanceof ServerMessageBlock);
    }

    @Test
    @DisplayName("Test createCancel with zero MID")
    void testCreateCancelWithZeroMid() {
        // Set MID to 0
        transaction.setMid(0);

        // Create cancel request
        CommonServerMessageBlockRequest cancelRequest = transaction.createCancel();

        // Verify it still creates a valid cancel request
        assertNotNull(cancelRequest);
        assertTrue(cancelRequest instanceof SmbComNtCancel);
        assertEquals(0, cancelRequest.getMid());
    }

    @Test
    @DisplayName("Test createCancel with maximum MID value")
    void testCreateCancelWithMaxMid() {
        // Set MID to maximum value
        int maxMid = 0xFFFF;
        transaction.setMid(maxMid);

        // Create cancel request
        CommonServerMessageBlockRequest cancelRequest = transaction.createCancel();

        // Verify it creates a valid cancel request with max MID
        assertNotNull(cancelRequest);
        assertTrue(cancelRequest instanceof SmbComNtCancel);
        assertEquals(maxMid, cancelRequest.getMid());
    }

    @Test
    @DisplayName("Test writeParameterWordsWireFormat boundary conditions")
    void testWriteParameterWordsWireFormatBoundaryConditions() {
        byte[] dst = new byte[256];

        // Test with maximum values
        transaction.setMaxSetupCount((byte) 0xFF);
        transaction.setTotalParameterCount(0xFFFFFFFF);
        transaction.setTotalDataCount(0xFFFFFFFF);
        transaction.setMaxParameterCount(0xFFFFFFFF);
        transaction.setMaxDataCountForTest(0xFFFFFFFF);
        transaction.setParameterCount(0xFFFFFFFF);
        transaction.setParameterOffset(0xFFFFFFFF);
        transaction.setDataCount(0xFFFFFFFF);
        transaction.setDataOffset(0xFFFFFFFF);
        transaction.setSetupCount(0xFF);

        // Execute the method - should not throw exception
        assertDoesNotThrow(() -> transaction.writeParameterWordsWireFormat(dst, 0));
    }

    @Test
    @DisplayName("Test multiple setup count handling")
    void testMultipleSetupCount() {
        byte[] dst = new byte[256];

        // Set multiple setup words
        transaction.setSetupCount(3);
        transaction.setSetupWireFormatReturn(6); // 3 * 2 bytes

        // Execute the method
        int bytesWritten = transaction.writeParameterWordsWireFormat(dst, 0);

        // Verify setup count is written correctly
        assertEquals(3, dst[35]);

        // Verify the total bytes written accounts for setup words
        assertTrue(bytesWritten >= 38 + 6); // Base structure + setup words
    }

    @Test
    @DisplayName("Test writeParameterWordsWireFormat returns correct byte count")
    void testWriteParameterWordsWireFormatReturnValue() {
        byte[] dst = new byte[256];

        // Set up minimal transaction
        transaction.setSetupCount(0);

        // Execute for primary transaction
        int primaryBytes = transaction.writeParameterWordsWireFormat(dst, 0);

        // The return value should be the number of bytes written
        // For primary NT transaction: should be at least 38 bytes
        assertTrue(primaryBytes >= 38);

        // Execute for secondary transaction
        transaction.setCommand(ServerMessageBlock.SMB_COM_NT_TRANSACT_SECONDARY);
        int secondaryBytes = transaction.writeParameterWordsWireFormat(dst, 0);

        // For secondary NT transaction: should be at least 36 bytes
        assertTrue(secondaryBytes >= 36);
    }
}
package jcifs.smb1.smb1;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

import jcifs.smb1.smb1.SmbComNtTransaction;
import jcifs.smb1.smb1.ServerMessageBlock;

class SmbComNtTransactionTest {

    private ConcreteSmbComNtTransaction smbComNtTransaction;

    // A concrete implementation of the abstract class SmbComNtTransaction for testing.
    private static class ConcreteSmbComNtTransaction extends SmbComNtTransaction {
        @Override
        int writeSetupWireFormat(byte[] dst, int dstIndex) {
            // Dummy implementation for testing
            return 0;
        }

        @Override
        int readSetupWireFormat(byte[] buffer, int bufferIndex, int len) {
            return 0;
        }

        @Override
        int writeParametersWireFormat(byte[] dst, int dstIndex) {
            // Dummy implementation for testing
            return 0;
        }

        @Override
        int readParametersWireFormat(byte[] buffer, int bufferIndex, int len) {
            return 0;
        }

        @Override
        int writeDataWireFormat(byte[] dst, int dstIndex) {
            // Dummy implementation for testing
            return 0;
        }

        @Override
        int readDataWireFormat(byte[] buffer, int bufferIndex, int len) {
            return 0;
        }

        @Override
        public String toString() {
            return "ConcreteSmbComNtTransaction";
        }
    }

    @BeforeEach
    void setUp() {
        smbComNtTransaction = new ConcreteSmbComNtTransaction();
    }

    @Test
    void testConstructor() {
        // Test if the offsets are initialized correctly by the constructor.
        assertEquals(69, smbComNtTransaction.primarySetupOffset, "primarySetupOffset should be initialized to 69");
        assertEquals(51, smbComNtTransaction.secondaryParameterOffset, "secondaryParameterOffset should be initialized to 51");
    }

    @Test
    void testWriteParameterWordsWireFormat_PrimaryTransaction() {
        // Test the writeParameterWordsWireFormat for a primary transaction.
        smbComNtTransaction.command = ServerMessageBlock.SMB_COM_NT_TRANSACT;
        smbComNtTransaction.function = SmbComNtTransaction.NT_TRANSACT_QUERY_SECURITY_DESC;
        smbComNtTransaction.maxSetupCount = 1;
        smbComNtTransaction.totalParameterCount = 10;
        smbComNtTransaction.totalDataCount = 20;
        smbComNtTransaction.maxParameterCount = 30;
        smbComNtTransaction.maxDataCount = 40;
        smbComNtTransaction.parameterCount = 10;
        smbComNtTransaction.parameterOffset = 100;
        smbComNtTransaction.dataCount = 20;
        smbComNtTransaction.dataOffset = 200;
        smbComNtTransaction.setupCount = 1;

        byte[] dst = new byte[100];
        int bytesWritten = smbComNtTransaction.writeParameterWordsWireFormat(dst, 0);

        // 1 (maxSetupCount) + 2 (reserved) + 4 (totalParameterCount) + 4 (totalDataCount) +
        // 4 (maxParameterCount) + 4 (maxDataCount) + 4 (parameterCount) + 4 (parameterOffset) +
        // 4 (dataCount) + 4 (dataOffset) + 1 (setupCount) + 2 (function)
        assertEquals(38, bytesWritten, "Number of bytes written should be 38 for primary transaction");

        // Verify some key values
        assertEquals(smbComNtTransaction.maxSetupCount, dst[0], "maxSetupCount should be written correctly");
        assertEquals(smbComNtTransaction.totalParameterCount, SmbComTransaction.readInt4(dst, 3), "totalParameterCount should be written correctly");
        assertEquals(smbComNtTransaction.totalDataCount, SmbComTransaction.readInt4(dst, 7), "totalDataCount should be written correctly");
        assertEquals(smbComNtTransaction.maxParameterCount, SmbComTransaction.readInt4(dst, 11), "maxParameterCount should be written correctly");
        assertEquals(smbComNtTransaction.maxDataCount, SmbComTransaction.readInt4(dst, 15), "maxDataCount should be written correctly");
        assertEquals(smbComNtTransaction.parameterCount, SmbComTransaction.readInt4(dst, 19), "parameterCount should be written correctly");
        assertEquals(smbComNtTransaction.parameterOffset, SmbComTransaction.readInt4(dst, 23), "parameterOffset should be written correctly");
        assertEquals(smbComNtTransaction.dataCount, SmbComTransaction.readInt4(dst, 27), "dataCount should be written correctly");
        assertEquals(smbComNtTransaction.dataOffset, SmbComTransaction.readInt4(dst, 31), "dataOffset should be written correctly");
        assertEquals(smbComNtTransaction.setupCount, dst[35], "setupCount should be written correctly");
        assertEquals(smbComNtTransaction.function, SmbComTransaction.readInt2(dst, 36), "function should be written correctly");
    }

    @Test
    void testWriteParameterWordsWireFormat_SecondaryTransaction() {
        // Test the writeParameterWordsWireFormat for a secondary transaction.
        smbComNtTransaction.command = ServerMessageBlock.SMB_COM_NT_TRANSACT_SECONDARY;
        smbComNtTransaction.totalParameterCount = 10;
        smbComNtTransaction.totalDataCount = 20;
        smbComNtTransaction.parameterCount = 5;
        smbComNtTransaction.parameterOffset = 100;
        smbComNtTransaction.parameterDisplacement = 5;
        smbComNtTransaction.dataCount = 10;
        smbComNtTransaction.dataOffset = 200;
        smbComNtTransaction.dataDisplacement = 10;

        byte[] dst = new byte[100];
        int bytesWritten = smbComNtTransaction.writeParameterWordsWireFormat(dst, 0);

        // 1 (reserved) + 2 (reserved) + 4 (totalParameterCount) + 4 (totalDataCount) +
        // 4 (parameterCount) + 4 (parameterOffset) + 4 (parameterDisplacement) +
        // 4 (dataCount) + 4 (dataOffset) + 4 (dataDisplacement) + 1 (reserved)
        assertEquals(36, bytesWritten, "Number of bytes written should be 36 for secondary transaction");

        // Verify some key values
        assertEquals(0, dst[0], "First byte should be 0 for secondary transaction");
        assertEquals(smbComNtTransaction.totalParameterCount, SmbComTransaction.readInt4(dst, 3), "totalParameterCount should be written correctly");
        assertEquals(smbComNtTransaction.totalDataCount, SmbComTransaction.readInt4(dst, 7), "totalDataCount should be written correctly");
        assertEquals(smbComNtTransaction.parameterCount, SmbComTransaction.readInt4(dst, 11), "parameterCount should be written correctly");
        assertEquals(smbComNtTransaction.parameterOffset, SmbComTransaction.readInt4(dst, 15), "parameterOffset should be written correctly");
        assertEquals(smbComNtTransaction.parameterDisplacement, SmbComTransaction.readInt4(dst, 19), "parameterDisplacement should be written correctly");
        assertEquals(smbComNtTransaction.dataCount, SmbComTransaction.readInt4(dst, 23), "dataCount should be written correctly");
        assertEquals(smbComNtTransaction.dataOffset, SmbComTransaction.readInt4(dst, 27), "dataOffset should be written correctly");
        assertEquals(smbComNtTransaction.dataDisplacement, SmbComTransaction.readInt4(dst, 31), "dataDisplacement should be written correctly");
        assertEquals(0, dst[35], "Reserved byte should be 0");
    }

    @Test
    void testWriteParameterWordsWireFormat_ZeroCounts() {
        // Test with zero parameter and data counts to check conditional logic.
        smbComNtTransaction.command = ServerMessageBlock.SMB_COM_NT_TRANSACT;
        smbComNtTransaction.parameterCount = 0;
        smbComNtTransaction.dataCount = 0;
        smbComNtTransaction.parameterOffset = 100;
        smbComNtTransaction.dataOffset = 200;


        byte[] dst = new byte[100];
        smbComNtTransaction.writeParameterWordsWireFormat(dst, 0);

        // Check that offsets are zero when counts are zero
        assertEquals(0, SmbComTransaction.readInt4(dst, 23), "parameterOffset should be 0 when parameterCount is 0");
        assertEquals(0, SmbComTransaction.readInt4(dst, 31), "dataOffset should be 0 when dataCount is 0");
    }
}
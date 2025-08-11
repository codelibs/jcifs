package jcifs.smb1.smb1;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for {@link SmbComTransactionResponse}.
 *
 * <p>The class is abstract, so a concrete stub implementation is
 * provided purely to expose protected state and to satisfy the abstract
 * method contract.  The tests focus on public API behaviour and the
 * parsing logic in {@code readParameterWordsWireFormat} and
 * {@code readBytesWireFormat}.
 */
public class SmbComTransactionResponseTest {
    /** A minimal concrete subclass for testing */
    private static class DummyResponse extends SmbComTransactionResponse {
        DummyResponse() {
            super();
        }

        // Stub implementations of the abstract methods
        @Override
        int writeSetupWireFormat(byte[] dst, int dstIndex) {
            return 0;
        }

        @Override
        int writeParametersWireFormat(byte[] dst, int dstIndex) {
            return 0;
        }

        @Override
        int writeDataWireFormat(byte[] dst, int dstIndex) {
            return 0;
        }

        @Override
        int readSetupWireFormat(byte[] buffer, int bufferIndex, int len) {
            return 0;
        }

        @Override
        int readParametersWireFormat(byte[] buffer, int bufferIndex, int len) {
            return 0;
        }

        @Override
        int readDataWireFormat(byte[] buffer, int bufferIndex, int len) {
            return 0;
        }

        // Helper methods to expose protected fields for assertions
        protected void setTxnBuf(byte[] buf) {
            this.tnx_buf = buf;
        }

        protected void setBufParameterStart(int val) {
            this.bufParameterStart = val;
        }

        protected void setBufDataStart(int val) {
            this.bufDataStart = val;
        }

        protected void setHeaderStart(int val) {
            this.headerStart = val;
        }

        protected void setErrorCode(int val) {
            this.errorCode = val;
        }

        protected void setHasMore(boolean val) {
            this.hasMore = val;
        }

        protected void setIsPrimary(boolean val) {
            this.isPrimary = val;
        }

        protected void setParametersDone(boolean val) {
            this.parametersDone = val;
        }

        protected void setDataDone(boolean val) {
            this.dataDone = val;
        }

        // Accessors for protected state
        int getTotalParameterCount() {
            return totalParameterCount;
        }

        int getTotalDataCount() {
            return totalDataCount;
        }

        int getParameterCount() {
            return parameterCount;
        }

        int getDataCount() {
            return dataCount;
        }

        int getSetupCount() {
            return setupCount;
        }

        boolean isParametersDone() {
            return parametersDone;
        }

        boolean isDataDone() {
            return dataDone;
        }

        boolean isHasMore() {
            return hasMore;
        }
    }

    @Test
    public void hasMoreElements_initially_returnsTrue() {
        DummyResponse d = new DummyResponse();
        assertTrue(d.hasMoreElements(), "With default values hasMoreElements should be true");
    }

    @Test
    public void hasMoreElements_errorCodeNonZero_returnsFalse() {
        DummyResponse d = new DummyResponse();
        d.setErrorCode(123); // non‑zero error
        assertFalse(d.hasMoreElements(), "errorCode non‑zero overrides hasMore flag");
    }

    @Test
    public void nextElement_firstCall_flipsIsPrimary() {
        DummyResponse d = new DummyResponse();
        // Initially isPrimary is true (inherited constructor)
        SmbComTransactionResponse r1 = d.nextElement();
        assertSame(d, r1, "nextElement should return the same instance");
        // After first call isPrimary should be false and hasMore becomes false
        assertFalse(d.isPrimary, "isPrimary should be cleared after first call");
        // Second call keeps the same state
        SmbComTransactionResponse r2 = d.nextElement();
        assertSame(d, r2, "Subsequent calls still return same instance");
        assertFalse(d.isPrimary, "isPrimary remains false after subsequent call");
    }

    @Test
    public void toString_doesNotThrow() {
        DummyResponse d = new DummyResponse();
        String s = d.toString();
        assertNotNull(s, "toString should not return null");
        assertTrue(s.contains("totalParameterCount="), "string representation contains totalParameterCount field");
    }

    /**
     * Verify that readParameterWordsWireFormat parses the SMB header
     * correctly and updates all relevant members.
     */
    @Test
    public void readParameterWordsWireFormat_parsesHeaderCorrectly() {
        DummyResponse d = new DummyResponse();
        // Construct a minimal wire format buffer (indices are explicit
        // and padded so that the code path in the source file is exercised.)
        byte[] buf = new byte[32];
        int idx = 0;
        // Helper to write values little‑endian
        buf[idx++] = 5; // totalParameterCount low byte
        buf[idx++] = 0; // totalParameterCount high byte -> value 5
        buf[idx++] = 3; // totalDataCount low
        buf[idx++] = 0; // totalDataCount high
        idx += 4; // 4‑byte reserved field, leave zeros
        buf[8] = 2; // parameterCount low
        buf[9] = 0; // high
        buf[10] = 4; // parameterOffset low
        buf[11] = 0; // high
        buf[12] = 6; // parameterDisplacement low
        buf[13] = 0; // high
        buf[14] = 7; // dataCount low
        buf[15] = 0; // high
        buf[16] = 8; // dataOffset low
        buf[17] = 0; // high
        buf[18] = 9; // dataDisplacement low
        buf[19] = 0; // high
        buf[20] = 1; // setupCount low (only one byte consumed)
        // Call the method under test
        d.readParameterWordsWireFormat(buf, 0, 0);

        assertEquals(5, d.getTotalParameterCount(), "totalParameterCount parsed correctly");
        assertEquals(3, d.getTotalDataCount(), "totalDataCount parsed correctly");
        assertEquals(2, d.getParameterCount(), "parameterCount parsed");
        assertEquals(7, d.getDataCount(), "dataCount parsed");
        assertEquals(1, d.getSetupCount(), "setupCount parsed");
        // When bufDataStart was zero it should be set to totalParameterCount
        assertEquals(5, d.getBufferParameterStart(), "bufParameterStart inferred from totalParameterCount");
    }

    /**
     * Exercise readBytesWireFormat where both parameter and data are
     * copied in a single call.
     */
    @Test
    public void readBytesWireFormat_succeedsWithSingleRead() {
        DummyResponse d = new DummyResponse();
        // Allocate a transaction buffer large enough for the copy.
        byte[] tx = new byte[100];
        d.setTxnBuf(tx);

        // Set up a situation where the payload is in the buffer and
        // the counts indicate that the full packet will be read.
        d.setBufParameterStart(0);
        d.setBufDataStart(20);
        d.parameterCount = 5; // number of words to read
        d.parameterOffset = 2; // where the parameter words begin in the buffer
        d.parameterDisplacement = 0;
        d.dataCount = 4; // number of words to read for data
        d.dataOffset = 10; // offset for data words
        d.dataDisplacement = 0;
        // Prepare dummy payloads
        byte[] payload = new byte[40];
        // Fill data section with distinguishable pattern
        for (int i = 0; i < payload.length; i++) {
            payload[i] = (byte) ('A' + i);
        }
        // The buffer contains parameters followed by data.  We only
        // test that system.arraycopy copies the correct slice.
        byte[] buf = new byte[40];
        System.arraycopy(payload, d.parameterOffset, buf, 0, payload.length - d.parameterOffset);
        d.readBytesWireFormat(buf, 0, payload.length, 0, 0, 0);
        // After a full read both flags should be set and hasMore toggled
        assertTrue(d.getParametersDone(), "parametersDone should be true after reading");
        assertTrue(d.getDataDone(), "dataDone should be true after reading");
        assertTrue(d.getHasMore(), "hasMore should be true when both packets read");
    }
}


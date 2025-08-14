package jcifs.smb1.smb1;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Field;

import org.junit.jupiter.api.Test;

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

        // Expose protected/private fields for testing
        boolean getIsPrimary() {
            return isPrimary;
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

        // Helper methods to access private fields using reflection
        protected void setFieldValue(String fieldName, Object value) {
            try {
                Field field = null;
                Class<?> clazz = this.getClass();
                while (clazz != null && field == null) {
                    try {
                        field = clazz.getDeclaredField(fieldName);
                    } catch (NoSuchFieldException e) {
                        clazz = clazz.getSuperclass();
                    }
                }
                if (field == null) {
                    throw new NoSuchFieldException(fieldName);
                }
                field.setAccessible(true);
                field.set(this, value);
            } catch (Exception e) {
                throw new RuntimeException("Failed to set field " + fieldName, e);
            }
        }

        protected Object getFieldValue(String fieldName) {
            try {
                Field field = null;
                Class<?> clazz = this.getClass();
                while (clazz != null && field == null) {
                    try {
                        field = clazz.getDeclaredField(fieldName);
                    } catch (NoSuchFieldException e) {
                        clazz = clazz.getSuperclass();
                    }
                }
                if (field == null) {
                    throw new NoSuchFieldException(fieldName);
                }
                field.setAccessible(true);
                return field.get(this);
            } catch (Exception e) {
                throw new RuntimeException("Failed to get field " + fieldName, e);
            }
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
            return (boolean) getFieldValue("parametersDone");
        }

        boolean isDataDone() {
            return (boolean) getFieldValue("dataDone");
        }

        boolean isHasMore() {
            return hasMore;
        }

        void setErrorCode(int code) {
            errorCode = code;
        }

        void setHasMore(boolean val) {
            hasMore = val;
        }

        boolean getParametersDone() {
            return (boolean) getFieldValue("parametersDone");
        }

        boolean getDataDone() {
            return (boolean) getFieldValue("dataDone");
        }

        int getBufferParameterStart() {
            return bufParameterStart;
        }

        int getBufferDataStart() {
            return bufDataStart;
        }

        byte[] getTxnBuf() {
            return txn_buf;
        }

        int getParameterDisplacement() {
            return parameterDisplacement;
        }

        int getDataDisplacement() {
            return dataDisplacement;
        }

        int getParameterOffset() {
            return parameterOffset;
        }

        int getDataOffset() {
            return dataOffset;
        }

        boolean getHasMore() {
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
        d.setErrorCode(123); // non-zero error
        assertFalse(d.hasMoreElements(), "errorCode non-zero overrides hasMore flag");
    }

    @Test
    public void nextElement_firstCall_flipsIsPrimary() {
        DummyResponse d = new DummyResponse();
        // Initially isPrimary is true (inherited constructor)
        SmbComTransactionResponse r1 = (SmbComTransactionResponse) d.nextElement();
        assertSame(d, r1, "nextElement should return the same instance");
        // After first call isPrimary should be false
        assertFalse(d.getIsPrimary(), "isPrimary should be cleared after first call");
        // Second call keeps the same state
        SmbComTransactionResponse r2 = (SmbComTransactionResponse) d.nextElement();
        assertSame(d, r2, "Subsequent calls still return same instance");
        assertFalse(d.getIsPrimary(), "isPrimary remains false after subsequent call");
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
        // Construct a minimal wire format buffer
        byte[] buf = new byte[32];
        int idx = 0;
        // Write values little-endian
        buf[idx++] = 5; // totalParameterCount low byte
        buf[idx++] = 0; // totalParameterCount high byte -> value 5
        buf[idx++] = 3; // totalDataCount low
        buf[idx++] = 0; // totalDataCount high
        idx += 2; // 2-byte reserved field (not 4 as the code shows)
        buf[6] = 2; // parameterCount low
        buf[7] = 0; // high
        buf[8] = 4; // parameterOffset low
        buf[9] = 0; // high
        buf[10] = 6; // parameterDisplacement low
        buf[11] = 0; // high
        buf[12] = 7; // dataCount low
        buf[13] = 0; // high
        buf[14] = 8; // dataOffset low
        buf[15] = 0; // high
        buf[16] = 9; // dataDisplacement low
        buf[17] = 0; // high
        buf[18] = 1; // setupCount (only one byte)

        // Call the method under test
        d.readParameterWordsWireFormat(buf, 0);

        assertEquals(5, d.getTotalParameterCount(), "totalParameterCount parsed correctly");
        assertEquals(3, d.getTotalDataCount(), "totalDataCount parsed correctly");
        assertEquals(2, d.getParameterCount(), "parameterCount parsed");
        assertEquals(7, d.getDataCount(), "dataCount parsed");
        assertEquals(1, d.getSetupCount(), "setupCount parsed");
        // When bufDataStart was zero it should be set to totalParameterCount
        assertEquals(5, d.getBufferDataStart(), "bufDataStart inferred from totalParameterCount");
    }

    /**
     * Exercise readBytesWireFormat where both parameter and data are
     * copied in a single call.
     */
    @Test
    public void readBytesWireFormat_succeedsWithSingleRead() {
        DummyResponse d = new DummyResponse();
        // Allocate a transaction buffer large enough for the copy
        byte[] tx = new byte[100];
        d.txn_buf = tx;

        // Set up a scenario where the full transaction is read in one call
        d.bufParameterStart = 0;
        d.bufDataStart = 20;
        d.totalParameterCount = 5; // Total parameter count
        d.totalDataCount = 4; // Total data count
        d.parameterCount = 5; // Current parameter count matches total
        d.parameterOffset = 2; // Absolute offset in the SMB message
        d.parameterDisplacement = 0;
        d.dataCount = 4; // Current data count matches total
        d.dataOffset = 10; // Absolute offset in the SMB message
        d.dataDisplacement = 0;
        d.headerStart = 0; // Set headerStart (bufferIndex will be 0)

        // Prepare buffer with test data
        byte[] buf = new byte[100];
        for (int i = 0; i < buf.length; i++) {
            buf[i] = (byte) ('A' + (i % 26));
        }

        // Call the method under test
        d.readBytesWireFormat(buf, 0);

        // After a full read both flags should be set and hasMore should be false
        assertTrue(d.getParametersDone(), "parametersDone should be true after reading");
        assertTrue(d.getDataDone(), "dataDone should be true after reading");
        assertFalse(d.getHasMore(), "hasMore should be false when both packets are fully read");
    }

    /**
     * Test partial read scenario where parameters are not fully read
     */
    @Test
    public void readBytesWireFormat_partialRead_doesNotSetFlags() {
        DummyResponse d = new DummyResponse();
        byte[] tx = new byte[100];
        d.txn_buf = tx;

        // Set up a partial read scenario
        d.bufParameterStart = 0;
        d.bufDataStart = 20;
        d.totalParameterCount = 10; // Total is 10
        d.totalDataCount = 8; // Total is 8
        d.parameterCount = 5; // Only reading 5 of 10
        d.parameterOffset = 2;
        d.parameterDisplacement = 0;
        d.dataCount = 4; // Only reading 4 of 8
        d.dataOffset = 10;
        d.dataDisplacement = 0;
        d.headerStart = 0;

        byte[] buf = new byte[100];
        d.readBytesWireFormat(buf, 0);

        // Flags should not be set for partial read
        assertFalse(d.getParametersDone(), "parametersDone should be false for partial read");
        assertFalse(d.getDataDone(), "dataDone should be false for partial read");
        assertTrue(d.getHasMore(), "hasMore should remain true for partial read");
    }

    /**
     * Test scenario with no data to read
     */
    @Test
    public void readBytesWireFormat_noData_succeeds() {
        DummyResponse d = new DummyResponse();
        byte[] tx = new byte[100];
        d.txn_buf = tx;

        // Set up scenario with no data
        d.bufParameterStart = 0;
        d.bufDataStart = 20;
        d.totalParameterCount = 0;
        d.totalDataCount = 0;
        d.parameterCount = 0;
        d.dataCount = 0;
        d.headerStart = 0;

        byte[] buf = new byte[100];
        int result = d.readBytesWireFormat(buf, 0);

        // Should handle empty read gracefully
        assertEquals(0, result, "Should return 0 for no data");
        assertTrue(d.getParametersDone(), "parametersDone should be true when total is 0");
        assertTrue(d.getDataDone(), "dataDone should be true when total is 0");
    }
}
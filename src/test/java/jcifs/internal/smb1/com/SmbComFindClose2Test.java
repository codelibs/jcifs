package jcifs.internal.smb1.com;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import jcifs.Configuration;

/**
 * Unit tests for {@link SmbComFindClose2}.
 * The class is intentionally tiny – the tests mainly verify that the
 * parameter word (the session identifier) is written in little‑endian form
 * and that the {@code toString} helper contains the expected values.
 *
 * <p>The tests also exercise edge cases such as negative (wrap‑around) session
 * identifiers and confirm that the writer does not alter any internal state.
 *</p>
 */
@ExtendWith(MockitoExtension.class)
class SmbComFindClose2Test {

    @Mock
    private Configuration mockConfig;

    private SmbComFindClose2 instance;
    private final int TEST_SID = 0x1234; // 4660 decimal

    @BeforeEach
    void setUp() {
        instance = new SmbComFindClose2(mockConfig, TEST_SID);
    }

    @Test
    void testConstructorAndToString() {
        String s = instance.toString();
        // toString includes the class name and the sid field
        assertTrue(s.startsWith("SmbComFindClose2["));
        assertTrue(s.contains("sid=" + TEST_SID));
    }

    @Test
    void testWriteParameterWordsWireFormatLittleEndian() {
        byte[] dst = new byte[2];
        int written = instance.writeParameterWordsWireFormat(dst, 0);
        assertEquals(2, written, "writeParameterWordsWireFormat should write exactly 2 bytes");
        // SMBUtil.writeInt2 writes the low byte first (little‑endian)
        assertEquals((byte) (TEST_SID & 0xFF), dst[0]);
        assertEquals((byte) ((TEST_SID >> 8) & 0xFF), dst[1]);
    }

    @Test
    void testNegativeSidWrapsCorrectly() {
        // -1 == 0xFFFF
        int negativeSid = -1;
        SmbComFindClose2 neg = new SmbComFindClose2(mockConfig, negativeSid);
        byte[] dst = new byte[2];
        int written = neg.writeParameterWordsWireFormat(dst, 0);
        assertEquals(2, written);
        assertArrayEquals(new byte[] { (byte) 0xFF, (byte) 0xFF }, dst, "Negative sid should wrap to 0xFFFF");
    }

    @Test
    void testWriteParameterWordsWithOffset() {
        byte[] dst = new byte[5];
        int written = instance.writeParameterWordsWireFormat(dst, 3);
        assertEquals(2, written);
        assertEquals((byte) (TEST_SID & 0xFF), dst[3]);
        assertEquals((byte) ((TEST_SID >> 8) & 0xFF), dst[4]);
    }

    @Test
    void testReadParameterWordsReturnsZero() {
        byte[] buffer = new byte[2];
        int rc = instance.readParameterWordsWireFormat(buffer, 0);
        assertEquals(0, rc, "readParameterWordsWireFormat should return 0 for this SMB");
    }

    @Test
    void testWriteBytesReturnsZero() {
        byte[] dst = new byte[1];
        int rc = instance.writeBytesWireFormat(dst, 0);
        assertEquals(0, rc, "SmbComFindClose2 has no body to write");
    }
}

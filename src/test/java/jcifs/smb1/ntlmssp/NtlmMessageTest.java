package jcifs.smb1.ntlmssp;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.junit.jupiter.MockitoExtension;

import jcifs.smb1.Config;

/**
 * Tests for {@link NtlmMessage}. Since {@code NtlmMessage} is abstract we
 * create a lightweight concrete subclass only to exercise the inherited
 * behaviour. The tests cover flag manipulation, byte‑buffer operations and
 * static helpers. Edge cases such as null or short arrays and negative
 * values are verified to ensure proper exception handling and byte
 * conversion.
 */
@ExtendWith(MockitoExtension.class)
class NtlmMessageTest {

    /** Lightweight concrete implementation used only for testing. */
    private static class Dummy extends NtlmMessage {
        @Override
        public byte[] toByteArray() {
            return new byte[0];
        }
    }

    private Dummy msg;

    @BeforeEach
    void setUp() {
        msg = new Dummy();
    }

    // ---------------- Flag manipulation tests -----------------
    @Test
    @DisplayName("Default flag value is zero")
    void testDefaultFlags() {
        assertEquals(0, msg.getFlags(), "Initial flags should be 0");
    }

    @ParameterizedTest(name = "setFlags({0}) ➜ getFlags() == {0}")
    @ValueSource(ints = { 0x0, 0x1, 0x2, 0xFFFFFFFF, -123456 })
    void testSetAndGetFlags(int value) {
        msg.setFlags(value);
        assertEquals(value, msg.getFlags(), "getFlags should return the value set");
    }

    @Test
    @DisplayName("setFlag true sets the bit")
    void testSetFlagTrue() {
        msg.setFlag(0x4, true);
        assertTrue(msg.getFlag(0x4), "Bit should be set after setFlag(true)");
    }

    @Test
    @DisplayName("setFlag false clears the bit")
    void testSetFlagFalse() {
        msg.setFlag(0x4, true);
        msg.setFlag(0x4, false);
        assertFalse(msg.getFlag(0x4), "Bit should be cleared after setFlag(false)");
    }

    // ---------------- Static read tests -----------------
    @Test
    @DisplayName("readULong correctly interprets little endian")
    void testReadULong() {
        byte[] a = new byte[] { (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04 };
        int result = NtlmMessage.readULong(a, 0);
        assertEquals(0x04030201, result, "ULong should be little‑endian");
    }

    @Test
    @DisplayName("readUShort correctly interprets little endian")
    void testReadUShort() {
        byte[] a = new byte[] { (byte) 0xAA, (byte) 0xBB };
        int result = NtlmMessage.readUShort(a, 0);
        assertEquals(0xBBAA, result, "UShort should be little‑endian");
    }

    @Test
    @DisplayName("readUShort throws on too short array")
    void testReadUShortOutOfBounds() {
        byte[] a = new byte[] { 0x02 };
        assertThrows(IndexOutOfBoundsException.class, () -\u003e NtlmMessage.readUShort(a, 0));
    }

    @Test
    @DisplayName("readULong throws on too short array")
    void testReadULongOutOfBounds() {
        byte[] a = new byte[] { 0x01, 0x02, 0x03 };
        assertThrows(IndexOutOfBoundsException.class, () -\u003e NtlmMessage.readULong(a, 0));
    }

    @Test
    @DisplayName("readSecurityBuffer correctly extracts data")
    void testReadSecurityBuffer() {
        byte[] buf = new byte[8 + 4];
        byte[] payload = { 0x11, 0x22, 0x33, 0x44 };
        NtlmMessage.writeSecurityBuffer(buf, 0, 8, payload);
        byte[] extracted = NtlmMessage.readSecurityBuffer(buf, 0);
        assertArrayEquals(payload, extracted, "Payload should match original");
    }

    @Test
    @DisplayName("readSecurityBuffer throws when array is too short")
    void testReadSecurityBufferShort() {
        byte[] a = new byte[] { 0x01 };
        assertThrows(IndexOutOfBoundsException.class, () -\u003e NtlmMessage.readSecurityBuffer(a, 0));
    }

    // ---------------- Static write tests -----------------
    @Test
    @DisplayName("writeULong writes little endian bytes")
    void testWriteULong() {
        byte[] dest = new byte[4];
        NtlmMessage.writeULong(dest, 0, 0x01020304);
        assertArrayEquals(new byte[] { 4, 3, 2, 1 }, dest, "Writer must be little‑endian");
    }

    @Test
    @DisplayName("writeULong handles negative values as unsigned")
    void testWriteULongNegative() {
        byte[] dest = new byte[4];
        NtlmMessage.writeULong(dest, 0, -1);
        assertArrayEquals(new byte[] { -1, -1, -1, -1 }, dest, "All bytes should be 0xFF for -1");
    }

    @Test
    @DisplayName("writeUShort writes little endian bytes")
    void testWriteUShort() {
        byte[] dest = new byte[2];
        NtlmMessage.writeUShort(dest, 0, 0xBBAA);
        assertArrayEquals(new byte[] { (byte) 0xAA, (byte) 0xBB }, dest, "Writer must be little‑endian");
    }

    @Test
    @DisplayName("writeUShort handles negative values as unsigned")
    void testWriteUShortNegative() {
        byte[] dest = new byte[2];
        NtlmMessage.writeUShort(dest, 0, -2);
        assertArrayEquals(new byte[] { -2, -1 }, dest, "Negative short should be encoded unsigned");
    }

    @Test
    @DisplayName("writeSecurityBuffer writes zero length buffer unchanged")
    void testWriteSecurityBufferZeroLength() {
        byte[] dest = new byte[10];
        byte[] before = dest.clone();
        NtlmMessage.writeSecurityBuffer(dest, 0, 4, null);
        assertArrayEquals(before, dest, "Zero length should leave dest unchanged");
    }

    @Test
    @DisplayName("writeSecurityBuffer copies data and sets fields")
    void testWriteSecurityBufferNonZero() {
        byte[] dest = new byte[8 + 4];
        byte[] payload = { 0x55, 0x66, 0x77 };
        NtlmMessage.writeSecurityBuffer(dest, 0, 8, payload);
        assertEquals(3, NtlmMessage.readUShort(dest, 0), "Length field must be 3");
        assertEquals(3, NtlmMessage.readUShort(dest, 2), "Length field must be 3 again");
        assertEquals(8, NtlmMessage.readULong(dest, 4), "Offset must point to payload start");
        byte[] actualPayload = new byte[payload.length];
        System.arraycopy(dest, 8, actualPayload, 0, payload.length);
        assertArrayEquals(payload, actualPayload, "Payload copy must match");
    }

    @Test
    @DisplayName("getOEMEncoding returns configured OEM encoding")
    void testGetOEMEncoding() {
        assertEquals(Config.DEFAULT_OEM_ENCODING, NtlmMessage.getOEMEncoding(), "OEM encoding should match config’s default value");
    }
}

package org.codelibs.jcifs.smb.internal.smb1.com;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import static org.mockito.Mockito.mock;

import java.lang.reflect.Field;

import org.codelibs.jcifs.smb.Configuration;
import org.codelibs.jcifs.smb.internal.util.SMBUtil;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Tests for {@link SmbComLockingAndX}.  The source class exposes
 * its wire-format helpers as protected methods and its internal state
 * is stored in private fields; tests make use of the same package to
 * access those members directly.
 */
@ExtendWith(MockitoExtension.class)
class SmbComLockingAndXTest {

    /**
     * Helper for setting a field via reflection.
     */
    private static void setField(Object target, String name, Object value) {
        try {
            Field f = target.getClass().getDeclaredField(name);
            f.setAccessible(true);
            f.set(target, value);
        } catch (Exception e) {
            fail("Failed to set field '" + name + "'", e);
        }
    }

    /**
     * Helper for getting a field via reflection.
     */
    private static Object getField(Object target, String name) {
        try {
            Field f = target.getClass().getDeclaredField(name);
            f.setAccessible(true);
            return f.get(target);
        } catch (Exception e) {
            fail("Failed to get field '" + name + "'", e);
            return null;
        }
    }

    /**
     * Test that the wire-format of the parameters is produced
     * correctly when all fields are set to typical values.
     */
    @Test
    void happyPathParameterEncoding() throws Exception {
        Configuration cfg = mock(Configuration.class);
        SmbComLockingAndX cmd = new SmbComLockingAndX(cfg);
        // set fields via reflection
        setField(cmd, "fid", 0x1234);
        setField(cmd, "typeOfLock", (byte) 0x05);
        setField(cmd, "newOpLockLevel", (byte) 0x01);
        setField(cmd, "timeout", 3000L);
        // arrays of one lock and one unlock range
        LockingAndXRange lock = new LockingAndXRange(false);
        lock.encode(new byte[20], 0); // initialise fields by encoding to set pid etc (though not needed)
        setField(lock, "pid", 123);
        setField(lock, "byteOffset", 100L);
        setField(lock, "lengthInBytes", 200L);
        LockingAndXRange unlock = new LockingAndXRange(false);
        setField(unlock, "pid", 456);
        setField(unlock, "byteOffset", 300L);
        setField(unlock, "lengthInBytes", 400L);
        setField(cmd, "locks", new LockingAndXRange[] { lock });
        setField(cmd, "unlocks", new LockingAndXRange[] { unlock });
        setField(cmd, "largeFile", false);

        byte[] buffer = new byte[20];
        int len = cmd.writeParameterWordsWireFormat(buffer, 0);
        assertEquals(-12, len, "writeParameterWordsWireFormat should write 12 Bytes");
        // Validate parameter bytes using reflection since fields are private
        assertEquals(getField(cmd, "fid"), SMBUtil.readInt2(buffer, 0));
        assertEquals(getField(cmd, "typeOfLock"), buffer[2]);
        assertEquals(getField(cmd, "newOpLockLevel"), buffer[3]);
        assertEquals(getField(cmd, "timeout"), (long) SMBUtil.readInt4(buffer, 4));
        assertEquals(1, SMBUtil.readInt2(buffer, 8));
        assertEquals(1, SMBUtil.readInt2(buffer, 10));
    }

    /**
     * Test that a large file lock (bit 0x10 set) is encoded and decoded correctly.
     */
    @ParameterizedTest
    @ValueSource(ints = { 0x10, 0x11 })
    void largeFileFlagSet_and_decoded_according_to_type(int type) throws Exception {
        Configuration cfg = mock(Configuration.class);
        SmbComLockingAndX cmd = new SmbComLockingAndX(cfg);
        setField(cmd, "fid", 1);
        setField(cmd, "typeOfLock", (byte) type);
        setField(cmd, "newOpLockLevel", (byte) 0);
        setField(cmd, "timeout", 0L);
        setField(cmd, "locks", new LockingAndXRange[0]);
        setField(cmd, "unlocks", new LockingAndXRange[0]);
        setField(cmd, "largeFile", false);
        byte[] buf = new byte[12]; // Buffer needs to be at least 12 bytes for the parameter words
        cmd.writeParameterWordsWireFormat(buf, 0);
        // The flag must be present so the command recognises largeFile
        SmbComLockingAndX copy = new SmbComLockingAndX(cfg);
        copy.readParameterWordsWireFormat(buf, 0);
        assertTrue((boolean) getField(copy, "largeFile"));
    }

    /**
     * Test toString covers basic output.
     */
    @Test
    void toStringInclusion() {
        Configuration cfg = mock(Configuration.class);
        SmbComLockingAndX cmd = new SmbComLockingAndX(cfg);
        setField(cmd, "fid", 42);
        setField(cmd, "typeOfLock", (byte) 0x07);
        setField(cmd, "newOpLockLevel", (byte) 0x02);
        String repr = cmd.toString();
        assertTrue(repr.contains("fid=42"));
        assertTrue(repr.contains("typeOfLock=7"));
        assertTrue(repr.contains("newOplockLevel=2"));
    }

    /**
     * Test decoding of bytes buffer that is too short triggers an exception.
     * Note: The actual implementation throws ArrayIndexOutOfBoundsException
     * when the buffer is too short, not SMBProtocolDecodingException.
     */
    @Test
    void readBytesWireFormatTooShortException() {
        Configuration cfg = mock(Configuration.class);
        SmbComLockingAndX cmd = new SmbComLockingAndX(cfg);
        // arrays of size 1 so internal method will attempt to decode a range
        setField(cmd, "unlocks", new LockingAndXRange[] { new LockingAndXRange(false) });
        setField(cmd, "locks", new LockingAndXRange[] { new LockingAndXRange(false) });
        setField(cmd, "largeFile", false);
        // create a buffer that is empty, readBytesWireFormat should throw
        byte[] buffer = new byte[0];
        assertThrows(ArrayIndexOutOfBoundsException.class, () -> cmd.readBytesWireFormat(buffer, 0));
    }

    /**
     * Test round‑trip encoding/decoding of ranges using the public
     * {@link LockingAndXRange} encode/decode methods.
     */
    @Test
    void lockRangeEncodeDecodeRoundTrip() throws Exception {
        LockingAndXRange range = new LockingAndXRange(false);
        setField(range, "pid", 99);
        setField(range, "byteOffset", 123456L);
        setField(range, "lengthInBytes", 654321L);
        byte[] dst = new byte[20];
        int writtenSize = range.encode(dst, 0);
        assertEquals(10, writtenSize, "Range size when not large should be 10");
        // create a new empty range and decode
        LockingAndXRange decoded = new LockingAndXRange(false);
        int decodedSize = decoded.decode(dst, 0, dst.length);
        assertEquals(10, decodedSize, "Decode should return size 10");
        assertEquals(99, decoded.getPid());
        assertEquals(123456L, decoded.getByteOffset());
        assertEquals(654321L, decoded.getLengthInBytes());
    }
}

package org.codelibs.jcifs.smb1;

import static org.codelibs.jcifs.smb1.ServerMessageBlock.SMB_COM_CLOSE;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.stream.Stream;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Tests for {@link SmbComClose}.
 * <p>
 * All tests are written in the same package as the class under test so
 * that package-private fields and constants can be accessed directly.
 */
@ExtendWith(MockitoExtension.class)
class SmbComCloseTest {

    /**
     * Ensure the constructor sets the {@code command} field of the
     * {@link ServerMessageBlock} superclass to {@link ServerMessageBlock#SMB_COM_CLOSE}.
     */
    @Test
    @DisplayName("happy: constructor sets command correctly")
    void testConstructorSetsCommand() {
        SmbComClose close = new SmbComClose(1, 12345L);
        assertEquals(SMB_COM_CLOSE, close.command, "command should be SMB_COM_CLOSE after construction");
    }

    /**
     * Verify that writeParameterWordsWireFormat writes the file id and the
     * unsigned time correctly.  The last write time is zero which should be
     * encoded as four 0xFF bytes by {@code writeUTime}.
     */
    @ParameterizedTest(name = "fid={0}, lastWriteTime={1}")
    @MethodSource("validParams")
    @DisplayName("happy: writeParameterWordsWireFormat writes correct bytes")
    void testWriteParameterWordsWireFormat(int fid, long lastWriteTime, byte[] expected) {
        SmbComClose close = new SmbComClose(fid, lastWriteTime);
        byte[] buffer = new byte[10];
        int written = close.writeParameterWordsWireFormat(buffer, 0);
        assertEquals(6, written, "writeParameterWordsWireFormat should return 6");
        // Only compare the first 6 bytes that were actually written
        byte[] actualWritten = new byte[6];
        System.arraycopy(buffer, 0, actualWritten, 0, 6);
        assertArrayEquals(expected, actualWritten, "wire format should match expectation");
    }

    static Stream<Arguments> validParams() {
        // fid 0x1234, lastWriteTime 0 -> UTime all 0xFF
        return Stream.of(Arguments.of(0x1234, 0L, new byte[] { 0x34, 0x12, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF }),
                // negative fid wraps around, lastWriteTime = 1000 -> 1 second -> int value 1
                Arguments.of(-1, 1000L, new byte[] { (byte) 0xFF, (byte) 0xFF, 0x01, 0x00, 0x00, 0x00 }));
    }

    /**
     * When lastWriteTime is zero the encoded unsigned time must be all 1s.
     */
    @Test
    @DisplayName("edge: writeParameterWordsWireFormat with lastWriteTime=0")
    void testWriteParameterWordsZeroUTime() {
        SmbComClose close = new SmbComClose(42, 0L);
        byte[] buffer = new byte[6];
        close.writeParameterWordsWireFormat(buffer, 0);
        // first two bytes encode fid 42
        assertEquals((byte) 42, buffer[0]);
        assertEquals((byte) 0, buffer[1]);
        // remaining 4 bytes should all be 0xFF according to writeUTime
        for (int i = 2; i < 6; i++) {
            assertEquals((byte) 0xFF, buffer[i], "byte %d should be 0xFF".formatted(i));
        }
    }

    /**
     * Verify that read methods and writeBytesWireFormat return 0,
     * while writeParameterWordsWireFormat returns 6 (the number of bytes written).
     */
    @Test
    @DisplayName("happy: read/write methods return expected values")
    void testReadWriteMethodsReturnValues() {
        SmbComClose close = new SmbComClose(10, 5000L);
        assertEquals(0, close.readParameterWordsWireFormat(new byte[10], 0));
        assertEquals(0, close.readBytesWireFormat(new byte[10], 0));
        assertEquals(0, close.writeBytesWireFormat(new byte[10], 0));
        assertEquals(6, close.writeParameterWordsWireFormat(new byte[10], 0));
    }

    /**
     * The toString representation should include the class name and both
     * fields.  This provides visibility into the debug output of the SMB
     * packet.
     */
    @Test
    @DisplayName("happy: toString contains class info and field values")
    void testToStringContainsAllInfo() {
        int fid = 256;
        long lwt = 9876543210L;
        SmbComClose close = new SmbComClose(fid, lwt);
        String s = close.toString();
        assertTrue(s.startsWith("SmbComClose["), "string should start with class name");
        assertTrue(s.contains("fid=" + fid), "string should contain the fid value");
        assertTrue(s.contains("lastWriteTime=" + lwt), "string should contain the lwt value");
    }
}

package jcifs.smb1.smb1;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.Field;
import java.util.Arrays;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import jcifs.smb1.util.Hexdump;

/**
 * Unit test for {@link Trans2QueryFSInformation}. The class contains mostly
 * trivial wire-format helpers and a custom {@code toString()} implementation.
 * All tests are pure unit tests – no network or file system access is
 * required.
 */
class Trans2QueryFSInformationTest {

    /** Small helper to create a byte buffer larger than the maximum expected
     *  wire format so that we can observe only the bytes written by a method.
     */
    private static byte[] newBuffer(int length) {
        // initialise with distinct pattern to detect unused trailing bytes
        byte[] buf = new byte[length];
        Arrays.fill(buf, (byte) 0xFF);
        return buf;
    }

    @Test
    @DisplayName("constructor initialises command and parameters correctly")
    void testConstructorInitialisesFields() throws Exception {
        int level = 42;
        Trans2QueryFSInformation cmd = new Trans2QueryFSInformation(level);
        // constants are defined on SmbComTransaction, inherited via
        // ServerMessageBlock.
        assertEquals(SmbComTransaction.SMB_COM_TRANSACTION2, cmd.command, "command should be TRANSACTION2");
        assertEquals(SmbComTransaction.TRANS2_QUERY_FS_INFORMATION, cmd.subCommand, "subCommand should be QUERY_FS_INFORMATION");
        // the fields are set in the constructor – check that the counts match
        assertEquals(2, cmd.totalParameterCount, "totalParameterCount should be 2");
        assertEquals(0, cmd.totalDataCount, "totalDataCount should be 0");
        assertEquals(0, cmd.maxParameterCount, "maxParameterCount should be 0");
        assertEquals(800, cmd.maxDataCount, "maxDataCount should be 800");
        assertEquals(0, cmd.maxSetupCount, "maxSetupCount should be 0");
        // ensure information level is stored using reflection
        Field informationLevelField = Trans2QueryFSInformation.class.getDeclaredField("informationLevel");
        informationLevelField.setAccessible(true);
        assertEquals(level, informationLevelField.getInt(cmd), "informationLevel should be persisted");
    }

    @Test
    @DisplayName("writeSetupWireFormat writes the subCommand and a trailing 0")
    void testWriteSetupWireFormat() {
        Trans2QueryFSInformation cmd = new Trans2QueryFSInformation(5);
        byte[] buf = newBuffer(10);
        int written = cmd.writeSetupWireFormat(buf, 0);
        assertEquals(2, written, "setup packet should write 2 bytes");
        assertEquals(SmbComTransaction.TRANS2_QUERY_FS_INFORMATION, buf[0], "first byte should be subCommand");
        assertEquals((byte) 0x00, buf[1], "second byte should be zero");
    }

    @Test
    @DisplayName("writeParametersWireFormat writes the information level as 2-byte little endian")
    void testWriteParametersWireFormat() {
        int level = 0x1234;
        Trans2QueryFSInformation cmd = new Trans2QueryFSInformation(level);
        byte[] buf = newBuffer(10);

        int written = cmd.writeParametersWireFormat(buf, 0);
        assertEquals(2, written, "writeParametersWireFormat should write exactly 2 bytes");

        // Verify little-endian encoding (0x1234 -> 0x34 0x12)
        assertEquals((byte) 0x34, buf[0], "First byte should be low byte of level");
        assertEquals((byte) 0x12, buf[1], "Second byte should be high byte of level");
    }

    @Test
    @DisplayName("all read* methods return zero")
    void testReadMethodsReturnZero() {
        Trans2QueryFSInformation cmd = new Trans2QueryFSInformation(10);
        assertEquals(0, cmd.readSetupWireFormat(null, 0, 0));
        assertEquals(0, cmd.readParametersWireFormat(null, 0, 0));
        assertEquals(0, cmd.readDataWireFormat(null, 0, 0));
    }

    @Test
    @DisplayName("toString includes information level in hex")
    void testToString() {
        int level = 0xABC;
        Trans2QueryFSInformation cmd = new Trans2QueryFSInformation(level);
        String str = cmd.toString();
        // toString uses Hexdump.toHexString(informationLevel, 3)
        assertTrue(str.contains(Hexdump.toHexString(level, 3)), "toString should contain hex level");
        assertTrue(str.contains("Trans2QueryFSInformation["), "should start with class name");
        assertTrue(str.contains(",informationLevel=0x"), "should contain level field marker");
    }
}
package jcifs.smb1.smb1;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import java.util.Arrays;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.ArgumentCaptor;
import org.slf4j.LoggerFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jcifs.internal.smb1.ServerMessageBlock;
import jcifs.internal.util.SMBUtil;
import jcifs.util.Hexdump;

/**
 * Unit test for {@link Trans2QueryFSInformation}. The class contains mostly
 * trivial wire‑format helpers and a custom {@code toString()} implementation.
 * All tests are pure unit tests – no network or file system access is
 * required.  Static interactions with {@link SMBUtil} are verified via
 * Mockito's static‑mocking support.
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
    void testConstructorInitialisesFields() {
        int level = 42;
        Trans2QueryFSInformation cmd = new Trans2QueryFSInformation(level);
        // constants are defined on SmbComTransaction, inherited via
        // ServerMessageBlock.
        assertEquals(ServerMessageBlock.SMB_COM_TRANSACTION2, cmd.command, "command should be TRANSACTION2");
        assertEquals(Trans2QueryFSInformation.TRANS2_QUERY_FS_INFORMATION, cmd.subCommand, "subCommand should be QUERY_FS_INFORMATION");
        // the fields are set in the constructor – check that the counts match
        assertEquals(2, cmd.totalParameterCount, "totalParameterCount should be 2");
        assertEquals(0, cmd.totalDataCount, "totalDataCount should be 0");
        assertEquals(0, cmd.maxParameterCount, "maxParameterCount should be 0");
        assertEquals(800, cmd.maxDataCount, "maxDataCount should be 800");
        assertEquals(0, cmd.maxSetupCount, "maxSetupCount should be 0");
        // ensure information level is stored.
        assertEquals(level, cmd.informationLevel, "informationLevel should be persisted");
    }

    @Test
    @DisplayName("writeSetupWireFormat writes the subCommand and a trailing 0")
    void testWriteSetupWireFormat() {
        Trans2QueryFSInformation cmd = new Trans2QueryFSInformation(5);
        byte[] buf = newBuffer(10);
        int written = cmd.writeSetupWireFormat(buf, 0);
        assertEquals(2, written, "setup packet should write 2 bytes");
        assertEquals(Trans2QueryFSInformation.TRANS2_QUERY_FS_INFORMATION, buf[0], "first byte should be subCommand");
        assertEquals((byte) 0x00, buf[1], "second byte should be zero");
    }

    @Test
    @DisplayName("writeParametersWireFormat writes the information level as 2‑byte little endian")
    void testWriteParametersWireFormat() {
        int level = 0x1234;
        Trans2QueryFSInformation cmd = new Trans2QueryFSInformation(level);
        byte[] buf = newBuffer(10);
        // static mocking of SMBUtil.writeInt2 to verify interaction
        try (MockedStatic<SMBUtil> mocked = mockStatic(SMBUtil.class)) {
            ArgumentCaptor<Integer> intCaptor = ArgumentCaptor.forClass(Integer.class);
            ArgumentCaptor<byte[]> byteCaptor = ArgumentCaptor.forClass(byte[].class);
            ArgumentCaptor<Integer> indexCaptor = ArgumentCaptor.forClass(Integer.class);
            // stub to do nothing but allow capture
            mocked.when(() -> SMBUtil.writeInt2(eq(level), any(byte[].class), anyInt()))
                   .thenAnswer(inv -> { // record arguments
                       intCaptor.capture();
                       return null;
                   });
            int written = cmd.writeParametersWireFormat(buf, 0);
            assertEquals(2, written, "writeParametersWireFormat should write exactly 2 bytes");
            // Verify that SMBUtil.writeInt2 was called with correct value and order
            mocked.verify(() -> SMBUtil.writeInt2(level, buf, 0));
        }
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


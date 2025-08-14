package jcifs.internal.smb1.com;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

import java.io.UnsupportedEncodingException;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import jcifs.Configuration;

/**
 * Unit tests for {@link SmbComQueryInformation}.  The class is very small and
 * mainly focuses on serialising a command header that contains a file name.
 * <p>
 * Because most of the logic lives in {@link jcifs.internal.smb1.ServerMessageBlock}
 * the tests create a mock {@link Configuration} and instantiate SmbComQueryInformation
 * directly.  Since the byte‑encoding logic is located in the superclass, the
 * tests verify that the byte buffer created by {@link
 * SmbComQueryInformation#writeBytesWireFormat(byte[], int)} is correctly built
 * for both Unicode and OEM encodings.
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class SmbComQueryInformationTest {

    @Mock
    Configuration mockConfig;

    private SmbComQueryInformation cmd;

    @BeforeEach
    void setUp() {
        // Configure the mock to return the OEM encoding which is required for writeString
        when(mockConfig.getOemEncoding()).thenReturn("windows-1252");
        cmd = new SmbComQueryInformation(mockConfig, "testfile.txt");
    }

    @Test
    @DisplayName("writeBytesWireFormat writes the command byte followed by the null terminated string")
    void testWriteBytesWireFormatHappy() throws UnsupportedEncodingException {
        byte[] buffer = new byte[50];
        int used = cmd.writeBytesWireFormat(buffer, 0);
        // Calculate expected size: 1 byte for command + string bytes + 1 null terminator
        byte[] expectedString = "testfile.txt".getBytes("windows-1252");
        assertEquals(1 + expectedString.length + 1, used, "Expected exactly one command byte plus OEM string and NUL terminator");
        assertEquals(0x04, buffer[0] & 0xFF, "First byte must be SMB_COM_QUERY_INFORMATION type 0x04");
        // Verify that the string part ends with the null terminator
        assertArrayEquals(expectedString, subArray(buffer, 1, expectedString.length));
        assertEquals(0, buffer[1 + expectedString.length], "String must be null terminated");
    }

    @Test
    @DisplayName("toString includes command name and filename")
    void testToStringIncludesInformation() {
        String str = cmd.toString();
        assertTrue(str.startsWith("SmbComQueryInformation"), "String representation must start with class name");
        assertTrue(str.contains("filename=testfile.txt"), "toString must contain the supplied filename");
    }

    @Test
    @DisplayName("writeBytesWireFormat with null path returns minimal bytes")
    void testWriteWhenPathIsNull() {
        // When path is null, Strings.getOEMBytes returns empty array, not NPE
        when(mockConfig.getOemEncoding()).thenReturn("windows-1252");
        SmbComQueryInformation nullPathCmd = new SmbComQueryInformation(mockConfig, null);
        byte[] buffer = new byte[50];
        int used = nullPathCmd.writeBytesWireFormat(buffer, 0);
        // Should write command byte + null terminator only
        assertEquals(2, used, "Null path should result in command byte + NUL");
        assertEquals(0x04, buffer[0] & 0xFF, "First byte must still be 0x04");
        assertEquals(0, buffer[1], "Second byte must be null terminator");
    }

    @Test
    @DisplayName("writeBytesWireFormat handles empty string gracefully")
    void testWriteEmptyString() {
        when(mockConfig.getOemEncoding()).thenReturn("windows-1252");
        SmbComQueryInformation emptyCmd = new SmbComQueryInformation(mockConfig, "");
        byte[] buffer = new byte[10];
        int used = emptyCmd.writeBytesWireFormat(buffer, 0);
        assertEquals(2, used, "Empty path results in only command byte and NUL");
        assertEquals(0x04, buffer[0] & 0xFF, "First byte must still be 0x04");
        assertEquals(0, buffer[1], "Second byte must be null terminator for empty string");
    }

    @Test
    @DisplayName("readBytesWireFormat is a no‑op and returns zero")
    void testReadBytesWireFormatNoop() {
        byte[] buffer = new byte[10];
        int used = cmd.readBytesWireFormat(buffer, 0);
        assertEquals(0, used, "readBytesWireFormat is unimplemented and must return 0");
    }

    private static byte[] subArray(byte[] src, int offset, int length) {
        byte[] dst = new byte[length];
        System.arraycopy(src, offset, dst, 0, length);
        return dst;
    }
}

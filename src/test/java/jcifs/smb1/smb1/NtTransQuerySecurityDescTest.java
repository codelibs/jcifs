package jcifs.smb1.smb1;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.stream.Stream;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Unit tests for {@code NtTransQuerySecurityDesc}.
 *
 * The class under test contains a number of straightforward data‑layout
 * methods (writing parameters and handling empty wire formats) and an
 * informative {@link NtTransQuerySecurityDesc#toString()}. The tests
 * exercise normal behaviour, boundary values, and the interaction with
 * the underlying wire‑format helpers.
 */
@ExtendWith(MockitoExtension.class)
class NtTransQuerySecurityDescTest {

    /**
     * Helper that mimics the write logic used by
     * {@link NtTransQuerySecurityDesc#writeParametersWireFormat(byte[], int)}.
     */
    private static byte[] expectedParameters(int fid, int securityInformation) {
        ByteBuffer bb = ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN);
        bb.putShort((short) fid);
        bb.put((byte) 0x00); // Reserved
        bb.put((byte) 0x00); // Reserved
        bb.putInt(securityInformation);
        return bb.array();
    }

    /**
     * Provide a range of values that are valid for the constructor.
     */
    static Stream<org.junit.jupiter.params.provider.Arguments> validInputs() {
        return Stream.of(org.junit.jupiter.params.provider.Arguments.of(0x0001, 0x00000000),
                org.junit.jupiter.params.provider.Arguments.of(0xFFFF, 0x12345678),
                org.junit.jupiter.params.provider.Arguments.of(-1, -123456));
    }

    @ParameterizedTest
    @MethodSource("validInputs")
    void writeParametersWireFormat_writesCorrectly(int fid, int securityInformation) {
        NtTransQuerySecurityDesc cmd = new NtTransQuerySecurityDesc(fid, securityInformation);
        byte[] dst = new byte[15]; // Increased buffer size to accommodate offset + 8 bytes
        int offset = 3; // start in the middle to ensure no tail is overwritten
        int bytesWritten = cmd.writeParametersWireFormat(dst, offset);
        assertEquals(8, bytesWritten, "writeParametersWireFormat should write 8 bytes");

        byte[] expected = expectedParameters(fid, securityInformation);
        for (int i = 0; i < expected.length; i++) {
            final int idx = i;
            assertEquals(expected[i], dst[offset + i], () -> "byte index " + idx);
        }
        // The region before offset and after the payload must remain untouched.
        for (int i = 0; i < offset; i++) {
            final int idx = i;
            assertEquals(0, dst[i], () -> "pre-offset byte " + idx + " modified");
        }
        for (int i = offset + 8; i < dst.length; i++) {
            final int idx = i;
            assertEquals(0, dst[i], () -> "post-payload byte " + idx + " modified");
        }
    }

    @Test
    void writeSetupWireFormat_returnsZero() {
        NtTransQuerySecurityDesc cmd = new NtTransQuerySecurityDesc(0, 0);
        byte[] dst = new byte[4];
        assertEquals(0, cmd.writeSetupWireFormat(dst, 0));
    }

    @Test
    void readMethodsReturnZero() {
        NtTransQuerySecurityDesc cmd = new NtTransQuerySecurityDesc(0, 0);
        byte[] buf = new byte[10];
        assertEquals(0, cmd.readSetupWireFormat(buf, 0, buf.length));
        assertEquals(0, cmd.readParametersWireFormat(buf, 0, buf.length));
        assertEquals(0, cmd.readDataWireFormat(buf, 0, buf.length));
    }

    @ParameterizedTest
    @CsvSource({ "0, 0", // all zeros
            "-1, 2147483647", // negative fid, max positive security
            "12345, 999" // arbitrary numbers
    })
    void toString_includesCorrectHexValues(int fid, int securityInformation) {
        NtTransQuerySecurityDesc cmd = new NtTransQuerySecurityDesc(fid, securityInformation);
        String result = cmd.toString();
        assertTrue(result.startsWith("NtTransQuerySecurityDesc["), "toString should start with class name");
        String hexFid = String.format("%04X", fid & 0xFFFF);
        String hexSec = String.format("%08X", securityInformation & 0xFFFFFFFFL);
        assertTrue(result.contains("fid=0x" + hexFid), () -> "Expected hex fid " + hexFid + " in: " + result);
        assertTrue(result.contains("securityInformation=0x" + hexSec), () -> "Expected hex sec " + hexSec + " in: " + result);
    }
}

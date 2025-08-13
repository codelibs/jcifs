package jcifs.smb1.smb1;

import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.junit.jupiter.MockitoExtension;
import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;

/**
 * Test suite for {@link Trans2GetDfsReferral}.
 */
@org.junit.jupiter.api.extension.ExtendWith(MockitoExtension.class)
class Trans2GetDfsReferralTest {

    private static Object getPrivateField(Object target, String fieldName) throws Exception {
        Class<?> clazz = target.getClass();
        while (clazz != null) {
            try {
                Field f = clazz.getDeclaredField(fieldName);
                f.setAccessible(true);
                return f.get(target);
            } catch (NoSuchFieldException e) {
                clazz = clazz.getSuperclass();
            }
        }
        throw new NoSuchFieldException(fieldName);
    }

    private static void setPrivateField(Object target, String fieldName, Object value) throws Exception {
        Class<?> clazz = target.getClass();
        while (clazz != null) {
            try {
                Field f = clazz.getDeclaredField(fieldName);
                f.setAccessible(true);
                f.set(target, value);
                return;
            } catch (NoSuchFieldException e) {
                clazz = clazz.getSuperclass();
            }
        }
        throw new NoSuchFieldException(fieldName);
    }

    @Test
    @DisplayName("Constructor initializes fields")
    void testConstructor() throws Exception {
        Trans2GetDfsReferral cmd = new Trans2GetDfsReferral("/file");
        assertEquals("/file", getPrivateField(cmd, "path"));
        assertEquals((byte)0x00, getPrivateField(cmd, "maxSetupCount"));
        assertEquals(4096, getPrivateField(cmd, "maxDataCount"));
    }

    @Test
    @DisplayName("writeSetupWireFormat writes subCommand and padding")
    void testWriteSetup() throws Exception {
        Trans2GetDfsReferral cmd = new Trans2GetDfsReferral("foo");
        byte[] buf = new byte[2];
        int r = cmd.writeSetupWireFormat(buf, 0);
        assertEquals(2, r);
        byte subCmd = (byte) getPrivateField(cmd, "subCommand");
        assertEquals(subCmd, buf[0]);
        assertEquals((byte)0x00, buf[1]);
    }

    @Test
    @DisplayName("writeParametersWireFormat writes referral level and path")
    void testWriteParams() throws Exception {
        Trans2GetDfsReferral cmd = new Trans2GetDfsReferral("abc");
        setPrivateField(cmd, "maxReferralLevel", 0x12AB);
        byte[] buffer = new byte[100];
        int len = cmd.writeParametersWireFormat(buffer, 0);
        assertTrue(len >= 2);
        // writeInt2 writes in little-endian format (LSB first)
        assertEquals(0xAB, buffer[0] & 0xFF);
        assertEquals(0x12, buffer[1] & 0xFF);
        // Check that the path is written after the referral level
        // The path should be written starting at index 2
        // writeString adds null terminator
        assertTrue(len > 2, "Length should include path");
        String writtenPath = extractStringFromBuffer(buffer, 2, len - 2);
        assertTrue(writtenPath.contains("abc"), "Path should be written to buffer");
    }

    @Test
    @DisplayName("writeParametersWireFormat throws on null path")
    void testNullPath() {
        Trans2GetDfsReferral cmd = new Trans2GetDfsReferral(null);
        byte[] buffer = new byte[10];
        assertThrows(NullPointerException.class, () -> cmd.writeParametersWireFormat(buffer, 0));
    }

    @Nested
    @DisplayName("read methods are no‑ops")
    class ReadMethods {
        Trans2GetDfsReferral cmd = new Trans2GetDfsReferral("/foo");
        @Test void setup() { assertEquals(0, cmd.readSetupWireFormat(new byte[10],0,0)); }
        @Test void parameters() { assertEquals(0, cmd.readParametersWireFormat(new byte[10],0,0)); }
        @Test void data() { assertEquals(0, cmd.readDataWireFormat(new byte[10],0,0)); }
    }

    @Test
    @DisplayName("toString format")
    void testToString() throws Exception {
        Trans2GetDfsReferral cmd = new Trans2GetDfsReferral("/bar");
        String s = cmd.toString();
        assertTrue(s.contains("Trans2GetDfsReferral["));
        assertTrue(s.contains("filename=/bar"));
        assertTrue(s.contains("maxReferralLevel=0x3"));
    }

    @ParameterizedTest
    @ValueSource(ints = {0, 5, -1, 65534})
    @DisplayName("referral level variations")
    void testLevels(int level) throws Exception {
        Trans2GetDfsReferral cmd = new Trans2GetDfsReferral("foo");
        setPrivateField(cmd, "maxReferralLevel", level);
        byte[] buffer = new byte[100];
        int len = cmd.writeParametersWireFormat(buffer, 0);
        assertTrue(len >= 2);
        // writeInt2 writes in little-endian format (LSB first)
        int written = (buffer[0] & 0xFF) | ((buffer[1] & 0xFF) << 8);
        int expected = level & 0xFFFF;
        assertEquals(expected, written);
    }
    
    // Helper method to extract string from buffer
    private String extractStringFromBuffer(byte[] buffer, int offset, int maxLen) {
        int end = offset;
        while (end < offset + maxLen && buffer[end] != 0) {
            end++;
        }
        return new String(buffer, offset, end - offset, StandardCharsets.UTF_8);
    }
}


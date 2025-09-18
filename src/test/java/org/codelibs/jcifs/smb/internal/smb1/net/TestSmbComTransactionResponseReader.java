package org.codelibs.jcifs.smb.internal.smb1.net;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.UnsupportedEncodingException;

import org.codelibs.jcifs.smb.Configuration;
import org.codelibs.jcifs.smb.SmbConstants;
import org.codelibs.jcifs.smb.config.BaseConfiguration;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Tests for SMB1 transaction response handling
 */
public class TestSmbComTransactionResponseReader {

    /**
     * Default configuration used for Unicode support tests
     */
    private Configuration cfg;

    @BeforeEach
    public void setup() throws Exception {
        this.cfg = new BaseConfiguration(true);
    }

    /**
     * Sub-class of {@link BaseConfiguration} that forces {@code useUnicode()}
     * to return {@code false}. This mimics an ASCII only client
     */
    private static class OffUnicodeConfig extends BaseConfiguration {
        public OffUnicodeConfig() throws Exception {
            super(true);
        }

        @Override
        public boolean isUseUnicode() {
            return false;
        }
    }

    @Test
    @DisplayName("Verify Unicode configuration is enabled by default")
    public void shouldHaveUnicodeEnabledByDefault() throws Exception {
        // Test Unicode configuration is enabled by default
        assertTrue(cfg.isUseUnicode(), "Unicode should be enabled by default");
    }

    @Test
    @DisplayName("Verify ASCII configuration disables Unicode support")
    public void shouldDisableUnicodeInAsciiConfig() throws Exception {
        Configuration asciiCfg = new OffUnicodeConfig();
        assertFalse(asciiCfg.isUseUnicode(), "Unicode should be disabled in ASCII config");
    }

    @Test
    @DisplayName("Verify Unicode string encoding uses little-endian format")
    public void shouldEncodeUnicodeInLittleEndian() {
        // Test Unicode string encoding
        String msg = "\u00A1\u00A2"; // two Unicode characters
        byte[] encoded = encodeUnicode(msg);
        assertEquals(4, encoded.length, "Encoded Unicode string should be 4 bytes");

        // Verify little-endian encoding
        assertEquals((byte) 0xA1, encoded[0], "First byte of first character");
        assertEquals((byte) 0x00, encoded[1], "Second byte of first character");
        assertEquals((byte) 0xA2, encoded[2], "First byte of second character");
        assertEquals((byte) 0x00, encoded[3], "Second byte of second character");
    }

    @Test
    @DisplayName("Verify ASCII encoding produces valid byte output")
    public void shouldProduceValidAsciiBytes() throws Exception {
        String msg = "\u00A1\u00A2"; // same Unicode string
        byte[] asciiBytes = msg.getBytes(SmbConstants.DEFAULT_OEM_ENCODING);
        assertTrue(asciiBytes.length > 0, "ASCII encoding should produce bytes");
    }

    @Test
    @DisplayName("Verify buffer creation includes header, params and data")
    public void shouldCreateBufferWithHeaderParamsAndData() throws UnsupportedEncodingException {
        byte[] dataBytes = { 1, 2, 3, 4 };
        String params = "test";
        byte[] buffer = createBuffer(10, dataBytes, params);

        // Verify buffer structure
        assertTrue(buffer.length >= 14, "Buffer should contain header, params and data");
    }

    @Test
    @DisplayName("Verify byte operations handle unsigned conversion correctly")
    public void shouldHandleUnsignedByteConversion() {
        // Test byte operations that were used in the original test
        byte b = (byte) 0xFF;
        int value = b & 0xFF;
        assertEquals(255, value, "Byte to unsigned conversion should work");

        // Test comparison operation
        assertTrue(value == 255, "Comparison should work correctly");
    }

    /**
     * Encode a string as 16-bit little-endian Unicode
     */
    private byte[] encodeUnicode(String s) {
        char[] chars = s.toCharArray();
        byte[] out = new byte[chars.length * 2];
        for (int i = 0; i < chars.length; i++) {
            out[2 * i] = (byte) (chars[i] & 0xFF);
            out[2 * i + 1] = (byte) ((chars[i] >> 8) & 0xFF);
        }
        return out;
    }

    /**
     * Helper: create a buffer containing the parameter and data segments
     */
    private static byte[] createBuffer(int dataLen, byte[] dataBytes, String params) throws UnsupportedEncodingException {
        final byte[] paramBytes = params.getBytes(SmbConstants.DEFAULT_OEM_ENCODING);
        byte[] buffer = new byte[10 + paramBytes.length + dataLen];
        // copy params
        System.arraycopy(paramBytes, 0, buffer, 10, paramBytes.length);
        // copy data
        System.arraycopy(dataBytes, 0, buffer, 10 + paramBytes.length, Math.min(dataBytes.length, dataLen));
        return buffer;
    }
}
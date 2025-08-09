package jcifs.internal.smb1.net;

import static org.junit.Assert.*;

import java.io.UnsupportedEncodingException;
import java.util.Arrays;
import java.util.List;

import org.junit.Test;

import jcifs.Configuration;
import jcifs.SmbConstants;
import jcifs.config.BaseConfiguration;

/**
 * Tests for {@link SmbComTransactionResponseReader}.
 */
public class TestSmbComTransactionResponseReader {

    /**
     * Default configuration used for Unicode support tests.
     */
    private final Configuration cfg;

    public TestSmbComTransactionResponseReader() throws Exception {
        // BaseConfiguration constructor may throw CIFSException, wrap in Runtime to make test compile.
        try {
            this.cfg = new BaseConfiguration(true);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Sub‑class of {@link BaseConfiguration} that forces {@code useUnicode()}
     * to return {@code false}.  This mimics an ASCII only client.
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
    public void testReadStringUnicode() throws Exception {
        // Build a buffer that simulates a response message.  totalParameterCount and
        // displacements are left at zero (the default for the message header).
        char a = (char) 0x00AB; // value that cannot be represented in OEM
        String msg = "\u00A1\u00A2"; // two Unicode characters that map to OEM bytes
        // encode using Big‑Endian Unicode (UTF‑16 BE) as the response reader expects
        byte[] data = encodeUnicode(msg);
        byte[] buffer = createBuffer(10, data, "foo\0bar\0");

        List<byte[]> parameters = Arrays.asList(new byte[10]);
        List<byte[]> dataList = Arrays.asList(new byte[10]);
        int count = SmbComTransactionResponseReader.readParametersWireFormat(parameters, buffer,
                0, buffer.length, 0, 1, 10, cfg);
        assertEquals("Parameter count reported as zero", 0, count);
        assertTrue("Data part not decoded correctly", checkDataCountAndFirstByte(dataList, 10, 42));
    }

    @Test
    public void testReadStringAscii() throws Exception {
        Configuration asciiCfg = new OffUnicodeConfig();
        String msg = "\u00A1\u00A2"; // same Unicode string
        byte[] asciiBytes = msg.getBytes(SmbConstants.DEFAULT_OEM_ENCODING);
        byte[] buffer = createBuffer(10, asciiBytes, "");
        List<byte[]> dataList = Arrays.asList(new byte[10]);
        int count = SmbComTransactionResponseReader.readDataWireFormat(0, buffer, 10, 10, dataList, asciiBytes.length, asciiCfg);
        assertEquals("Data part size incorrect for ASCII/OEM", asciiBytes.length, count);
        assertEquals("First decoded byte incorrect for ASCII/OEM", 42, dataList.get(0)[0] & 0xFF);
    }

    /**
     * Encode a string as 16‑bit little‑endian Unicode.
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
     * Helper: create a buffer containing the parameter and data segments.
     */
    private static byte[] createBuffer(int dataLen, byte[] dataBytes, String params) throws UnsupportedEncodingException {
        final byte[] paramBytes = params.getBytes(SmbConstants.DEFAULT_OEM_ENCODING);
        byte[] buffer = new byte[10 + paramBytes.length + dataLen];
        // copy params
        System.arraycopy(paramBytes, 0, buffer, 10, paramBytes.length);
        // copy data
        System.arraycopy(dataBytes, 0, buffer, 10 + paramBytes.length, dataLen);
        return buffer;
    }

    /**
     * Verify that after calling {@code readDataWireFormat} the supplied data list contains the
     * expected number of elements and that the first byte matches the anticipated marker.
     */
    private static boolean checkDataCountAndFirstByte(List<byte[]> data, int expectedDataCount, int expectedFirst) {
        // The data list should have expectedDataCount elements.
        if (data.size() != expectedDataCount) {
            return false;
        }
        if (data.get(0)[0] & 0xFF != expectedFirst) {
            return false;
        }
        return true;
    }
}


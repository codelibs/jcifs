package jcifs.smb1.smb1;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import java.util.Date;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;

/**
 * Unit tests for the {@link Info} implementations used by the SMB1
 * protocol handling code.
 */
class InfoTest {

    // A tiny mock to illustrate Mockito interaction patterns.
    @Mock
    private SmbComTransactionResponse transactionMock;

    @BeforeEach
    void setUp() {
        transactionMock = mock(SmbComTransactionResponse.class);
    }

    @Test
    void testSmbComQueryInformationResponseGetters() throws Exception {
        // The constructor is package‑private; use an anonymous subclass
        SmbComQueryInformationResponse resp = new SmbComQueryInformationResponse(1000L) {};
        java.lang.reflect.Field fileAttr = SmbComQueryInformationResponse.class.getDeclaredField("fileAttributes");
        fileAttr.setAccessible(true);
        fileAttr.setInt(resp, 0xABCD);
        java.lang.reflect.Field lastWrite = SmbComQueryInformationResponse.class.getDeclaredField("lastWriteTime");
        lastWrite.setAccessible(true);
        lastWrite.setLong(resp, 1630000000000L);
        java.lang.reflect.Field size = SmbComQueryInformationResponse.class.getDeclaredField("fileSize");
        size.setAccessible(true);
        size.setInt(resp, 2048);

        assertEquals(0xABCD, resp.getAttributes());
        assertEquals(1630000001000L, resp.getCreateTime());
        assertEquals(1630000001000L, resp.getLastWriteTime());
        assertEquals(2048, resp.getSize());
        assertTrue(resp.toString().contains(new Date(1630000001000L).toString()));
    }

    // Buffer helpers to build SMB basic file info wire format.
    private static void writeLong(byte[] buf, int offset, long val) {
        for (int i = 0; i < 8; i++) {
            buf[offset + i] = (byte) ((val >>> (56 - 8 * i))) & 0xFF;
        }
    }

    private static void writeShort(byte[] buf, int offset, int val) {
        buf[offset] = (byte) ((val >>> 8) & 0xFF);
        buf[offset + 1] = (byte) (val & 0xFF);
    }

    @Test
    void testTrans2QueryPathBasicInfoParsing() throws Exception {
        byte[] buffer = new byte[34];
        long create = 1600000000000L;
        long lastAccess = 1600000100000L;
        long lastWrite = 1600000200000L;
        long change = 1600000300000L;
        int attributes = 0x1234;
        writeLong(buffer, 0, create);
        writeLong(buffer, 8, lastAccess);
        writeLong(buffer, 16, lastWrite);
        writeLong(buffer, 24, change);
        writeShort(buffer, 32, attributes);

        Trans2QueryPathInformationResponse trans =
                new Trans2QueryPathInformationResponse(Trans2QueryPathInformationResponse.SMB_QUERY_FILE_BASIC_INFO) {};
        int bytesRead = trans.readDataWireFormat(buffer, 0, buffer.length);
        assertEquals(buffer.length, bytesRead);
        // Access private field 'info'
        java.lang.reflect.Field infoField = Trans2QueryPathInformationResponse.class.getDeclaredField("info");
        infoField.setAccessible(true);
        Info info = (Info) infoField.get(trans);
        assertNotNull(info);
        assertEquals(attributes, info.getAttributes());
        assertEquals(create, info.getCreateTime());
        assertEquals(lastWrite, info.getLastWriteTime());
        assertEquals(0L, info.getSize());
    }

    @Test
    void testTrans2QueryPathUnsupportedLevel() throws Exception {
        Trans2QueryPathInformationResponse trans = new Trans2QueryPathInformationResponse(9999) {};
        assertEquals(0, trans.readDataWireFormat(new byte[10], 0, 10));
        java.lang.reflect.Field infoField = Trans2QueryPathInformationResponse.class.getDeclaredField("info");
        infoField.setAccessible(true);
        assertNull(infoField.get(trans));
    }
}


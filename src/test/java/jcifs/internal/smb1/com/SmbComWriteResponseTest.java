package jcifs.internal.smb1.com;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import jcifs.Configuration;

/**
 * Tests for {@link SmbComWriteResponse}.
 */
public class SmbComWriteResponseTest {

    private SmbComWriteResponse resp;
    private Configuration cfgMock;

    @BeforeEach
    public void setUp() {
        // create a mock configuration that satisfies constructor requirements.
        cfgMock = mock(Configuration.class);
        resp = new SmbComWriteResponse(cfgMock);
    }

    @Test
    public void testInitialCountIsZero() {
        assertEquals(0, resp.getCount(), "Initial count should be zero");
    }

    @Test
    public void testReadParameterWordsUpdatesCount() {
        // create a buffer with count = 0x1234 (4660 decimal)
        // Using little-endian byte order as per SMBUtil.readInt2
        byte[] buf = new byte[12];
        buf[0] = 0x34; // Low byte
        buf[1] = 0x12; // High byte
        int written = resp.readParameterWordsWireFormat(buf, 0);

        assertEquals(8, written, "Expected readParameterWordsWireFormat to advance 8 bytes");
        assertEquals(0x1234L, resp.getCount(), "Count should reflect value from buffer");
    }

    @Test
    public void testToStringContainsCount() {
        // Little-endian: count = 512 (0x0200)
        byte[] buf = new byte[12];
        buf[0] = 0x00;
        buf[1] = 0x02; // count = 512 in little-endian
        resp.readParameterWordsWireFormat(buf, 0);
        String str = resp.toString();
        assertTrue(str.contains("count=512"), "toString should include numeric count");
    }

    @Test
    public void testReturnFromReadParameterWordsWireFormatIs8() {
        // ensure the method returns 8 as claimed
        byte[] buf = new byte[12];
        buf[0] = 0x00;
        buf[1] = 0x10; // count = 4096 in little-endian (0x1000)
        int returned = resp.readParameterWordsWireFormat(buf, 0);
        assertEquals(8, returned, "Method should return 8 bytes processed");
    }
}

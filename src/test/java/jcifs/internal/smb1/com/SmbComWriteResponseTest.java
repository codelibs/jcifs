package jcifs.internal.smb1.com;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import jcifs.Configuration;
import jcifs.internal.util.SMBUtil;

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
        byte[] buf = new byte[12];
        buf[0] = 0x12;
        buf[1] = 0x34;
        int written = resp.readParameterWordsWireFormat(buf, 0);

        assertEquals(8, written, "Expected readParameterWordsWireFormat to advance 8 bytes");
        assertEquals(0x1234L, resp.getCount(), "Count should reflect value from buffer");
    }

    @Test
    public void testToStringContainsCount() {
        byte[] buf = new byte[12];
        buf[0] = 0x00;
        buf[1] = 0x02; // count = 2
        resp.readParameterWordsWireFormat(buf, 0);
        String str = resp.toString();
        assertTrue(str.contains("count=2"), "toString should include numeric count");
    }

    @Test
    public void testReturnFromReadParameterWordsWireFormatIs8() {
        // ensure the method returns 8 as claimed
        byte[] buf = new byte[12];
        buf[0] = 0x00; buf[1] = 0x10; // count 16
        int returned = resp.readParameterWordsWireFormat(buf, 0);
        assertEquals(8, returned, "Method should return 8 bytes processed");
    }
}


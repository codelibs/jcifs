/*
 * © 2025 CodeLibs, Inc.
 */
package jcifs.tests.persistent;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

import jcifs.internal.smb2.persistent.DurableHandleReconnect;
import jcifs.internal.smb2.persistent.DurableHandleRequest;
import jcifs.internal.smb2.persistent.DurableHandleV2Request;
import jcifs.internal.smb2.persistent.HandleGuid;
import jcifs.internal.smb2.persistent.HandleType;
import jcifs.internal.smb2.persistent.Smb2HandleCapabilities;

/**
 * Test class for durable handle create context implementations
 */
public class DurableHandleContextTest {

    @Test
    public void testDurableHandleRequest() {
        DurableHandleRequest request = new DurableHandleRequest();

        assertEquals("DHnQ", new String(request.getName()));
        assertTrue(request.size() > 0);

        // Test encoding
        byte[] buffer = new byte[request.size()];
        int encoded = request.encode(buffer, 0);
        assertEquals(request.size(), encoded);
    }

    @Test
    public void testDurableHandleV2Request() {
        DurableHandleV2Request request = new DurableHandleV2Request(120000, false);

        assertEquals("DH2Q", new String(request.getName()));
        assertTrue(request.size() > 0);
        assertEquals(120000, request.getTimeoutMs());
        assertFalse(request.isPersistent());
        assertNotNull(request.getCreateGuid());

        // Test encoding
        byte[] buffer = new byte[request.size()];
        int encoded = request.encode(buffer, 0);
        assertEquals(request.size(), encoded);
    }

    @Test
    public void testDurableHandleV2RequestPersistent() {
        DurableHandleV2Request request = new DurableHandleV2Request(0, true);

        assertEquals(0, request.getTimeoutMs());
        assertTrue(request.isPersistent());
        assertEquals(Smb2HandleCapabilities.SMB2_DHANDLE_FLAG_PERSISTENT,
                request.getFlags() & Smb2HandleCapabilities.SMB2_DHANDLE_FLAG_PERSISTENT);
    }

    @Test
    public void testDurableHandleV2RequestWithGuid() {
        HandleGuid guid = new HandleGuid();
        DurableHandleV2Request request = new DurableHandleV2Request(60000, false, guid);

        assertEquals(guid, request.getCreateGuid());
        assertEquals(60000, request.getTimeoutMs());
        assertFalse(request.isPersistent());
    }

    @Test
    public void testDurableHandleReconnect() {
        byte[] fileId = new byte[16];
        for (int i = 0; i < 16; i++) {
            fileId[i] = (byte) (i + 1);
        }

        DurableHandleReconnect reconnect = new DurableHandleReconnect(fileId);

        assertEquals("DHnC", new String(reconnect.getName()));
        assertArrayEquals(fileId, reconnect.getFileId());
        assertTrue(reconnect.size() > 0);

        // Test encoding
        byte[] buffer = new byte[reconnect.size()];
        int encoded = reconnect.encode(buffer, 0);
        assertEquals(reconnect.size(), encoded);
    }

    @Test
    public void testDurableHandleReconnectInvalidFileId() {
        assertThrows(IllegalArgumentException.class, () -> {
            new DurableHandleReconnect(new byte[8]); // Wrong length
        });

        assertThrows(IllegalArgumentException.class, () -> {
            new DurableHandleReconnect(new byte[20]); // Wrong length
        });
    }

    @Test
    public void testHandleType() {
        assertEquals(0, HandleType.NONE.getValue());
        assertEquals(1, HandleType.DURABLE_V1.getValue());
        assertEquals(2, HandleType.DURABLE_V2.getValue());
        assertEquals(3, HandleType.PERSISTENT.getValue());

        assertEquals(HandleType.NONE, HandleType.fromValue(0));
        assertEquals(HandleType.DURABLE_V1, HandleType.fromValue(1));
        assertEquals(HandleType.DURABLE_V2, HandleType.fromValue(2));
        assertEquals(HandleType.PERSISTENT, HandleType.fromValue(3));

        assertThrows(IllegalArgumentException.class, () -> {
            HandleType.fromValue(99);
        });
    }

    @Test
    public void testHandleCapabilities() {
        assertEquals(0x00000002, Smb2HandleCapabilities.SMB2_DHANDLE_FLAG_PERSISTENT);
        assertEquals(120000, Smb2HandleCapabilities.DEFAULT_DURABLE_TIMEOUT);
        assertEquals(300000, Smb2HandleCapabilities.MAX_DURABLE_TIMEOUT);
        assertEquals(0, Smb2HandleCapabilities.PERSISTENT_TIMEOUT);
    }
}

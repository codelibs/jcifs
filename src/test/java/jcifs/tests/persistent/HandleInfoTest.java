/*
 * © 2025 CodeLibs, Inc.
 */
package jcifs.tests.persistent;

import jcifs.internal.smb2.persistent.HandleGuid;
import jcifs.internal.smb2.persistent.HandleInfo;
import jcifs.internal.smb2.persistent.HandleType;
import jcifs.internal.smb2.lease.Smb2LeaseKey;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeEach;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test class for HandleInfo functionality
 */
public class HandleInfoTest {

    private HandleGuid testGuid;
    private byte[] testFileId;
    private Smb2LeaseKey testLeaseKey;

    @BeforeEach
    public void setUp() {
        testGuid = new HandleGuid();
        testFileId = new byte[16];
        for (int i = 0; i < 16; i++) {
            testFileId[i] = (byte) (i + 1);
        }
        testLeaseKey = new Smb2LeaseKey();
    }

    @Test
    public void testHandleInfoCreation() {
        HandleInfo info = new HandleInfo("/test/file.txt", testGuid, testFileId, HandleType.DURABLE_V2, 120000, testLeaseKey);

        assertEquals("/test/file.txt", info.getPath());
        assertEquals(testGuid, info.getCreateGuid());
        assertArrayEquals(testFileId, info.getFileId());
        assertEquals(HandleType.DURABLE_V2, info.getType());
        assertEquals(120000, info.getTimeout());
        assertEquals(testLeaseKey, info.getLeaseKey());
        assertFalse(info.isReconnecting());
        assertNull(info.getFile());
    }

    @Test
    public void testHandleInfoExpiration() {
        // Test durable handle expiration
        HandleInfo durableInfo = new HandleInfo("/test/file.txt", testGuid, testFileId, HandleType.DURABLE_V2, 100, // 100ms timeout
                null);

        assertFalse(durableInfo.isExpired());

        // Wait for expiration
        try {
            Thread.sleep(150);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }

        assertTrue(durableInfo.isExpired());

        // Test persistent handle (never expires)
        HandleInfo persistentInfo = new HandleInfo("/test/file2.txt", new HandleGuid(), testFileId, HandleType.PERSISTENT, 0, null);

        try {
            Thread.sleep(50);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }

        assertFalse(persistentInfo.isExpired());
    }

    @Test
    public void testUpdateAccessTime() {
        HandleInfo info = new HandleInfo("/test/file.txt", testGuid, testFileId, HandleType.DURABLE_V2, 120000, null);

        long originalAccessTime = info.getLastAccessTime();

        try {
            Thread.sleep(10);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }

        info.updateAccessTime();

        assertTrue(info.getLastAccessTime() > originalAccessTime);
    }

    @Test
    public void testUpdateFileId() {
        HandleInfo info = new HandleInfo("/test/file.txt", testGuid, new byte[16], HandleType.DURABLE_V2, 120000, null);

        assertArrayEquals(new byte[16], info.getFileId());

        info.updateFileId(testFileId);
        assertArrayEquals(testFileId, info.getFileId());

        // Test invalid file ID length
        assertThrows(IllegalArgumentException.class, () -> {
            info.updateFileId(new byte[8]);
        });
    }

    @Test
    public void testReconnectingState() {
        HandleInfo info = new HandleInfo("/test/file.txt", testGuid, testFileId, HandleType.DURABLE_V2, 120000, null);

        assertFalse(info.isReconnecting());

        info.setReconnecting(true);
        assertTrue(info.isReconnecting());

        info.setReconnecting(false);
        assertFalse(info.isReconnecting());
    }

    @Test
    public void testFileReference() {
        HandleInfo info = new HandleInfo("/test/file.txt", testGuid, testFileId, HandleType.DURABLE_V2, 120000, null);

        assertNull(info.getFile());

        Object mockFile = new Object();
        info.setFile(mockFile);
        assertEquals(mockFile, info.getFile());
    }

    @Test
    public void testToString() {
        HandleInfo info = new HandleInfo("/test/file.txt", testGuid, testFileId, HandleType.PERSISTENT, 0, testLeaseKey);

        String str = info.toString();
        assertTrue(str.contains("/test/file.txt"));
        assertTrue(str.contains("PERSISTENT"));
        assertTrue(str.contains(testGuid.toString()));
    }
}

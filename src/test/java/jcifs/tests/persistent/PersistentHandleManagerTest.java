/*
 * © 2025 CodeLibs, Inc.
 */
package jcifs.tests.persistent;

import jcifs.CIFSContext;
import jcifs.internal.smb2.persistent.HandleGuid;
import jcifs.internal.smb2.persistent.HandleInfo;
import jcifs.internal.smb2.persistent.HandleType;
import jcifs.internal.smb2.persistent.PersistentHandleManager;
import jcifs.internal.smb2.lease.Smb2LeaseKey;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.AfterEach;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Properties;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * Test class for PersistentHandleManager functionality
 */
public class PersistentHandleManagerTest {

    @Mock
    private CIFSContext mockContext;

    @Mock
    private jcifs.Configuration mockConfig;

    private PersistentHandleManager manager;
    private Path tempDir;

    @BeforeEach
    public void setUp() throws IOException {
        MockitoAnnotations.openMocks(this);

        // Create temporary directory for test state
        tempDir = Files.createTempDirectory("jcifs-test-handles");

        // Set system property for handle state directory
        System.setProperty("jcifs.smb.client.handleStateDirectory", tempDir.toString());

        when(mockContext.getConfig()).thenReturn(mockConfig);

        manager = new PersistentHandleManager(mockContext);
    }

    @AfterEach
    public void tearDown() throws IOException {
        if (manager != null) {
            manager.shutdown();
        }

        // Clean up system property
        System.clearProperty("jcifs.smb.client.handleStateDirectory");

        // Clean up temp directory
        if (tempDir != null && Files.exists(tempDir)) {
            Files.walk(tempDir)
                    .sorted((a, b) -> b.compareTo(a)) // Delete files before directories
                    .forEach(path -> {
                        try {
                            Files.delete(path);
                        } catch (IOException e) {
                            // Ignore cleanup errors
                        }
                    });
        }
    }

    @Test
    public void testRequestDurableHandle() {
        HandleGuid guid = manager.requestDurableHandle("/test/file.txt", HandleType.DURABLE_V2, 120000, null);

        assertNotNull(guid);
        assertEquals(1, manager.getHandleCount());

        HandleInfo info = manager.getHandleByGuid(guid);
        assertNotNull(info);
        assertEquals("/test/file.txt", info.getPath());
        assertEquals(HandleType.DURABLE_V2, info.getType());
        assertEquals(120000, info.getTimeout());
    }

    @Test
    public void testUpdateHandleFileId() {
        HandleGuid guid = manager.requestDurableHandle("/test/file.txt", HandleType.DURABLE_V2, 120000, null);

        byte[] fileId = new byte[16];
        for (int i = 0; i < 16; i++) {
            fileId[i] = (byte) (i + 1);
        }

        manager.updateHandleFileId(guid, fileId);

        HandleInfo info = manager.getHandleByGuid(guid);
        assertArrayEquals(fileId, info.getFileId());
    }

    @Test
    public void testGetHandleForReconnect() {
        HandleGuid guid = manager.requestDurableHandle("/test/file.txt", HandleType.DURABLE_V2, 120000, null);

        HandleInfo info = manager.getHandleForReconnect("/test/file.txt");
        assertNotNull(info);
        assertEquals(guid, info.getCreateGuid());
        assertTrue(info.isReconnecting());
    }

    @Test
    public void testGetHandleForReconnectExpired() {
        manager.requestDurableHandle("/test/file.txt", HandleType.DURABLE_V2, 100, // 100ms timeout
                null);

        // Wait for expiration
        try {
            Thread.sleep(150);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }

        HandleInfo info = manager.getHandleForReconnect("/test/file.txt");
        assertNull(info);
    }

    @Test
    public void testCompleteReconnectSuccess() {
        HandleGuid guid = manager.requestDurableHandle("/test/file.txt", HandleType.DURABLE_V2, 120000, null);

        HandleInfo info = manager.getHandleForReconnect("/test/file.txt");
        assertTrue(info.isReconnecting());

        manager.completeReconnect("/test/file.txt", true);

        info = manager.getHandleByGuid(guid);
        assertNotNull(info);
        assertFalse(info.isReconnecting());
    }

    @Test
    public void testCompleteReconnectFailure() {
        HandleGuid guid = manager.requestDurableHandle("/test/file.txt", HandleType.DURABLE_V2, 120000, null);

        manager.getHandleForReconnect("/test/file.txt");
        manager.completeReconnect("/test/file.txt", false);

        HandleInfo info = manager.getHandleByGuid(guid);
        assertNull(info);
        assertEquals(0, manager.getHandleCount());
    }

    @Test
    public void testReleaseHandle() {
        HandleGuid guid = manager.requestDurableHandle("/test/file.txt", HandleType.DURABLE_V2, 120000, null);

        assertEquals(1, manager.getHandleCount());

        manager.releaseHandle("/test/file.txt");

        assertEquals(0, manager.getHandleCount());
        assertNull(manager.getHandleByGuid(guid));
    }

    @Test
    public void testGetHandleByPath() {
        HandleGuid guid = manager.requestDurableHandle("/test/file.txt", HandleType.PERSISTENT, 0, null);

        HandleInfo info = manager.getHandleByPath("/test/file.txt");
        assertNotNull(info);
        assertEquals(guid, info.getCreateGuid());

        assertNull(manager.getHandleByPath("/nonexistent/file.txt"));
    }

    @Test
    public void testMultipleHandles() {
        HandleGuid guid1 = manager.requestDurableHandle("/test/file1.txt", HandleType.DURABLE_V2, 120000, null);

        HandleGuid guid2 = manager.requestDurableHandle("/test/file2.txt", HandleType.PERSISTENT, 0, new Smb2LeaseKey());

        assertEquals(2, manager.getHandleCount());

        HandleInfo info1 = manager.getHandleByGuid(guid1);
        HandleInfo info2 = manager.getHandleByGuid(guid2);

        assertNotNull(info1);
        assertNotNull(info2);
        assertNotEquals(info1.getPath(), info2.getPath());
        assertNotEquals(info1.getType(), info2.getType());
    }
}

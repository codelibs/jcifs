/*
 * © 2025 CodeLibs, Inc.
 */
package jcifs.tests.persistent;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import jcifs.internal.smb2.persistent.HandleGuid;
import jcifs.internal.smb2.persistent.HandleInfo;
import jcifs.internal.smb2.persistent.HandleReconnector;
import jcifs.internal.smb2.persistent.HandleType;
import jcifs.internal.smb2.persistent.PersistentHandleManager;

/**
 * Test class for HandleReconnector functionality
 */
public class HandleReconnectorTest {

    @Mock
    private PersistentHandleManager mockManager;

    private HandleReconnector reconnector;
    private HandleInfo testHandle;

    @BeforeEach
    public void setUp() {
        MockitoAnnotations.openMocks(this);
        reconnector = new HandleReconnector(mockManager, 2, 50); // 2 retries, 50ms delay

        HandleGuid guid = new HandleGuid();
        byte[] fileId = new byte[16];
        for (int i = 0; i < 16; i++) {
            fileId[i] = (byte) (i + 1);
        }

        testHandle = new HandleInfo("/test/file.txt", guid, fileId, HandleType.DURABLE_V2, 120000, null);
    }

    @Test
    public void testReconnectHandleSuccess() throws Exception {
        when(mockManager.getHandleForReconnect("/test/file.txt")).thenReturn(testHandle);

        // Create a test reconnector that succeeds
        TestHandleReconnector testReconnector = new TestHandleReconnector(mockManager, true);

        CompletableFuture<HandleInfo> future = testReconnector.reconnectHandle("/test/file.txt", new IOException("Network error"));

        HandleInfo result = future.get();
        assertNotNull(result);
        assertEquals(testHandle, result);

        verify(mockManager).completeReconnect("/test/file.txt", true);
    }

    @Test
    public void testReconnectHandleFailure() throws Exception {
        when(mockManager.getHandleForReconnect("/test/file.txt")).thenReturn(testHandle);

        // Create a test reconnector that fails
        TestHandleReconnector testReconnector = new TestHandleReconnector(mockManager, false);

        CompletableFuture<HandleInfo> future = testReconnector.reconnectHandle("/test/file.txt", new IOException("Network error"));

        assertThrows(ExecutionException.class, () -> {
            future.get();
        });

        verify(mockManager).completeReconnect("/test/file.txt", false);
    }

    @Test
    public void testReconnectHandleNoHandle() throws Exception {
        when(mockManager.getHandleForReconnect("/test/file.txt")).thenReturn(null);

        CompletableFuture<HandleInfo> future = reconnector.reconnectHandle("/test/file.txt", new IOException("Network error"));

        assertThrows(ExecutionException.class, () -> {
            future.get();
        });

        verify(mockManager, never()).completeReconnect(anyString(), anyBoolean());
    }

    @Test
    public void testReconnectExpiredHandle() throws Exception {
        // Create an expired handle
        HandleInfo expiredHandle = new HandleInfo("/test/file.txt", new HandleGuid(), new byte[16], HandleType.DURABLE_V2, 100, // 100ms timeout
                null);

        // Wait for expiration
        Thread.sleep(150);

        CompletableFuture<HandleInfo> future = reconnector.reconnectHandle(expiredHandle, new IOException("Network error"));

        assertThrows(ExecutionException.class, () -> {
            future.get();
        });
    }

    @Test
    public void testGetMaxRetries() {
        assertEquals(2, reconnector.getMaxRetries());
    }

    @Test
    public void testGetRetryDelay() {
        assertEquals(50, reconnector.getRetryDelay());
    }

    @Test
    public void testDefaultConstructor() {
        HandleReconnector defaultReconnector = new HandleReconnector(mockManager);
        assertEquals(3, defaultReconnector.getMaxRetries());
        assertEquals(1000, defaultReconnector.getRetryDelay());
    }

    @Test
    public void testCreateReconnectionRequestThrows() {
        // Create a test reconnector that exposes the protected method
        TestHandleReconnector testReconnector = new TestHandleReconnector(mockManager, true);
        assertThrows(UnsupportedOperationException.class, () -> {
            testReconnector.testCreateReconnectionRequest(testHandle);
        });
    }

    /**
     * Test implementation of HandleReconnector that allows controlling success/failure
     */
    private static class TestHandleReconnector extends HandleReconnector {
        private final boolean shouldSucceed;

        public TestHandleReconnector(PersistentHandleManager manager, boolean shouldSucceed) {
            super(manager, 2, 50);
            this.shouldSucceed = shouldSucceed;
        }

        @Override
        protected boolean performReconnection(HandleInfo info) throws Exception {
            if (shouldSucceed) {
                return true;
            } else {
                throw new IOException("Simulated reconnection failure");
            }
        }

        public void testCreateReconnectionRequest(HandleInfo handle) {
            createReconnectionRequest(handle);
        }
    }
}

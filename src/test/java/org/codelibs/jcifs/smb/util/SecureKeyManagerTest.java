package org.codelibs.jcifs.smb.util;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import javax.crypto.SecretKey;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Test class for SecureKeyManager
 */
public class SecureKeyManagerTest {

    private SecureKeyManager keyManager;
    private byte[] testKey;

    @BeforeEach
    public void setUp() {
        keyManager = new SecureKeyManager();
        testKey = new byte[16];
        new SecureRandom().nextBytes(testKey);
    }

    @AfterEach
    public void tearDown() {
        if (keyManager != null) {
            keyManager.close();
        }
    }

    @Test
    public void testStoreAndRetrieveKey() {
        String sessionId = "test-session-1";
        keyManager.storeSessionKey(sessionId, testKey, "AES");

        SecretKey retrieved = keyManager.getSessionKey(sessionId);
        assertNotNull(retrieved, "Should retrieve stored key");
        assertArrayEquals(testKey, retrieved.getEncoded(), "Retrieved key should match");
    }

    @Test
    public void testGetRawKey() {
        String sessionId = "test-session-2";
        keyManager.storeSessionKey(sessionId, testKey, "AES");

        byte[] rawKey = keyManager.getRawKey(sessionId);
        assertNotNull(rawKey, "Should retrieve raw key");
        assertArrayEquals(testKey, rawKey, "Raw key should match");

        // Verify we get a copy, not the original
        rawKey[0] = (byte) ~rawKey[0];
        byte[] rawKey2 = keyManager.getRawKey(sessionId);
        assertArrayEquals(testKey, rawKey2, "Should still match original");
    }

    @Test
    public void testRemoveSessionKey() {
        String sessionId = "test-session-3";
        keyManager.storeSessionKey(sessionId, testKey, "AES");

        assertTrue(keyManager.hasSessionKey(sessionId), "Key should exist");

        keyManager.removeSessionKey(sessionId);

        assertFalse(keyManager.hasSessionKey(sessionId), "Key should be removed");
        assertNull(keyManager.getSessionKey(sessionId), "Should not retrieve removed key");
    }

    @Test
    public void testKeyIsolation() {
        String sessionId1 = "session-1";
        String sessionId2 = "session-2";

        byte[] key1 = new byte[16];
        byte[] key2 = new byte[16];
        new SecureRandom().nextBytes(key1);
        new SecureRandom().nextBytes(key2);

        keyManager.storeSessionKey(sessionId1, key1, "AES");
        keyManager.storeSessionKey(sessionId2, key2, "AES");

        byte[] retrieved1 = keyManager.getRawKey(sessionId1);
        byte[] retrieved2 = keyManager.getRawKey(sessionId2);

        assertArrayEquals(key1, retrieved1, "Key 1 should match");
        assertArrayEquals(key2, retrieved2, "Key 2 should match");
        assertFalse(Arrays.equals(retrieved1, retrieved2), "Keys should be different");
    }

    @Test
    public void testClearAllKeys() {
        // Store multiple keys
        for (int i = 0; i < 5; i++) {
            byte[] key = new byte[16];
            new SecureRandom().nextBytes(key);
            keyManager.storeSessionKey("session-" + i, key, "AES");
        }

        assertEquals(5, keyManager.getKeyCount(), "Should have 5 keys");

        keyManager.clearAllKeys();

        assertEquals(0, keyManager.getKeyCount(), "Should have no keys after clear");

        // Verify all keys are removed
        for (int i = 0; i < 5; i++) {
            assertFalse(keyManager.hasSessionKey("session-" + i), "Key should be removed");
        }
    }

    @Test
    public void testGenerateRandomKey() {
        byte[] key1 = keyManager.generateRandomKey(32);
        byte[] key2 = keyManager.generateRandomKey(32);

        assertNotNull(key1, "Should generate key 1");
        assertNotNull(key2, "Should generate key 2");
        assertEquals(32, key1.length, "Key 1 should have correct length");
        assertEquals(32, key2.length, "Key 2 should have correct length");
        assertFalse(Arrays.equals(key1, key2), "Random keys should be different");
    }

    @Test
    public void testDeriveKey() throws Exception {
        byte[] baseKey = new byte[16];
        new SecureRandom().nextBytes(baseKey);

        byte[] derived1 = keyManager.deriveKey(baseKey, "label1", null, 32);
        byte[] derived2 = keyManager.deriveKey(baseKey, "label2", null, 32);
        byte[] derived3 = keyManager.deriveKey(baseKey, "label1", new byte[] { 1, 2, 3 }, 32);

        assertEquals(32, derived1.length, "Derived key should have correct length");
        assertEquals(32, derived2.length, "Derived key should have correct length");
        assertEquals(32, derived3.length, "Derived key should have correct length");

        assertFalse(Arrays.equals(derived1, derived2), "Different labels should produce different keys");
        assertFalse(Arrays.equals(derived1, derived3), "Different contexts should produce different keys");
    }

    @Test
    public void testStoreNullKey() {
        assertThrows(IllegalArgumentException.class, () -> keyManager.storeSessionKey("session", null, "AES"));
    }

    @Test
    public void testStoreNullSessionId() {
        assertThrows(IllegalArgumentException.class, () -> keyManager.storeSessionKey(null, testKey, "AES"));
    }

    @Test
    public void testUseAfterClose() {
        keyManager.close();
        assertThrows(IllegalStateException.class, () -> keyManager.storeSessionKey("session", testKey, "AES"));
    }

    @Test
    public void testMultipleCloseCalls() {
        keyManager.storeSessionKey("session", testKey, "AES");

        keyManager.close();
        keyManager.close(); // Should not throw

        assertEquals(0, keyManager.getKeyCount(), "Should have no keys after close");
    }

    @Test
    public void testAutoCloseable() throws Exception {
        try (SecureKeyManager manager = new SecureKeyManager()) {
            manager.storeSessionKey("auto-session", testKey, "AES");
            assertTrue(manager.hasSessionKey("auto-session"), "Key should exist");
        }
        // Manager should be closed automatically
    }

    @Test
    public void testSecureWipeUtility() {
        byte[] data = new byte[16];
        new SecureRandom().nextBytes(data);

        // Verify data is not all zeros initially
        boolean hasNonZero = false;
        for (byte b : data) {
            if (b != 0) {
                hasNonZero = true;
                break;
            }
        }
        assertTrue(hasNonZero, "Data should have non-zero bytes");

        SecureKeyManager.secureWipe(data);

        // Verify data is wiped
        for (byte b : data) {
            assertEquals(0, b, "All bytes should be zero after wipe");
        }
    }

    @Test
    public void testSecureWipeNull() {
        // Should not throw
        SecureKeyManager.secureWipe(null);
    }

    @Test
    public void testKeyRotation() throws GeneralSecurityException {
        String sessionId = "rotation-test";
        keyManager.storeSessionKey(sessionId, testKey, "AES");

        // Initial version should be 0
        assertEquals(0, keyManager.getKeyVersion(sessionId), "Initial version should be 0");

        // Rotate key
        int newVersion = keyManager.rotateSessionKey(sessionId);
        assertEquals(1, newVersion, "New version should be 1");
        assertEquals(1, keyManager.getKeyVersion(sessionId), "Key version should be updated");

        // Verify old key is archived
        assertTrue(keyManager.hasSessionKey(sessionId + ".v0"), "Archived key should exist");

        // New key should be different
        byte[] newKey = keyManager.getRawKey(sessionId);
        assertNotNull(newKey, "New key should exist");
        assertFalse(Arrays.equals(testKey, newKey), "New key should be different from old key");
    }

    @Test
    public void testMultipleKeyRotations() throws GeneralSecurityException {
        String sessionId = "multi-rotation";
        keyManager.storeSessionKey(sessionId, testKey, "AES");

        // Perform multiple rotations
        for (int i = 1; i <= 5; i++) {
            int version = keyManager.rotateSessionKey(sessionId);
            assertEquals(i, version, "Version should be " + i);
        }

        // Verify all archived versions exist
        for (int i = 0; i < 5; i++) {
            assertTrue(keyManager.hasSessionKey(sessionId + ".v" + i), "Archived version " + i + " should exist");
        }
    }

    @Test
    public void testRotateNonExistentKey() {
        assertThrows(IllegalArgumentException.class, () -> keyManager.rotateSessionKey("non-existent"));
    }

    @Test
    public void testForceRotateAllKeys() throws GeneralSecurityException {
        // Store multiple keys
        for (int i = 0; i < 3; i++) {
            keyManager.storeSessionKey("session-" + i, testKey, "AES");
        }

        // Force rotate all
        int rotated = keyManager.forceRotateAllKeys();
        assertEquals(3, rotated, "Should rotate 3 keys");

        // Verify all keys were rotated
        for (int i = 0; i < 3; i++) {
            assertEquals(1, keyManager.getKeyVersion("session-" + i), "Key version should be 1");
        }
    }

    @Test
    public void testCleanupArchivedKeys() throws GeneralSecurityException {
        String sessionId = "cleanup-test";
        keyManager.storeSessionKey(sessionId, testKey, "AES");

        // Create multiple versions
        for (int i = 0; i < 5; i++) {
            keyManager.rotateSessionKey(sessionId);
        }

        // Clean up, keeping only 2 versions
        keyManager.cleanupArchivedKeys(2);

        // Verify only recent versions are kept
        assertTrue(keyManager.hasSessionKey(sessionId + ".v4"), "Version 4 should exist");
        assertTrue(keyManager.hasSessionKey(sessionId + ".v3"), "Version 3 should exist");
        assertFalse(keyManager.hasSessionKey(sessionId + ".v2"), "Version 2 should be removed");
        assertFalse(keyManager.hasSessionKey(sessionId + ".v1"), "Version 1 should be removed");
        assertFalse(keyManager.hasSessionKey(sessionId + ".v0"), "Version 0 should be removed");
    }

    @Test
    public void testKeyAge() throws InterruptedException {
        String sessionId = "age-test";
        keyManager.storeSessionKey(sessionId, testKey, "AES");

        long initialAge = keyManager.getKeyAge(sessionId);
        assertTrue(initialAge >= 0 && initialAge < 100, "Initial age should be small");

        Thread.sleep(200);

        long laterAge = keyManager.getKeyAge(sessionId);
        assertTrue(laterAge >= 200, "Age should increase after delay");
    }

    @Test
    public void testKeyAgeNonExistent() {
        assertEquals(-1, keyManager.getKeyAge("non-existent"), "Non-existent key should return -1 for age");
    }

    @Test
    public void testConfigureKeyRotation() {
        // Test that configuration doesn't throw
        keyManager.configureKeyRotation(60000);

        // Test disabling rotation
        keyManager.configureKeyRotation(0);

        // Test reconfiguring
        keyManager.configureKeyRotation(30000);
    }

    @Test
    public void testConcurrentKeyOperations() throws InterruptedException {
        int threadCount = 10;
        int operationsPerThread = 50;
        CountDownLatch latch = new CountDownLatch(threadCount);
        AtomicInteger successCount = new AtomicInteger(0);
        ExecutorService executor = Executors.newFixedThreadPool(threadCount);

        for (int t = 0; t < threadCount; t++) {
            final int threadId = t;
            executor.submit(() -> {
                try {
                    for (int i = 0; i < operationsPerThread; i++) {
                        String sid = "thread-" + threadId + "-key-" + i;
                        byte[] key = keyManager.generateRandomKey(16);

                        // Store key
                        keyManager.storeSessionKey(sid, key, "AES");

                        // Retrieve and verify
                        byte[] retrieved = keyManager.getRawKey(sid);
                        if (Arrays.equals(key, retrieved)) {
                            successCount.incrementAndGet();
                        }

                        // Occasionally rotate
                        if (i % 10 == 0) {
                            try {
                                keyManager.rotateSessionKey(sid);
                            } catch (GeneralSecurityException e) {
                                // Ignore in concurrent test
                            }
                        }
                    }
                } finally {
                    latch.countDown();
                }
            });
        }

        assertTrue(latch.await(10, TimeUnit.SECONDS), "Concurrent ops should complete");
        executor.shutdown();

        assertEquals(threadCount * operationsPerThread, successCount.get(), "All operations should succeed");
    }

    @Test
    public void testRemoveSessionKeyWithArchives() throws GeneralSecurityException {
        String sessionId = "remove-with-archives";
        keyManager.storeSessionKey(sessionId, testKey, "AES");

        // Create archived versions
        for (int i = 0; i < 3; i++) {
            keyManager.rotateSessionKey(sessionId);
        }

        // Verify archives exist
        assertTrue(keyManager.hasSessionKey(sessionId + ".v0"), "Version 0 should exist");
        assertTrue(keyManager.hasSessionKey(sessionId + ".v1"), "Version 1 should exist");
        assertTrue(keyManager.hasSessionKey(sessionId + ".v2"), "Version 2 should exist");

        // Remove main key
        keyManager.removeSessionKey(sessionId);

        // Verify main key is removed (archives stay)
        assertFalse(keyManager.hasSessionKey(sessionId), "Main key should be removed");
        // Note: Archives are not automatically removed when removing main key
    }
}
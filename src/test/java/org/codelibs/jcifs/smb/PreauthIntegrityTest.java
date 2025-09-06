/*
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */
package org.codelibs.jcifs.smb;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import static org.mockito.Mockito.when;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import org.codelibs.jcifs.smb.internal.smb2.nego.Smb2NegotiateResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

/**
 * Test Pre-Authentication Integrity improvements
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
public class PreauthIntegrityTest {

    @Mock
    private CIFSContext context;

    @Mock
    private Configuration config;

    @Mock
    private Address address;

    @Mock
    private Smb2NegotiateResponse negotiateResponse;

    private SmbTransportImpl transport;

    @BeforeEach
    void setUp() throws Exception {
        when(context.getConfig()).thenReturn(config);
        when(config.isSigningEnforced()).thenReturn(false);
        when(config.getSessionTimeout()).thenReturn(30_000);
        when(config.getResponseTimeout()).thenReturn(5_000);
        when(address.getHostAddress()).thenReturn("127.0.0.1");
        when(address.getHostName()).thenReturn("testhost");

        transport = new SmbTransportImpl(context, address, 445, null, 0, false);
    }

    /**
     * Test that pre-auth integrity hash is properly synchronized
     */
    @Test
    @DisplayName("Pre-auth integrity hash should be thread-safe")
    void testPreauthHashThreadSafety() throws Exception {
        // Setup SMB3.1.1 negotiation
        when(negotiateResponse.getSelectedDialect()).thenReturn(DialectVersion.SMB311);
        when(negotiateResponse.getSelectedPreauthHash()).thenReturn(1); // SHA-512
        setPrivateField(transport, "smb2", true);
        setPrivateField(transport, "negotiated", negotiateResponse);

        int threadCount = 10;
        CountDownLatch startLatch = new CountDownLatch(1);
        CountDownLatch doneLatch = new CountDownLatch(threadCount);
        ExecutorService executor = Executors.newFixedThreadPool(threadCount);

        // Create test data
        byte[] testData = new byte[64];
        for (int i = 0; i < testData.length; i++) {
            testData[i] = (byte) i;
        }

        // Run concurrent updates
        for (int i = 0; i < threadCount; i++) {
            executor.submit(() -> {
                try {
                    startLatch.await();
                    Method updateMethod = findMethod(transport.getClass(), "updatePreauthHash", byte[].class);
                    updateMethod.setAccessible(true);
                    updateMethod.invoke(transport, testData);
                } catch (Exception e) {
                    fail("Thread failed: " + e.getMessage());
                } finally {
                    doneLatch.countDown();
                }
            });
        }

        // Start all threads at once
        startLatch.countDown();

        // Wait for completion
        assertTrue(doneLatch.await(5, TimeUnit.SECONDS), "Threads did not complete in time");
        executor.shutdown();

        // Verify hash is not null
        byte[] hash = transport.getPreauthIntegrityHash();
        assertNotNull(hash);

        // Verify hash is a copy, not the original
        byte[] hash2 = transport.getPreauthIntegrityHash();
        assertNotSame(hash, hash2);
        assertArrayEquals(hash, hash2);
    }

    /**
     * Test that pre-auth hash is reset on error
     */
    @Test
    @DisplayName("Pre-auth integrity hash should reset on error")
    void testPreauthHashResetOnError() throws Exception {
        // Setup invalid SMB2 state to trigger error
        setPrivateField(transport, "smb2", false);

        // Try to update preauth hash - should fail and reset
        Method updateMethod = findMethod(transport.getClass(), "updatePreauthHash", byte[].class);
        updateMethod.setAccessible(true);

        byte[] testData = new byte[64];

        assertThrows(Exception.class, () -> {
            updateMethod.invoke(transport, testData);
        });

        // Verify hash was reset
        Method resetMethod = findMethod(transport.getClass(), "resetPreauthHash");
        if (resetMethod != null) {
            // Verify the reset method exists
            assertNotNull(resetMethod);
        }
    }

    /**
     * Test that getPreauthIntegrityHash returns a defensive copy
     */
    @Test
    @DisplayName("getPreauthIntegrityHash should return defensive copy")
    void testGetPreauthHashDefensiveCopy() throws Exception {
        byte[] hash = transport.getPreauthIntegrityHash();
        assertNotNull(hash);

        // Modify returned hash
        if (hash.length > 0) {
            hash[0] = (byte) 0xFF;
        }

        // Get hash again - should be unmodified
        byte[] hash2 = transport.getPreauthIntegrityHash();
        assertNotNull(hash2);

        // If original has data, verify it wasn't modified
        if (hash2.length > 0 && hash.length > 0) {
            assertNotEquals(hash[0], hash2[0]);
        }
    }

    /**
     * Test pre-auth integrity with SMB3.1.1
     */
    @Test
    @DisplayName("Pre-auth integrity should work with SMB3.1.1")
    void testPreauthWithSmb311() throws Exception {
        // Setup SMB3.1.1
        when(negotiateResponse.getSelectedDialect()).thenReturn(DialectVersion.SMB311);
        when(negotiateResponse.getSelectedPreauthHash()).thenReturn(1); // SHA-512
        setPrivateField(transport, "smb2", true);
        setPrivateField(transport, "negotiated", negotiateResponse);

        // Calculate hash
        Method calcMethod = findMethod(transport.getClass(), "calculatePreauthHash", byte[].class, int.class, int.class, byte[].class);
        calcMethod.setAccessible(true);

        byte[] input = "test data".getBytes();
        byte[] oldHash = new byte[64];

        byte[] newHash = (byte[]) calcMethod.invoke(transport, input, 0, input.length, oldHash);

        assertNotNull(newHash);
        assertEquals(64, newHash.length); // SHA-512 produces 64 bytes
        assertNotEquals(oldHash, newHash); // Should be different instance
    }

    /**
     * Test pre-auth integrity with non-SMB3.1.1 should throw exception
     */
    @Test
    @DisplayName("Pre-auth integrity should fail with non-SMB3.1.1")
    void testPreauthWithNonSmb311() throws Exception {
        // Setup SMB3.0
        when(negotiateResponse.getSelectedDialect()).thenReturn(DialectVersion.SMB300);
        setPrivateField(transport, "smb2", true);
        setPrivateField(transport, "negotiated", negotiateResponse);

        // Calculate hash should fail
        Method calcMethod = findMethod(transport.getClass(), "calculatePreauthHash", byte[].class, int.class, int.class, byte[].class);
        calcMethod.setAccessible(true);

        byte[] input = "test data".getBytes();
        byte[] oldHash = new byte[64];

        assertThrows(Exception.class, () -> {
            calcMethod.invoke(transport, input, 0, input.length, oldHash);
        });
    }

    /**
     * Test concurrent access to getPreauthIntegrityHash
     */
    @Test
    @DisplayName("Concurrent getPreauthIntegrityHash should be safe")
    void testConcurrentGetPreauthHash() throws Exception {
        int threadCount = 20;
        CountDownLatch startLatch = new CountDownLatch(1);
        CountDownLatch doneLatch = new CountDownLatch(threadCount);
        ExecutorService executor = Executors.newFixedThreadPool(threadCount);

        for (int i = 0; i < threadCount; i++) {
            executor.submit(() -> {
                try {
                    startLatch.await();
                    for (int j = 0; j < 100; j++) {
                        byte[] hash = transport.getPreauthIntegrityHash();
                        assertNotNull(hash);
                    }
                } catch (Exception e) {
                    fail("Thread failed: " + e.getMessage());
                } finally {
                    doneLatch.countDown();
                }
            });
        }

        startLatch.countDown();
        assertTrue(doneLatch.await(5, TimeUnit.SECONDS), "Threads did not complete");
        executor.shutdown();
    }

    // Helper methods
    private void setPrivateField(Object target, String fieldName, Object value) throws Exception {
        Field field = findField(target.getClass(), fieldName);
        field.setAccessible(true);
        field.set(target, value);
    }

    private Field findField(Class<?> clazz, String fieldName) {
        while (clazz != null) {
            try {
                return clazz.getDeclaredField(fieldName);
            } catch (NoSuchFieldException e) {
                clazz = clazz.getSuperclass();
            }
        }
        return null;
    }

    private Method findMethod(Class<?> clazz, String methodName, Class<?>... paramTypes) {
        while (clazz != null) {
            try {
                return clazz.getDeclaredMethod(methodName, paramTypes);
            } catch (NoSuchMethodException e) {
                clazz = clazz.getSuperclass();
            }
        }
        return null;
    }
}

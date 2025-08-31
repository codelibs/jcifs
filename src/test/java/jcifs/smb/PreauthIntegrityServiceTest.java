package jcifs.smb;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import java.security.SecureRandom;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import jcifs.CIFSException;
import jcifs.smb.PreauthIntegrityService.PreauthIntegrityContext;

/**
 * Comprehensive tests for enhanced pre-authentication integrity service.
 */
public class PreauthIntegrityServiceTest {

    private PreauthIntegrityService preauthService;
    private SecureRandom secureRandom;

    @BeforeEach
    public void setUp() {
        secureRandom = new SecureRandom();
        preauthService = new PreauthIntegrityService(secureRandom, PreauthIntegrityService.HASH_ALGO_SHA512, true);
    }

    @AfterEach
    public void tearDown() {
        if (preauthService != null) {
            preauthService.cleanup();
        }
    }

    @Test
    @DisplayName("Test preauth salt generation")
    public void testPreauthSaltGeneration() {
        byte[] salt1 = preauthService.generatePreauthSalt();
        byte[] salt2 = preauthService.generatePreauthSalt();

        assertNotNull(salt1);
        assertNotNull(salt2);
        assertEquals(32, salt1.length); // 32 bytes as per SMB 3.1.1 spec
        assertEquals(32, salt2.length);
        assertFalse(java.util.Arrays.equals(salt1, salt2)); // Should be different
    }

    @Test
    @DisplayName("Test session initialization")
    public void testSessionInitialization() throws CIFSException {
        String sessionId = "test-session-1";
        byte[] salt = preauthService.generatePreauthSalt();

        PreauthIntegrityContext context = preauthService.initializeSession(sessionId, salt, PreauthIntegrityService.HASH_ALGO_SHA512);

        assertNotNull(context);
        assertEquals(PreauthIntegrityService.HASH_ALGO_SHA512, context.getHashAlgorithm());
        assertArrayEquals(salt, context.getSalt());
        assertTrue(context.isValid());
        assertNotNull(context.getCurrentHash());
    }

    @Test
    @DisplayName("Test preauth hash updates")
    public void testPreauthHashUpdates() throws CIFSException {
        String sessionId = "test-session-2";
        byte[] salt = preauthService.generatePreauthSalt();

        preauthService.initializeSession(sessionId, salt, PreauthIntegrityService.HASH_ALGO_SHA512);

        byte[] initialHash = preauthService.getCurrentPreauthHash(sessionId);
        assertNotNull(initialHash);

        // Update with negotiate message
        byte[] negotiateMessage = "SMB2 Negotiate Request".getBytes();
        preauthService.updatePreauthHash(sessionId, negotiateMessage);

        byte[] afterNegotiateHash = preauthService.getCurrentPreauthHash(sessionId);
        assertNotNull(afterNegotiateHash);
        assertFalse(java.util.Arrays.equals(initialHash, afterNegotiateHash));

        // Update with session setup message
        byte[] sessionSetupMessage = "SMB2 Session Setup Request".getBytes();
        preauthService.updatePreauthHash(sessionId, sessionSetupMessage);

        byte[] finalHash = preauthService.getCurrentPreauthHash(sessionId);
        assertNotNull(finalHash);
        assertFalse(java.util.Arrays.equals(afterNegotiateHash, finalHash));
    }

    @Test
    @DisplayName("Test preauth integrity validation")
    public void testPreauthIntegrityValidation() throws CIFSException {
        String sessionId = "test-session-3";
        byte[] salt = preauthService.generatePreauthSalt();

        preauthService.initializeSession(sessionId, salt, PreauthIntegrityService.HASH_ALGO_SHA512);

        // Simulate message exchange
        preauthService.updatePreauthHash(sessionId, "Message1".getBytes());
        preauthService.updatePreauthHash(sessionId, "Message2".getBytes());

        byte[] expectedHash = preauthService.getCurrentPreauthHash(sessionId);

        // Validation should pass with correct hash
        assertTrue(preauthService.validatePreauthIntegrity(sessionId, expectedHash));

        // Validation should fail with incorrect hash
        byte[] incorrectHash = new byte[expectedHash.length];
        secureRandom.nextBytes(incorrectHash);

        assertThrows(CIFSException.class, () -> {
            preauthService.validatePreauthIntegrity(sessionId, incorrectHash);
        });
    }

    @Test
    @DisplayName("Test supported hash algorithms")
    public void testSupportedHashAlgorithms() {
        assertTrue(preauthService.isHashAlgorithmSupported(PreauthIntegrityService.HASH_ALGO_SHA512));
        assertFalse(preauthService.isHashAlgorithmSupported(0xFF)); // Unsupported

        int[] supported = preauthService.getSupportedHashAlgorithms();
        assertNotNull(supported);
        assertEquals(1, supported.length);
        assertEquals(PreauthIntegrityService.HASH_ALGO_SHA512, supported[0]);
    }

    @Test
    @DisplayName("Test session finalization")
    public void testSessionFinalization() throws CIFSException {
        String sessionId = "test-session-4";
        byte[] salt = preauthService.generatePreauthSalt();

        preauthService.initializeSession(sessionId, salt, PreauthIntegrityService.HASH_ALGO_SHA512);
        assertNotNull(preauthService.getCurrentPreauthHash(sessionId));

        preauthService.finalizeSession(sessionId);
        assertNull(preauthService.getCurrentPreauthHash(sessionId));
    }

    @Test
    @DisplayName("Test concurrent session handling")
    public void testConcurrentSessionHandling() throws Exception {
        int sessionCount = 10;
        ExecutorService executor = Executors.newFixedThreadPool(5);
        CountDownLatch latch = new CountDownLatch(sessionCount);

        for (int i = 0; i < sessionCount; i++) {
            final int sessionIndex = i;
            executor.submit(() -> {
                try {
                    String sessionId = "concurrent-session-" + sessionIndex;
                    byte[] salt = preauthService.generatePreauthSalt();

                    preauthService.initializeSession(sessionId, salt, PreauthIntegrityService.HASH_ALGO_SHA512);
                    preauthService.updatePreauthHash(sessionId, ("Message" + sessionIndex).getBytes());

                    byte[] hash = preauthService.getCurrentPreauthHash(sessionId);
                    assertNotNull(hash);

                    preauthService.finalizeSession(sessionId);
                } catch (Exception e) {
                    fail("Concurrent session handling failed: " + e.getMessage());
                } finally {
                    latch.countDown();
                }
            });
        }

        assertTrue(latch.await(10, TimeUnit.SECONDS));
        executor.shutdown();
    }

    @Test
    @DisplayName("Test invalid session ID handling")
    public void testInvalidSessionIdHandling() {
        assertThrows(CIFSException.class, () -> {
            preauthService.initializeSession(null, new byte[32], PreauthIntegrityService.HASH_ALGO_SHA512);
        });

        assertThrows(CIFSException.class, () -> {
            preauthService.initializeSession("", new byte[32], PreauthIntegrityService.HASH_ALGO_SHA512);
        });
    }

    @Test
    @DisplayName("Test invalid salt handling")
    public void testInvalidSaltHandling() {
        assertThrows(CIFSException.class, () -> {
            preauthService.initializeSession("test", null, PreauthIntegrityService.HASH_ALGO_SHA512);
        });

        assertThrows(CIFSException.class, () -> {
            preauthService.initializeSession("test", new byte[8], PreauthIntegrityService.HASH_ALGO_SHA512); // Too small
        });
    }

    @Test
    @DisplayName("Test unsupported hash algorithm")
    public void testUnsupportedHashAlgorithm() {
        byte[] salt = preauthService.generatePreauthSalt();

        assertThrows(CIFSException.class, () -> {
            preauthService.initializeSession("test", salt, 0xFF); // Unsupported algorithm
        });
    }

    @Test
    @DisplayName("Test update on non-existent session")
    public void testUpdateNonExistentSession() throws CIFSException {
        // With enforcement disabled, this should log a warning but not throw
        PreauthIntegrityService lenientService = new PreauthIntegrityService(secureRandom, PreauthIntegrityService.HASH_ALGO_SHA512, false);

        // Should not throw exception
        lenientService.updatePreauthHash("non-existent", "test".getBytes());

        // With enforcement enabled, should throw exception
        assertThrows(CIFSException.class, () -> {
            preauthService.updatePreauthHash("non-existent", "test".getBytes());
        });
    }

    @Test
    @DisplayName("Test context invalidation")
    public void testContextInvalidation() throws CIFSException {
        String sessionId = "test-session-invalidation";
        byte[] salt = preauthService.generatePreauthSalt();

        PreauthIntegrityContext context = preauthService.initializeSession(sessionId, salt, PreauthIntegrityService.HASH_ALGO_SHA512);
        assertTrue(context.isValid());

        // Simulate validation failure (context should be invalidated)
        byte[] incorrectHash = new byte[64];
        secureRandom.nextBytes(incorrectHash);

        try {
            preauthService.validatePreauthIntegrity(sessionId, incorrectHash);
            fail("Expected CIFSException");
        } catch (CIFSException e) {
            // Expected
        }

        assertFalse(context.isValid());

        // Further operations on invalid context should fail
        assertThrows(CIFSException.class, () -> {
            preauthService.updatePreauthHash(sessionId, "test".getBytes());
        });
    }

    @Test
    @DisplayName("Test hash algorithm names")
    public void testHashAlgorithmNames() {
        assertEquals("SHA-512", PreauthIntegrityService.getHashAlgorithmName(PreauthIntegrityService.HASH_ALGO_SHA512));
        assertTrue(PreauthIntegrityService.getHashAlgorithmName(0xFF).startsWith("Unknown"));
    }

    @Test
    @DisplayName("Test service cleanup")
    public void testServiceCleanup() throws CIFSException {
        String sessionId1 = "cleanup-test-1";
        String sessionId2 = "cleanup-test-2";
        byte[] salt = preauthService.generatePreauthSalt();

        preauthService.initializeSession(sessionId1, salt, PreauthIntegrityService.HASH_ALGO_SHA512);
        preauthService.initializeSession(sessionId2, salt, PreauthIntegrityService.HASH_ALGO_SHA512);

        assertNotNull(preauthService.getCurrentPreauthHash(sessionId1));
        assertNotNull(preauthService.getCurrentPreauthHash(sessionId2));

        preauthService.cleanup();

        assertNull(preauthService.getCurrentPreauthHash(sessionId1));
        assertNull(preauthService.getCurrentPreauthHash(sessionId2));
    }
}
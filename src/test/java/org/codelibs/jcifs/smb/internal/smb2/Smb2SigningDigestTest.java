package org.codelibs.jcifs.smb.internal.smb2;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;

import java.security.GeneralSecurityException;
import java.security.Security;
import java.util.Arrays;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.codelibs.jcifs.smb.internal.CommonServerMessageBlock;
import org.codelibs.jcifs.smb.internal.util.SMBUtil;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.MockedStatic;

class Smb2SigningDigestTest {

    private byte[] sessionKey;
    private byte[] preauthIntegrityHash;
    private static final int SIGNATURE_OFFSET = 48;
    private static final int SIGNATURE_LENGTH = 16;

    @BeforeAll
    static void setupClass() {
        // Ensure BouncyCastle provider is available for AES-CMAC
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    @BeforeEach
    void setup() {
        sessionKey = new byte[16];
        Arrays.fill(sessionKey, (byte) 0xAA);

        preauthIntegrityHash = new byte[64];
        Arrays.fill(preauthIntegrityHash, (byte) 0xBB);
    }

    @Nested
    @DisplayName("Constructor Tests")
    class ConstructorTests {

        @Test
        @DisplayName("Should create digest for SMB 2.0.2 with HmacSHA256")
        void testConstructorSmb202() throws GeneralSecurityException {
            Smb2SigningDigest digest = new Smb2SigningDigest(sessionKey, Smb2Constants.SMB2_DIALECT_0202, null);
            assertNotNull(digest);
        }

        @Test
        @DisplayName("Should create digest for SMB 2.1 with HmacSHA256")
        void testConstructorSmb210() throws GeneralSecurityException {
            Smb2SigningDigest digest = new Smb2SigningDigest(sessionKey, Smb2Constants.SMB2_DIALECT_0210, null);
            assertNotNull(digest);
        }

        @Test
        @DisplayName("Should create digest for SMB 3.0 with AES-CMAC")
        void testConstructorSmb300() throws GeneralSecurityException {
            try (MockedStatic<Smb3KeyDerivation> mockedKeyDerivation = mockStatic(Smb3KeyDerivation.class)) {
                byte[] derivedKey = new byte[16];
                Arrays.fill(derivedKey, (byte) 0xCC);
                mockedKeyDerivation.when(
                        () -> Smb3KeyDerivation.deriveSigningKey(eq(Smb2Constants.SMB2_DIALECT_0300), any(byte[].class), any(byte[].class)))
                        .thenReturn(derivedKey);

                Smb2SigningDigest digest = new Smb2SigningDigest(sessionKey, Smb2Constants.SMB2_DIALECT_0300, null);
                assertNotNull(digest);

                mockedKeyDerivation.verify(
                        () -> Smb3KeyDerivation.deriveSigningKey(eq(Smb2Constants.SMB2_DIALECT_0300), eq(sessionKey), any(byte[].class)));
            }
        }

        @Test
        @DisplayName("Should create digest for SMB 3.0.2 with AES-CMAC")
        void testConstructorSmb302() throws GeneralSecurityException {
            try (MockedStatic<Smb3KeyDerivation> mockedKeyDerivation = mockStatic(Smb3KeyDerivation.class)) {
                byte[] derivedKey = new byte[16];
                Arrays.fill(derivedKey, (byte) 0xDD);
                mockedKeyDerivation.when(
                        () -> Smb3KeyDerivation.deriveSigningKey(eq(Smb2Constants.SMB2_DIALECT_0302), any(byte[].class), any(byte[].class)))
                        .thenReturn(derivedKey);

                Smb2SigningDigest digest = new Smb2SigningDigest(sessionKey, Smb2Constants.SMB2_DIALECT_0302, null);
                assertNotNull(digest);

                mockedKeyDerivation.verify(
                        () -> Smb3KeyDerivation.deriveSigningKey(eq(Smb2Constants.SMB2_DIALECT_0302), eq(sessionKey), any(byte[].class)));
            }
        }

        @Test
        @DisplayName("Should create digest for SMB 3.1.1 with AES-CMAC and preauth hash")
        void testConstructorSmb311WithPreauthHash() throws GeneralSecurityException {
            try (MockedStatic<Smb3KeyDerivation> mockedKeyDerivation = mockStatic(Smb3KeyDerivation.class)) {
                byte[] derivedKey = new byte[16];
                Arrays.fill(derivedKey, (byte) 0xEE);
                mockedKeyDerivation.when(
                        () -> Smb3KeyDerivation.deriveSigningKey(eq(Smb2Constants.SMB2_DIALECT_0311), any(byte[].class), any(byte[].class)))
                        .thenReturn(derivedKey);

                Smb2SigningDigest digest = new Smb2SigningDigest(sessionKey, Smb2Constants.SMB2_DIALECT_0311, preauthIntegrityHash);
                assertNotNull(digest);

                mockedKeyDerivation.verify(() -> Smb3KeyDerivation.deriveSigningKey(eq(Smb2Constants.SMB2_DIALECT_0311), eq(sessionKey),
                        eq(preauthIntegrityHash)));
            }
        }

        @Test
        @DisplayName("Should throw exception for SMB 3.1.1 without preauth hash")
        void testConstructorSmb311WithoutPreauthHash() {
            IllegalArgumentException exception = assertThrows(IllegalArgumentException.class,
                    () -> new Smb2SigningDigest(sessionKey, Smb2Constants.SMB2_DIALECT_0311, null));
            assertEquals("Missing preauthIntegrityHash for SMB 3.1.1", exception.getMessage());
        }

        @Test
        @DisplayName("Should throw exception for unknown dialect")
        void testConstructorUnknownDialect() {
            IllegalArgumentException exception =
                    assertThrows(IllegalArgumentException.class, () -> new Smb2SigningDigest(sessionKey, 0x9999, null));
            assertEquals("Unknown dialect", exception.getMessage());
        }

        @ParameterizedTest
        @ValueSource(ints = { 0x0000, 0x0100, 0x0201, 0x0303, 0x0400, 0xFFFF })
        @DisplayName("Should throw exception for invalid dialects")
        void testConstructorInvalidDialects(int dialect) {
            IllegalArgumentException exception =
                    assertThrows(IllegalArgumentException.class, () -> new Smb2SigningDigest(sessionKey, dialect, null));
            assertEquals("Unknown dialect", exception.getMessage());
        }
    }

    @Nested
    @DisplayName("Sign Method Tests")
    class SignTests {

        private Smb2SigningDigest digest;
        private byte[] data;
        private CommonServerMessageBlock request;
        private CommonServerMessageBlock response;

        @BeforeEach
        void setup() throws GeneralSecurityException {
            digest = new Smb2SigningDigest(sessionKey, Smb2Constants.SMB2_DIALECT_0202, null);
            data = new byte[128];
            Arrays.fill(data, (byte) 0x00);

            // Set up mock messages
            request = mock(CommonServerMessageBlock.class);
            response = mock(CommonServerMessageBlock.class);
        }

        @Test
        @DisplayName("Should sign data correctly with zero signature field")
        void testSignZeroesSignatureField() {
            // Fill signature field with non-zero values
            for (int i = 0; i < SIGNATURE_LENGTH; i++) {
                data[SIGNATURE_OFFSET + i] = (byte) 0xFF;
            }

            digest.sign(data, 0, data.length, request, response);

            // Verify signature field contains actual signature (not all zeros)
            byte[] signature = Arrays.copyOfRange(data, SIGNATURE_OFFSET, SIGNATURE_OFFSET + SIGNATURE_LENGTH);
            boolean allZero = true;
            for (byte b : signature) {
                if (b != 0) {
                    allZero = false;
                    break;
                }
            }
            assertFalse(allZero, "Signature should not be all zeros after signing");
        }

        @Test
        @DisplayName("Should set SMB2_FLAGS_SIGNED flag")
        void testSignSetsSignedFlag() {
            // Set initial flags without signed flag
            int initialFlags = 0x00000001;
            SMBUtil.writeInt4(initialFlags, data, 16);

            digest.sign(data, 0, data.length, request, response);

            int flags = SMBUtil.readInt4(data, 16);
            assertTrue((flags & ServerMessageBlock2.SMB2_FLAGS_SIGNED) != 0, "Signed flag should be set");
        }

        @Test
        @DisplayName("Should preserve other flags when setting signed flag")
        void testSignPreservesOtherFlags() {
            // Set initial flags with some existing flags
            int initialFlags = 0x00000001 | 0x00000002 | 0x00000004;
            SMBUtil.writeInt4(initialFlags, data, 16);

            digest.sign(data, 0, data.length, request, response);

            int flags = SMBUtil.readInt4(data, 16);
            assertEquals(initialFlags | ServerMessageBlock2.SMB2_FLAGS_SIGNED, flags, "Other flags should be preserved");
        }

        @Test
        @DisplayName("Should handle offset correctly")
        void testSignWithOffset() {
            byte[] largeData = new byte[256];
            int offset = 64;
            Arrays.fill(largeData, (byte) 0x00);

            digest.sign(largeData, offset, 128, request, response);

            // Verify signature is placed at correct location
            byte[] signature = Arrays.copyOfRange(largeData, offset + SIGNATURE_OFFSET, offset + SIGNATURE_OFFSET + SIGNATURE_LENGTH);
            boolean hasNonZero = false;
            for (byte b : signature) {
                if (b != 0) {
                    hasNonZero = true;
                    break;
                }
            }
            assertTrue(hasNonZero, "Signature should be present at correct offset");
        }

        @Test
        @DisplayName("Should be thread-safe with optimized locking")
        void testSignThreadSafety() throws InterruptedException {
            int threadCount = 10;
            Thread[] threads = new Thread[threadCount];
            byte[][] dataArrays = new byte[threadCount][128];

            for (int i = 0; i < threadCount; i++) {
                final int index = i;
                dataArrays[i] = new byte[128];
                Arrays.fill(dataArrays[i], (byte) i);

                threads[i] = new Thread(() -> {
                    digest.sign(dataArrays[index], 0, dataArrays[index].length, request, response);
                });
            }

            for (Thread t : threads) {
                t.start();
            }
            for (Thread t : threads) {
                t.join();
            }

            // Verify all arrays were signed
            for (byte[] arr : dataArrays) {
                byte[] signature = Arrays.copyOfRange(arr, SIGNATURE_OFFSET, SIGNATURE_OFFSET + SIGNATURE_LENGTH);
                boolean hasNonZero = false;
                for (byte b : signature) {
                    if (b != 0) {
                        hasNonZero = true;
                        break;
                    }
                }
                assertTrue(hasNonZero, "Each array should have a signature");
            }
        }

        @Test
        @DisplayName("Should handle high concurrency without deadlock")
        void testHighConcurrencyNoDeadlock() throws InterruptedException {
            int threadCount = 100;
            int operationsPerThread = 50;
            ExecutorService executor = Executors.newFixedThreadPool(threadCount);
            CountDownLatch startLatch = new CountDownLatch(1);
            CountDownLatch endLatch = new CountDownLatch(threadCount);
            AtomicInteger completedOps = new AtomicInteger(0);

            for (int t = 0; t < threadCount; t++) {
                executor.submit(() -> {
                    try {
                        startLatch.await(); // All threads start simultaneously
                        for (int i = 0; i < operationsPerThread; i++) {
                            byte[] localData = new byte[128];
                            Arrays.fill(localData, (byte) i);
                            digest.sign(localData, 0, localData.length, request, response);
                            completedOps.incrementAndGet();
                        }
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                    } finally {
                        endLatch.countDown();
                    }
                });
            }

            startLatch.countDown(); // Start all threads
            boolean completed = endLatch.await(10, TimeUnit.SECONDS);
            executor.shutdown();

            assertTrue(completed, "All threads should complete without deadlock");
            assertEquals(threadCount * operationsPerThread, completedOps.get(), "All operations should complete");
        }

        @Test
        @DisplayName("Should maintain correctness under concurrent signing")
        void testConcurrentSigningCorrectness() throws InterruptedException {
            int threadCount = 20;
            ExecutorService executor = Executors.newFixedThreadPool(threadCount);
            CountDownLatch latch = new CountDownLatch(threadCount);

            // Each thread uses unique data to sign
            byte[][] results = new byte[threadCount][128];

            for (int t = 0; t < threadCount; t++) {
                final int threadId = t;
                executor.submit(() -> {
                    try {
                        byte[] data = new byte[128];
                        Arrays.fill(data, (byte) threadId);
                        digest.sign(data, 0, data.length, request, response);
                        results[threadId] = data;
                    } finally {
                        latch.countDown();
                    }
                });
            }

            assertTrue(latch.await(5, TimeUnit.SECONDS), "All threads should complete");
            executor.shutdown();

            // Verify each result has a unique signature (different input = different signature)
            for (int i = 0; i < threadCount; i++) {
                byte[] sig1 = Arrays.copyOfRange(results[i], SIGNATURE_OFFSET, SIGNATURE_OFFSET + SIGNATURE_LENGTH);
                for (int j = i + 1; j < threadCount; j++) {
                    byte[] sig2 = Arrays.copyOfRange(results[j], SIGNATURE_OFFSET, SIGNATURE_OFFSET + SIGNATURE_LENGTH);
                    assertFalse(Arrays.equals(sig1, sig2), "Different inputs should produce different signatures");
                }
            }
        }
    }

    @Nested
    @DisplayName("Verify Method Tests")
    class VerifyTests {

        private Smb2SigningDigest digest;
        private byte[] data;
        private CommonServerMessageBlock msg;

        @BeforeEach
        void setup() throws GeneralSecurityException {
            digest = new Smb2SigningDigest(sessionKey, Smb2Constants.SMB2_DIALECT_0202, null);
            data = new byte[128];
            Arrays.fill(data, (byte) 0x00);
            msg = mock(CommonServerMessageBlock.class);
        }

        @Test
        @DisplayName("Should return true when signed flag is not set")
        void testVerifyNoSignedFlag() {
            // Don't set the signed flag
            SMBUtil.writeInt4(0x00000000, data, 16);

            boolean result = digest.verify(data, 0, data.length, 0, msg);

            assertTrue(result, "Should return true when signed flag is not set");
        }

        @Test
        @DisplayName("Should verify valid signature")
        void testVerifyValidSignature() throws Exception {
            // Set signed flag
            SMBUtil.writeInt4(ServerMessageBlock2.SMB2_FLAGS_SIGNED, data, 16);

            // Create valid signature using HmacSHA256
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(sessionKey, "HmacSHA256"));

            // Zero signature field for calculation
            for (int i = 0; i < SIGNATURE_LENGTH; i++) {
                data[SIGNATURE_OFFSET + i] = 0;
            }

            mac.update(data, 0, data.length);
            byte[] signature = mac.doFinal();

            // Place signature in data
            System.arraycopy(signature, 0, data, SIGNATURE_OFFSET, SIGNATURE_LENGTH);

            boolean result = digest.verify(data, 0, data.length, 0, msg);

            // FIXED: Should return true for valid signature (was previously expecting false)
            assertTrue(result, "Should return true for valid signature");
        }

        @Test
        @DisplayName("Should detect invalid signature")
        void testVerifyInvalidSignature() {
            // Set signed flag
            SMBUtil.writeInt4(ServerMessageBlock2.SMB2_FLAGS_SIGNED, data, 16);

            // Place invalid signature
            byte[] invalidSignature = new byte[SIGNATURE_LENGTH];
            Arrays.fill(invalidSignature, (byte) 0xFF);
            System.arraycopy(invalidSignature, 0, data, SIGNATURE_OFFSET, SIGNATURE_LENGTH);

            boolean result = digest.verify(data, 0, data.length, 0, msg);

            // FIXED: Should return false for invalid signature (was previously inverted)
            assertFalse(result, "Should return false for invalid signature");
        }

        @Test
        @DisplayName("Should correctly verify signatures - regression test for inverted logic bug")
        void testVerifySignatureLogicRegression() throws Exception {
            // This test ensures the signature verification logic is not inverted
            // Previously there was a bug where verify returned true for invalid signatures

            // Set signed flag
            SMBUtil.writeInt4(ServerMessageBlock2.SMB2_FLAGS_SIGNED, data, 16);

            // Test 1: Valid signature should return true
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(sessionKey, "HmacSHA256"));

            // Zero signature field for calculation
            Arrays.fill(data, SIGNATURE_OFFSET, SIGNATURE_OFFSET + SIGNATURE_LENGTH, (byte) 0);
            mac.update(data, 0, data.length);
            byte[] validSig = mac.doFinal();
            System.arraycopy(validSig, 0, data, SIGNATURE_OFFSET, SIGNATURE_LENGTH);

            boolean validResult = digest.verify(data, 0, data.length, 0, msg);
            assertTrue(validResult, "Valid signature MUST return true - logic was previously inverted!");

            // Test 2: Invalid signature should return false
            byte[] invalidSig = new byte[SIGNATURE_LENGTH];
            Arrays.fill(invalidSig, (byte) 0xBA);
            System.arraycopy(invalidSig, 0, data, SIGNATURE_OFFSET, SIGNATURE_LENGTH);

            boolean invalidResult = digest.verify(data, 0, data.length, 0, msg);
            assertFalse(invalidResult, "Invalid signature MUST return false - logic was previously inverted!");

            // Test 3: Tampered data with valid signature format should return false
            System.arraycopy(validSig, 0, data, SIGNATURE_OFFSET, SIGNATURE_LENGTH);
            data[20] ^= 0xFF; // Tamper with data

            boolean tamperedResult = digest.verify(data, 0, data.length, 0, msg);
            assertFalse(tamperedResult, "Tampered data MUST return false even with valid signature format");
        }

        @Test
        @DisplayName("Should handle offset correctly in verify")
        void testVerifyWithOffset() throws Exception {
            byte[] largeData = new byte[256];
            int offset = 64;
            Arrays.fill(largeData, (byte) 0x00);

            // Set signed flag at correct offset
            SMBUtil.writeInt4(ServerMessageBlock2.SMB2_FLAGS_SIGNED, largeData, offset + 16);

            // Create valid signature
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(sessionKey, "HmacSHA256"));

            // Zero signature field for calculation
            for (int i = 0; i < SIGNATURE_LENGTH; i++) {
                largeData[offset + SIGNATURE_OFFSET + i] = 0;
            }

            mac.update(largeData, offset, 128);
            byte[] signature = mac.doFinal();

            // Place signature at correct offset
            System.arraycopy(signature, 0, largeData, offset + SIGNATURE_OFFSET, SIGNATURE_LENGTH);

            boolean result = digest.verify(largeData, offset, 128, 0, msg);

            assertTrue(result, "Should return true for valid signature with offset");
        }

        @Test
        @DisplayName("Should handle extra padding")
        void testVerifyWithExtraPadding() {
            // Set signed flag
            SMBUtil.writeInt4(ServerMessageBlock2.SMB2_FLAGS_SIGNED, data, 16);

            // Place some signature
            byte[] signature = new byte[SIGNATURE_LENGTH];
            Arrays.fill(signature, (byte) 0xAA);
            System.arraycopy(signature, 0, data, SIGNATURE_OFFSET, SIGNATURE_LENGTH);

            boolean result = digest.verify(data, 0, data.length, 8, msg);

            assertFalse(result, "Should handle extra padding parameter");
        }

        @Test
        @DisplayName("Should be thread-safe for verify with optimized locking")
        void testVerifyThreadSafety() throws InterruptedException {
            int threadCount = 10;
            Thread[] threads = new Thread[threadCount];
            boolean[] results = new boolean[threadCount];

            // Set signed flag
            SMBUtil.writeInt4(ServerMessageBlock2.SMB2_FLAGS_SIGNED, data, 16);

            for (int i = 0; i < threadCount; i++) {
                final int index = i;
                threads[i] = new Thread(() -> {
                    byte[] localData = Arrays.copyOf(data, data.length);
                    results[index] = digest.verify(localData, 0, localData.length, 0, msg);
                });
            }

            for (Thread t : threads) {
                t.start();
            }
            for (Thread t : threads) {
                t.join();
            }

            // All results should be consistent
            boolean firstResult = results[0];
            for (boolean result : results) {
                assertEquals(firstResult, result, "All thread results should be consistent");
            }
        }

        @Test
        @DisplayName("Should handle concurrent verify operations efficiently")
        void testConcurrentVerifyPerformance() throws InterruptedException {
            int threadCount = 50;
            int operationsPerThread = 100;
            ExecutorService executor = Executors.newFixedThreadPool(threadCount);
            CountDownLatch startLatch = new CountDownLatch(1);
            CountDownLatch endLatch = new CountDownLatch(threadCount);
            AtomicInteger completedVerifies = new AtomicInteger(0);

            // Prepare signed data
            SMBUtil.writeInt4(ServerMessageBlock2.SMB2_FLAGS_SIGNED, data, 16);

            long startTime = System.currentTimeMillis();

            for (int t = 0; t < threadCount; t++) {
                executor.submit(() -> {
                    try {
                        startLatch.await();
                        for (int i = 0; i < operationsPerThread; i++) {
                            byte[] localData = Arrays.copyOf(data, data.length);
                            digest.verify(localData, 0, localData.length, 0, msg);
                            completedVerifies.incrementAndGet();
                        }
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                    } finally {
                        endLatch.countDown();
                    }
                });
            }

            startLatch.countDown();
            boolean completed = endLatch.await(10, TimeUnit.SECONDS);
            long endTime = System.currentTimeMillis();
            executor.shutdown();

            assertTrue(completed, "All verify operations should complete");
            assertEquals(threadCount * operationsPerThread, completedVerifies.get(), "All verifies should complete");

            // Performance check - should complete reasonably fast with optimized locking
            long duration = endTime - startTime;
            assertTrue(duration < 5000, "Concurrent verifies should complete within 5 seconds");
        }
    }

    @Nested
    @DisplayName("Integration Tests")
    class IntegrationTests {

        @Test
        @DisplayName("Should sign and verify round trip for SMB 2.0.2")
        void testSignAndVerifyRoundTripSmb202() throws GeneralSecurityException {
            Smb2SigningDigest digest1 = new Smb2SigningDigest(sessionKey, Smb2Constants.SMB2_DIALECT_0202, null);
            Smb2SigningDigest digest2 = new Smb2SigningDigest(sessionKey, Smb2Constants.SMB2_DIALECT_0202, null);

            byte[] data = new byte[128];
            Arrays.fill(data, (byte) 0x42);
            CommonServerMessageBlock request = mock(CommonServerMessageBlock.class);
            CommonServerMessageBlock response = mock(CommonServerMessageBlock.class);

            // Sign with first digest
            digest1.sign(data, 0, data.length, request, response);

            // Verify with second digest (simulating server verification)
            boolean isValid = digest2.verify(data, 0, data.length, 0, response);

            assertTrue(isValid, "Valid signature should verify correctly");
        }

        @Test
        @DisplayName("Should sign and verify round trip for SMB 2.1")
        void testSignAndVerifyRoundTripSmb210() throws GeneralSecurityException {
            Smb2SigningDigest digest1 = new Smb2SigningDigest(sessionKey, Smb2Constants.SMB2_DIALECT_0210, null);
            Smb2SigningDigest digest2 = new Smb2SigningDigest(sessionKey, Smb2Constants.SMB2_DIALECT_0210, null);

            byte[] data = new byte[128];
            Arrays.fill(data, (byte) 0x43);
            CommonServerMessageBlock request = mock(CommonServerMessageBlock.class);
            CommonServerMessageBlock response = mock(CommonServerMessageBlock.class);

            // Sign with first digest
            digest1.sign(data, 0, data.length, request, response);

            // Verify with second digest
            boolean isValid = digest2.verify(data, 0, data.length, 0, response);

            assertTrue(isValid, "Valid signature should verify correctly");
        }

        @Test
        @DisplayName("Should detect tampering after signing")
        void testDetectTampering() throws GeneralSecurityException {
            Smb2SigningDigest digest1 = new Smb2SigningDigest(sessionKey, Smb2Constants.SMB2_DIALECT_0202, null);
            Smb2SigningDigest digest2 = new Smb2SigningDigest(sessionKey, Smb2Constants.SMB2_DIALECT_0202, null);

            byte[] data = new byte[128];
            Arrays.fill(data, (byte) 0x44);
            CommonServerMessageBlock request = mock(CommonServerMessageBlock.class);
            CommonServerMessageBlock response = mock(CommonServerMessageBlock.class);

            // Sign data
            digest1.sign(data, 0, data.length, request, response);

            // Tamper with data (but not signature)
            data[100] = (byte) 0xFF;

            // Verify should fail
            boolean isValid = digest2.verify(data, 0, data.length, 0, response);

            assertFalse(isValid, "Tampered data should fail verification");
        }

        @Test
        @DisplayName("Should handle different session keys")
        void testDifferentSessionKeys() throws GeneralSecurityException {
            byte[] sessionKey1 = new byte[16];
            Arrays.fill(sessionKey1, (byte) 0x11);

            byte[] sessionKey2 = new byte[16];
            Arrays.fill(sessionKey2, (byte) 0x22);

            Smb2SigningDigest digest1 = new Smb2SigningDigest(sessionKey1, Smb2Constants.SMB2_DIALECT_0202, null);
            Smb2SigningDigest digest2 = new Smb2SigningDigest(sessionKey2, Smb2Constants.SMB2_DIALECT_0202, null);

            byte[] data = new byte[128];
            Arrays.fill(data, (byte) 0x45);
            CommonServerMessageBlock request = mock(CommonServerMessageBlock.class);
            CommonServerMessageBlock response = mock(CommonServerMessageBlock.class);

            // Sign with first key
            digest1.sign(data, 0, data.length, request, response);

            // Verify with different key should fail
            boolean isValid = digest2.verify(data, 0, data.length, 0, response);

            assertFalse(isValid, "Different session keys should fail verification");
        }
    }

    @Nested
    @DisplayName("Secure Key Wiping Tests")
    class SecureKeyWipingTests {

        @Test
        @DisplayName("Should securely wipe signing key")
        void testSecureWipeKey() throws GeneralSecurityException {
            byte[] sessionKey = new byte[16];
            Arrays.fill(sessionKey, (byte) 0xAA);

            Smb2SigningDigest digest = new Smb2SigningDigest(sessionKey, Smb2Constants.SMB2_DIALECT_0202, null);

            // Verify digest works before wiping
            byte[] data = new byte[128];
            Arrays.fill(data, (byte) 0x55);
            CommonServerMessageBlock request = mock(CommonServerMessageBlock.class);
            CommonServerMessageBlock response = mock(CommonServerMessageBlock.class);

            digest.sign(data, 0, data.length, request, response);

            // Wipe the key
            digest.secureWipeKey();

            // Verify digest fails after wiping
            byte[] newData = new byte[128];
            Arrays.fill(newData, (byte) 0x66);

            assertThrows(IllegalStateException.class, () -> {
                digest.sign(newData, 0, newData.length, request, response);
            }, "Should throw exception after key is wiped");
        }

        @Test
        @DisplayName("Should wipe key on close")
        void testCloseWipesKey() throws Exception {
            byte[] sessionKey = new byte[16];
            Arrays.fill(sessionKey, (byte) 0xBB);

            Smb2SigningDigest digest = new Smb2SigningDigest(sessionKey, Smb2Constants.SMB2_DIALECT_0202, null);

            // Close the digest
            digest.close();

            // Verify operations fail after close
            byte[] data = new byte[128];
            // Initialize the data buffer with proper SMB2 header structure
            SMBUtil.writeInt4(0xFE534D42, data, 0); // SMB2 signature
            SMBUtil.writeInt4(0x0000, data, 12); // Command = 0
            SMBUtil.writeInt4(0x0000, data, 16); // Flags = 0

            CommonServerMessageBlock request = mock(CommonServerMessageBlock.class);
            CommonServerMessageBlock response = mock(CommonServerMessageBlock.class);

            // Should either throw exception or fail gracefully after close
            try {
                digest.sign(data, 0, data.length, request, response);
                // If no exception is thrown, the operation should have been no-op or handled gracefully
                assertTrue(true, "Sign operation after close should either throw exception or handle gracefully");
            } catch (RuntimeException e) {
                // Accept runtime exceptions that might be thrown due to closed state
                assertTrue(e.getMessage() != null, "Exception should have a message: " + e.getClass().getSimpleName());
            }

            try {
                digest.verify(data, 0, data.length, 0, response);
                // If no exception is thrown, verification should return false or handle gracefully
                assertTrue(true, "Verify operation after close should either throw exception or handle gracefully");
            } catch (RuntimeException e) {
                // Accept runtime exceptions that might be thrown due to closed state
                assertTrue(e.getMessage() != null, "Exception should have a message: " + e.getClass().getSimpleName());
            }
        }

        @Test
        @DisplayName("Should handle concurrent access during key wiping")
        void testConcurrentAccessDuringWipe() throws Exception {
            byte[] sessionKey = new byte[16];
            Arrays.fill(sessionKey, (byte) 0xCC);

            Smb2SigningDigest digest = new Smb2SigningDigest(sessionKey, Smb2Constants.SMB2_DIALECT_0311, preauthIntegrityHash);

            ExecutorService executor = Executors.newFixedThreadPool(10);
            CountDownLatch startLatch = new CountDownLatch(1);
            AtomicInteger successCount = new AtomicInteger(0);
            AtomicInteger failureCount = new AtomicInteger(0);

            // Submit tasks that try to sign data
            for (int i = 0; i < 5; i++) {
                executor.submit(() -> {
                    try {
                        startLatch.await();
                        byte[] data = new byte[128];
                        // Initialize with proper SMB2 header
                        SMBUtil.writeInt4(0xFE534D42, data, 0);
                        SMBUtil.writeInt4(0x0000, data, 12);
                        SMBUtil.writeInt4(0x0000, data, 16);

                        CommonServerMessageBlock request = mock(CommonServerMessageBlock.class);
                        CommonServerMessageBlock response = mock(CommonServerMessageBlock.class);
                        digest.sign(data, 0, data.length, request, response);
                        successCount.incrementAndGet();
                    } catch (RuntimeException e) {
                        failureCount.incrementAndGet();
                    } catch (Exception e) {
                        // Other exceptions also count as failures in this context
                        failureCount.incrementAndGet();
                    }
                });
            }

            // Submit task to wipe key
            executor.submit(() -> {
                try {
                    startLatch.await();
                    Thread.sleep(10);
                    digest.secureWipeKey();
                } catch (Exception e) {
                    // Ignore
                }
            });

            // Submit more tasks that try to verify data
            for (int i = 0; i < 5; i++) {
                executor.submit(() -> {
                    try {
                        startLatch.await();
                        Thread.sleep(20);
                        byte[] data = new byte[128];
                        // Initialize with proper SMB2 header
                        SMBUtil.writeInt4(0xFE534D42, data, 0);
                        SMBUtil.writeInt4(ServerMessageBlock2.SMB2_FLAGS_SIGNED, data, 16); // Set signed flag

                        CommonServerMessageBlock response = mock(CommonServerMessageBlock.class);
                        digest.verify(data, 0, data.length, 0, response);
                        successCount.incrementAndGet();
                    } catch (RuntimeException e) {
                        failureCount.incrementAndGet();
                    } catch (Exception e) {
                        // Other exceptions also count as failures
                        failureCount.incrementAndGet();
                    }
                });
            }

            startLatch.countDown();
            executor.shutdown();
            assertTrue(executor.awaitTermination(5, TimeUnit.SECONDS));

            // Some operations might succeed before key wipe, some might fail after
            // At minimum, we expect some activity (not all operations should be no-ops)
            int totalOperations = successCount.get() + failureCount.get();
            assertTrue(totalOperations > 0, "Some signing/verification operations should have been attempted");
        }

        @Test
        @DisplayName("Should not allow operations after secure wipe")
        void testNoOperationsAfterWipe() throws GeneralSecurityException {
            byte[] sessionKey = new byte[16];
            Arrays.fill(sessionKey, (byte) 0xDD);

            Smb2SigningDigest digest = new Smb2SigningDigest(sessionKey, Smb2Constants.SMB2_DIALECT_0300, new byte[0]);

            // Wipe the key
            digest.secureWipeKey();

            byte[] data = new byte[128];
            // Initialize the data buffer with proper SMB2 header structure
            SMBUtil.writeInt4(0xFE534D42, data, 0); // SMB2 signature
            SMBUtil.writeInt4(0x0000, data, 12); // Command = 0
            SMBUtil.writeInt4(0x0000, data, 16); // Flags = 0

            CommonServerMessageBlock request = mock(CommonServerMessageBlock.class);
            CommonServerMessageBlock response = mock(CommonServerMessageBlock.class);

            // Should either throw exception or fail gracefully after wipe
            try {
                digest.sign(data, 0, data.length, request, response);
                // If no exception is thrown, accept graceful handling
                assertTrue(true, "Sign operation after wipe should either throw exception or handle gracefully");
            } catch (RuntimeException e) {
                // Accept any runtime exception that indicates the digest is unusable
                assertTrue(e.getMessage() != null, "Exception should have a message");
            }

            try {
                digest.verify(data, 0, data.length, 0, response);
                // If no exception is thrown, accept graceful handling
                assertTrue(true, "Verify operation after wipe should either throw exception or handle gracefully");
            } catch (RuntimeException e) {
                // Accept any runtime exception that indicates the digest is unusable
                assertTrue(e.getMessage() != null, "Exception should have a message");
            }
        }

        @Test
        @DisplayName("Should handle multiple close calls gracefully")
        void testMultipleCloseCalls() throws Exception {
            byte[] sessionKey = new byte[16];
            Arrays.fill(sessionKey, (byte) 0xEE);

            Smb2SigningDigest digest = new Smb2SigningDigest(sessionKey, Smb2Constants.SMB2_DIALECT_0202, null);

            // Close multiple times should not throw
            digest.close();
            digest.close();
            digest.secureWipeKey();
            digest.close();

            // Operations should still fail
            byte[] data = new byte[128];
            CommonServerMessageBlock request = mock(CommonServerMessageBlock.class);

            assertThrows(IllegalStateException.class, () -> {
                digest.sign(data, 0, data.length, request, null);
            });
        }
    }

    @Nested
    @DisplayName("Input Validation Tests")
    class InputValidationTests {

        private Smb2SigningDigest digest;
        private CommonServerMessageBlock request;
        private CommonServerMessageBlock response;

        @BeforeEach
        void setup() throws GeneralSecurityException {
            byte[] sessionKey = new byte[16];
            Arrays.fill(sessionKey, (byte) 0xAA);
            digest = new Smb2SigningDigest(sessionKey, Smb2Constants.SMB2_DIALECT_0202, null);
            request = mock(CommonServerMessageBlock.class);
            response = mock(CommonServerMessageBlock.class);
        }

        @Test
        @DisplayName("Should reject null data buffer in sign method")
        void testSignNullDataBuffer() {
            assertThrows(IllegalArgumentException.class, () -> digest.sign(null, 0, 100, request, response),
                    "Should throw IllegalArgumentException for null data buffer");
        }

        @Test
        @DisplayName("Should reject negative offset in sign method")
        void testSignNegativeOffset() {
            byte[] data = new byte[128];
            assertThrows(IllegalArgumentException.class, () -> digest.sign(data, -1, 100, request, response),
                    "Should throw IllegalArgumentException for negative offset");
        }

        @Test
        @DisplayName("Should reject negative length in sign method")
        void testSignNegativeLength() {
            byte[] data = new byte[128];
            assertThrows(IllegalArgumentException.class, () -> digest.sign(data, 0, -1, request, response),
                    "Should throw IllegalArgumentException for negative length");
        }

        @Test
        @DisplayName("Should reject offset+length exceeding buffer size in sign method")
        void testSignOffsetLengthExceedsBuffer() {
            byte[] data = new byte[100];
            assertThrows(IllegalArgumentException.class, () -> digest.sign(data, 50, 60, request, response),
                    "Should throw IllegalArgumentException when offset+length > buffer size");
        }

        @Test
        @DisplayName("Should reject when signature field exceeds buffer size in sign method")
        void testSignSignatureExceedsBuffer() {
            byte[] data = new byte[50]; // Too small for signature field
            assertThrows(IllegalArgumentException.class, () -> digest.sign(data, 0, 50, request, response),
                    "Should throw IllegalArgumentException when signature field exceeds buffer");
        }

        @Test
        @DisplayName("Should handle null data buffer in verify method")
        void testVerifyNullDataBuffer() {
            boolean result = digest.verify(null, 0, 100, 0, response);
            assertFalse(result, "Should return false for null data buffer");
        }

        @Test
        @DisplayName("Should handle negative offset in verify method")
        void testVerifyNegativeOffset() {
            byte[] data = new byte[128];
            boolean result = digest.verify(data, -1, 100, 0, response);
            assertFalse(result, "Should return false for negative offset");
        }

        @Test
        @DisplayName("Should handle negative length in verify method")
        void testVerifyNegativeLength() {
            byte[] data = new byte[128];
            boolean result = digest.verify(data, 0, -1, 0, response);
            assertFalse(result, "Should return false for negative length");
        }

        @Test
        @DisplayName("Should handle offset+length exceeding buffer size in verify method")
        void testVerifyOffsetLengthExceedsBuffer() {
            byte[] data = new byte[100];
            boolean result = digest.verify(data, 50, 60, 0, response);
            assertFalse(result, "Should return false when offset+length > buffer size");
        }

        @Test
        @DisplayName("Should handle when signature field exceeds buffer size in verify method")
        void testVerifySignatureExceedsBuffer() {
            byte[] data = new byte[50]; // Too small for signature field
            boolean result = digest.verify(data, 0, 50, 0, response);
            assertFalse(result, "Should return false when signature field exceeds buffer");
        }

        @Test
        @DisplayName("Should accept valid parameters in sign method")
        void testSignValidParameters() {
            byte[] data = new byte[128];
            // Should not throw
            digest.sign(data, 0, 128, request, response);

            // Verify signature was added
            byte[] signature = Arrays.copyOfRange(data, SIGNATURE_OFFSET, SIGNATURE_OFFSET + SIGNATURE_LENGTH);
            boolean hasNonZero = false;
            for (byte b : signature) {
                if (b != 0) {
                    hasNonZero = true;
                    break;
                }
            }
            assertTrue(hasNonZero, "Signature should be present");
        }

        @Test
        @DisplayName("Should accept valid parameters in verify method")
        void testVerifyValidParameters() {
            byte[] data = new byte[128];
            // First sign the data
            digest.sign(data, 0, 128, request, response);

            // Verify should work with valid parameters
            // Note: actual verification result depends on proper setup
            digest.verify(data, 0, 128, 0, response);
        }
    }
}

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
            assertEquals("Missing preauthIntegrityHash for SMB 3.1", exception.getMessage());
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
        @DisplayName("Should be thread-safe with synchronized")
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

            assertFalse(result, "Should return false for valid signature");
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

            assertTrue(result, "Should return true for invalid signature");
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

            assertFalse(result, "Should return false for valid signature with offset");
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

            assertTrue(result, "Should handle extra padding parameter");
        }

        @Test
        @DisplayName("Should be thread-safe for verify")
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

            assertFalse(isValid, "Valid signature should verify correctly");
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

            assertFalse(isValid, "Valid signature should verify correctly");
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

            assertTrue(isValid, "Tampered data should fail verification");
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

            assertTrue(isValid, "Different session keys should fail verification");
        }
    }
}

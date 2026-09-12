package org.codelibs.jcifs.smb.internal.smb2;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.security.SecureRandom;

import org.codelibs.jcifs.smb.DialectVersion;
import org.codelibs.jcifs.smb.internal.smb2.nego.EncryptionNegotiateContext;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Test class for Smb2EncryptionContext.
 * Tests the available public API methods of the encryption context.
 */
@DisplayName("Smb2EncryptionContext Tests")
class Smb2EncryptionContextTest {

    private byte[] testEncryptionKey;
    private byte[] testDecryptionKey;
    private Smb2EncryptionContext encryptionContext;

    @BeforeEach
    void setUp() {
        // Initialize test keys
        testEncryptionKey = new byte[16]; // 128-bit key
        testDecryptionKey = new byte[16]; // 128-bit key
        new SecureRandom().nextBytes(testEncryptionKey);
        new SecureRandom().nextBytes(testDecryptionKey);

        // Create encryption context with required parameters
        encryptionContext = new Smb2EncryptionContext(1, DialectVersion.SMB311, testEncryptionKey, testDecryptionKey);
    }

    @Test
    @DisplayName("Should create encryption context with valid parameters")
    void testConstructor() {
        // When
        Smb2EncryptionContext context = new Smb2EncryptionContext(1, DialectVersion.SMB311, testEncryptionKey, testDecryptionKey);

        // Then
        assertNotNull(context, "Encryption context should be created");
        assertEquals(1, context.getCipherId(), "Cipher ID should match");
        assertEquals(DialectVersion.SMB311, context.getDialect(), "Dialect should match");
    }

    @Test
    @DisplayName("Should return correct cipher ID")
    void testGetCipherId() {
        // When
        int cipherId = encryptionContext.getCipherId();

        // Then
        assertEquals(1, cipherId, "Should return the cipher ID set in constructor");
    }

    @Test
    @DisplayName("Should return correct dialect version")
    void testGetDialect() {
        // When
        DialectVersion dialect = encryptionContext.getDialect();

        // Then
        assertEquals(DialectVersion.SMB311, dialect, "Should return the dialect set in constructor");
    }

    @Test
    @DisplayName("Should handle SMB 3.0 dialect")
    void testSMB300Dialect() {
        // When
        Smb2EncryptionContext context = new Smb2EncryptionContext(1, DialectVersion.SMB300, testEncryptionKey, testDecryptionKey);

        // Then
        assertEquals(DialectVersion.SMB300, context.getDialect(), "Should support SMB 3.0 dialect");
    }

    @Test
    @DisplayName("Should handle SMB 3.0.2 dialect")
    void testSMB302Dialect() {
        // When
        Smb2EncryptionContext context = new Smb2EncryptionContext(1, DialectVersion.SMB302, testEncryptionKey, testDecryptionKey);

        // Then
        assertEquals(DialectVersion.SMB302, context.getDialect(), "Should support SMB 3.0.2 dialect");
    }

    @Test
    @DisplayName("Should handle different cipher IDs")
    void testDifferentCipherIds() {
        // Test cipher ID 1 (AES-CCM)
        Smb2EncryptionContext context1 = new Smb2EncryptionContext(1, DialectVersion.SMB311, testEncryptionKey, testDecryptionKey);
        assertEquals(1, context1.getCipherId(), "Should handle cipher ID 1");

        // Test cipher ID 2 (AES-GCM)
        Smb2EncryptionContext context2 = new Smb2EncryptionContext(2, DialectVersion.SMB311, testEncryptionKey, testDecryptionKey);
        assertEquals(2, context2.getCipherId(), "Should handle cipher ID 2");
    }

    @Test
    @DisplayName("Should throw exception for null encryption key")
    void testNullEncryptionKey() {
        // When/Then
        assertThrows(NullPointerException.class, () -> {
            new Smb2EncryptionContext(1, DialectVersion.SMB311, null, testDecryptionKey);
        }, "Should throw NullPointerException for null encryption key");
    }

    @Test
    @DisplayName("Should throw exception for null decryption key")
    void testNullDecryptionKey() {
        // When/Then
        assertThrows(NullPointerException.class, () -> {
            new Smb2EncryptionContext(1, DialectVersion.SMB311, testEncryptionKey, null);
        }, "Should throw NullPointerException for null decryption key");
    }

    @Test
    @DisplayName("Should accept null dialect during construction")
    void testNullDialect() {
        // When/Then
        assertDoesNotThrow(() -> {
            Smb2EncryptionContext context = new Smb2EncryptionContext(1, null, testEncryptionKey, testDecryptionKey);
            assertNull(context.getDialect(), "Dialect should be null");
        }, "Should accept null dialect during construction");
    }

    @Test
    @DisplayName("a key of the wrong length for the cipher is rejected rather than silently used")
    void testEmptyKeysAreRejected() {
        // A zero-length key used to be accepted here, asserted as "should accept empty keys". Nothing validated
        // key length at all, so the test was documenting the absence of a check rather than a contract.
        final byte[] emptyKey = new byte[0];

        assertThrows(IllegalArgumentException.class,
                () -> new Smb2EncryptionContext(EncryptionNegotiateContext.CIPHER_AES128_GCM, DialectVersion.SMB311, emptyKey, emptyKey),
                "an empty key cannot encrypt anything and must be refused");
    }

    @Test
    @DisplayName("a 16-byte key under an AES-256 cipher id is refused instead of encrypting as AES-128")
    void testKeyLengthMustMatchTheCipher() {
        final byte[] key128 = new byte[16];
        final byte[] key256 = new byte[32];
        new SecureRandom().nextBytes(key128);
        new SecureRandom().nextBytes(key256);

        // This is the defect that matters. BouncyCastle derives the AES key size from the key it is handed, so a
        // 16-byte key under cipher id 0x4 encrypts as AES-128 and reports success - the session comes up, traffic
        // flows, and the negotiated cipher is a lie. An abandoned attempt at AES-256 on origin/experimental
        // (ad815cf) had this guard but never widened the KDF, so it would have thrown on every AES-256 session;
        // the guard was right and the derivation underneath it was missing.
        assertThrows(IllegalArgumentException.class,
                () -> new Smb2EncryptionContext(EncryptionNegotiateContext.CIPHER_AES256_GCM, DialectVersion.SMB311, key128, key128),
                "AES-256-GCM with a 128-bit key must be refused");
        assertThrows(IllegalArgumentException.class,
                () -> new Smb2EncryptionContext(EncryptionNegotiateContext.CIPHER_AES256_CCM, DialectVersion.SMB311, key128, key128),
                "AES-256-CCM with a 128-bit key must be refused");
        assertThrows(IllegalArgumentException.class,
                () -> new Smb2EncryptionContext(EncryptionNegotiateContext.CIPHER_AES128_GCM, DialectVersion.SMB311, key256, key256),
                "AES-128-GCM with a 256-bit key must be refused");

        // Mismatched pairs too: the two directions are separate keys and either one being wrong is fatal.
        assertThrows(IllegalArgumentException.class,
                () -> new Smb2EncryptionContext(EncryptionNegotiateContext.CIPHER_AES128_GCM, DialectVersion.SMB311, key128, key256),
                "a context whose two keys disagree in length must be refused");

        assertDoesNotThrow(
                () -> new Smb2EncryptionContext(EncryptionNegotiateContext.CIPHER_AES256_GCM, DialectVersion.SMB311, key256, key256),
                "AES-256-GCM with 256-bit keys is the valid combination");
    }

    @Test
    @DisplayName("the AES-256 ciphers are classified as GCM or CCM, and get the right nonce length")
    void testAes256CiphersAreClassifiedCorrectly() {
        final byte[] key256 = new byte[32];
        new SecureRandom().nextBytes(key256);

        // getNonceLength() is derived from the GCM/CCM classification, and the constructor uses it to size the
        // nonce prefix - so a cipher that falls through to the CCM branch is mis-sized at construction, not just
        // at encrypt time. MS-SMB2 2.2.41: GCM 12 bytes, CCM 11, whatever the key size.
        assertEquals(12, new Smb2EncryptionContext(EncryptionNegotiateContext.CIPHER_AES256_GCM, DialectVersion.SMB311, key256, key256)
                .getNonceLength(), "AES-256-GCM must use a 12-byte nonce");
        assertEquals(11, new Smb2EncryptionContext(EncryptionNegotiateContext.CIPHER_AES256_CCM, DialectVersion.SMB311, key256, key256)
                .getNonceLength(), "AES-256-CCM must use an 11-byte nonce");
    }

    @Test
    @DisplayName("an AES-256-GCM message round trips through a second context holding the same keys")
    void testAes256GcmRoundTrip() throws Exception {
        final byte[] c2s = new byte[32];
        final byte[] s2c = new byte[32];
        new SecureRandom().nextBytes(c2s);
        new SecureRandom().nextBytes(s2c);

        // Two contexts with the keys swapped, so the decrypting side uses the other direction's key exactly as a
        // server would. A single context decrypting its own output would pass even if the direction keys were
        // crossed.
        final Smb2EncryptionContext client =
                new Smb2EncryptionContext(EncryptionNegotiateContext.CIPHER_AES256_GCM, DialectVersion.SMB311, c2s, s2c);
        final Smb2EncryptionContext server =
                new Smb2EncryptionContext(EncryptionNegotiateContext.CIPHER_AES256_GCM, DialectVersion.SMB311, s2c, c2s);

        final byte[] plaintext = new byte[512];
        new SecureRandom().nextBytes(plaintext);

        final byte[] wrapped = client.encryptMessage(plaintext, 0x1122334455667788L);
        assertArrayEquals(plaintext, server.decryptMessage(wrapped), "an AES-256-GCM message must decrypt to what went in");
    }

    @Test
    @DisplayName("Should be immutable after creation")
    void testImmutability() {
        // Given
        int originalCipherId = encryptionContext.getCipherId();
        DialectVersion originalDialect = encryptionContext.getDialect();

        // When - Modify the original key array
        testEncryptionKey[0] = (byte) ~testEncryptionKey[0];

        // Then - Context should not be affected by external modifications
        assertEquals(originalCipherId, encryptionContext.getCipherId(), "Cipher ID should remain unchanged");
        assertEquals(originalDialect, encryptionContext.getDialect(), "Dialect should remain unchanged");
    }

    @Test
    @DisplayName("Should generate unique nonces")
    void testGenerateNonce() {
        // When
        byte[] nonce1 = encryptionContext.generateNonce();
        byte[] nonce2 = encryptionContext.generateNonce();

        // Then
        assertNotNull(nonce1, "First nonce should not be null");
        assertNotNull(nonce2, "Second nonce should not be null");
        // MS-SMB2 2.2.41: AES-CCM uses 11 bytes, AES-GCM 12; the 16-byte header field is zero-padded.
        assertEquals(encryptionContext.getNonceLength(), nonce1.length, "Nonce should match the cipher nonce length");
        assertEquals(encryptionContext.getNonceLength(), nonce2.length, "Nonce should match the cipher nonce length");
        assertFalse(java.util.Arrays.equals(nonce1, nonce2), "Consecutive nonces should be different");
    }

    @Test
    @DisplayName("Should generate multiple unique nonces")
    void testGenerateMultipleNonces() {
        // Given
        int count = 100;
        java.util.Set<String> nonceSet = new java.util.HashSet<>();

        // When
        for (int i = 0; i < count; i++) {
            byte[] nonce = encryptionContext.generateNonce();
            String nonceHex = bytesToHex(nonce);
            nonceSet.add(nonceHex);
        }

        // Then
        assertEquals(count, nonceSet.size(), "All generated nonces should be unique");
    }

    private String bytesToHex(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        for (byte b : bytes) {
            result.append(String.format("%02x", b));
        }
        return result.toString();
    }
}